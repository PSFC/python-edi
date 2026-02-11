"""
Parses a provided dictionary set and tries to build an EDI message from the data.
Provides hints if data is missing, incomplete, or incorrect.
"""

from .supported_formats import supported_formats
from .debug import Debug

class EDIGenerator(object):
    def __init__(self):
        # Set default delimiters
        self.element_delimiter = "^"
        self.segment_delimiter = "\n"
        self.data_delimiter = "`"

    def build(self, data):
        """
        Compiles a transaction set (as a dict) into an EDI message
        """
        # Check for transaction set ID in data

        if "ST" not in data:
            Debug.explain(supported_formats["ST"])
            raise ValueError("No transaction set header found in data.")
        # PSFC: Made ts_id an instance variable
        self.ts_id = data["ST"][0]
        if self.ts_id not in supported_formats:
            raise ValueError("Transaction set type '{}' is not supported. Valid types include: {}".format(
                self.ts_id,
                "".join(["\n - " + f for f in supported_formats])
            ))
        edi_format = supported_formats[self.ts_id]

        output_segments = []

        # Walk through the format definition to compile the output message
        for section in edi_format:
            if section["type"] == "segment":
                if section["id"] not in data:
                    if section["req"] in ("O", "C"):
                        # Optional or conditional segment is missing - that's fine, keep going
                        continue
                    elif section["req"] == "M":
                        # Mandatory segment is missing - explain it and then fail
                        Debug.explain(section)
                        raise ValueError("EDI data is missing mandatory segment '{}'.".format(section["id"]))
                    else:
                        raise ValueError("Unknown 'req' value '{}' when processing format for segment '{}' in set '{}'".format(section["req"], section["id"], self.ts_id))
                output_segments.extend(self.build_segment_list(section, data[section["id"]]))
            elif section["type"] == "loop":
                # PSFC: Allow for nested loops
                output_segments.extend(self.build_loop_list(section, data))

        # PSFC: Need trailing segment delimiter
        return self.segment_delimiter.join(output_segments) + self.segment_delimiter

    def build_loop_list(self, section, data):
        loop_segments = []

        if section["id"] not in data:
            mandatory = [segment for segment in section["segments"] if segment["req"] == "M"]
            if len(mandatory) > 0:
                Debug.explain(section)
                raise ValueError("EDI data is missing loop {} with mandatory segment(s) {}".format(section["id"], ", ".join([segment["id"] for segment in mandatory])))
            else:
                # No mandatory segments in loop - continue
                return loop_segments

        # Verify loop length
        if len(section["segments"]) > section["repeat"]:
            raise ValueError("Loop '{}' has {} segments (max {})".format(section["id"], len(section["segments"]), section["repeat"]))
        # Iterate through and build segments in loop
        for iteration in data[section["id"]]:
            for segment in section["segments"]:
                if segment["id"] not in iteration:
                    if section["req"] in ("O", "C"):
                        # Optional or conditional segment is missing - that's fine, keep going
                        continue
                    elif segment["req"] == "M":
                        # Mandatory segment is missing - explain loop and then fail
                        Debug.explain(section)
                        raise ValueError("EDI data in loop '{}' is missing mandatory segment '{}'.".format(section["id"], segment["id"]))
                    else:
                        raise ValueError("Unknown 'req' value '{}' when processing format for segment '{}' in set '{}'".format(segment["req"], segment["id"], self.ts_id))

                if segment["type"] == "loop":
                    # PSFC: Process nested loop
                    loop_segments.extend(self.build_loop_list(segment, iteration))
                else:
                    loop_segments.extend(self.build_segment_list(segment, iteration[segment["id"]]))

        return loop_segments

    def build_segment_list(self, segment, segment_data):
        segment_list = []

        if not isinstance(segment_data[0], list):
            # PSFC: Single occurrence of segment
            segment_list.append(self.build_segment(segment, segment_data))
        else:
            # PSFC: Multiple occurrences of segment
            num_uses = len(segment_data)
            # PSFC: If max_uses not present, or -1, then unbounded
            max_uses = segment.get('max_uses', -1)

            if max_uses > -1 and num_uses > max_uses:
                raise ValueError("Segment '{}' may not repeat more than {} time(s), found: {}".format(segment["id"], max_uses, num_uses))

            for segment_entry in segment_data:
                if isinstance(segment_entry, list):
                    segment_list.append(self.build_segment(segment, segment_entry))
                else:
                    raise TypeError("Repeated segment '{}' must have elements in list, found: '{}'".format(segment["id"], type(segment_entry)))

        return segment_list

    def build_segment(self, segment, segment_data):
        # Parse segment elements
        output_elements = [segment["id"]]

        # PSFC: Exception handling to report segment for failed element
        try:
            for e_data, e_format, index in zip(segment_data, segment["elements"], range(len(segment["elements"]))):
                # PSFC: Allow for composite elements
                output_elements.append(self.build_element_list(e_format, e_data))
        except ValueError as ve:
            raise ValueError("{}, in segment: {}".format(ve, segment['id']))

        # End of segment. If segment has syntax rules, validate them.
        if "syntax" in segment:
            for rule in segment["syntax"]:
                # Note that the criteria indexes are one-based 
                # rather than zero-based. However, the output_elements
                # array is prepopulated with the segment name,
                # so the net offset works perfectly!
                if rule["rule"] == "ATLEASTONE": # At least one of the elements in `criteria` must be present
                    found = False
                    for idx in rule["criteria"]:
                        if idx >= len(output_elements):
                            break
                        elif output_elements[idx] != "":
                            found = True
                    if found is False:
                        # None of the elements were found
                        required_elements = ", ".join(["{}{:02d}".format(segment["id"], e) for e in rule["criteria"]])
                        Debug.explain(segment)
                        raise ValueError("Syntax error parsing segment {}: At least one of {} is required.".format(segment["id"], required_elements))
                elif rule["rule"] == "ALLORNONE": # Either all the elements in `criteria` must be present, or none of them may be
                    found = 0
                    for idx in rule["criteria"]:
                        if idx >= len(output_elements):
                            break
                        elif output_elements[idx] != "":
                            found += 1
                    if 0 < found < len(rule["criteria"]):
                        # Some but not all the elements are present
                        required_elements = ", ".join(["{}{:02d}".format(segment["id"], e) for e in rule["criteria"]])
                        Debug.explain(segment)
                        raise ValueError("Syntax error parsing segment {}: If one of {} is present, all are required.".format(segment["id"], required_elements))
                elif rule["rule"] == "IFATLEASTONE": # If the first element in `criteria` is present, at least one of the others must be
                    found = 0
                    # Check if first element exists and is set
                    if rule["criteria"][0] < len(output_elements) and output_elements[rule["criteria"][0]] != "":
                        for idx in rule["criteria"][1:]:
                            if idx >= len(output_elements):
                                break
                            elif output_elements[idx] != "":
                                found += 1
                        # PSFC: IFATLEASTONE satisfied if any elements found
                        if found == 0:
                            # None of the other elements were found
                            first_element = "{}{:02d}".format(segment["id"], rule["criteria"][0])
                            # PSFC: Fixed typo, was dereferencing rule["criteria"][0]
                            required_elements = ", ".join(["{}{:02d}".format(segment["id"], e) for e in rule["criteria"]])
                            Debug.explain(segment)
                            raise ValueError("Syntax error parsing segment {}: If {} is present, at least one of {} are required.".format(segment["id"], first_element, required_elements))

        # PSFC: Remove trailing empty elements
        while output_elements and not output_elements[-1]:
            output_elements = output_elements[:-1]

        return self.element_delimiter.join(output_elements)

    def build_element_list(self, e_format, e_data):
        element_type = e_format["type"]

        if element_type == "element":
            return self.build_element(e_format, e_data)
        elif element_type == "composite":
            formatted_elements =\
                [ self.build_element(ce_format, ce_data) for ce_data, ce_format in zip(e_data[e_format["id"]], e_format["elements"]) ]
            return self.component_element_delimiter.join(formatted_elements)
        else:
            raise ValueError("Element {} ({}) has unknown type '{}'".format(e_format["id"], e_format["name"], element_type))

    def build_element(self, e_format, e_data):
        element_id = e_format["id"]
        formatted_element = ""
        if e_data is None:
            if e_format["req"] == "M":
                raise ValueError("Element {} ({}) is mandatory".format(element_id, e_format["name"]))
            # PSFC: allow conditional req value
            elif e_format["req"] in ("O", "C"):
                return ""
            else:
                raise ValueError("Unknown 'req' value '{}' when processing format for element '{}' in set '{}'".format(e_format["req"], element_id, self.ts_id))
        try:
            if e_format["data_type"] == "AN":
                formatted_element = str(e_data)
            elif e_format["data_type"] == "DT":
                if e_format["length"]["max"] == 8:
                    formatted_element = e_data.strftime("%Y%m%d")
                elif e_format["length"]["max"] == 6:
                    formatted_element = e_data.strftime("%y%m%d")
                else:
                    raise ValueError("Invalid length ({}) for date field in element '{}' in set '{}'".format(e_format["length"], element_id, self.ts_id))
            elif e_format["data_type"] == "TM":
                if e_format["length"]["max"] in (4, 6, 7, 8):
                    #formatted_element = e_data.strftime("%H%M%S%f")
                    formatted_element = e_data.strftime("%H%M")
                else:
                    raise ValueError("Invalid length ({}) for time field in element '{}' in set '{}'".format(e_format["length"], element_id, self.ts_id))
            elif e_format["data_type"] == "R":
                formatted_element = str(float(e_data))
            elif e_format["data_type"].startswith("N"):
                formatted_element = "{:0{length}.{decimal}f}".format(float(e_data), length=e_format["length"]["min"], decimal=e_format["data_type"][1:])
            elif e_format["data_type"] == "ID":
                formatted_element = str(e_data)
                if not e_format["data_type_ids"]:
                    #Debug.log_warning("No valid IDs provided for element '{}'. Allowing anyway.".format(e_format["name"]))
                    pass
                elif e_data not in e_format["data_type_ids"]:
                    #Debug.log_warning("ID '{}' not recognized for element '{}'. Allowing anyway.".format(e_data, e_format["name"]))
                    pass
            elif e_format["data_type"] == "":
                if element_id == "ISA16":
                    # Component Element Separator
                    self.data_delimiter = str(e_data)[0]
                    formatted_element = str(e_data)
                else:
                    raise ValueError("Undefined behavior for empty data type with element '{}'".format(element_id))
        except:
            raise ValueError("Error converting '{}' to data type '{}'".format(e_data, e_format["data_type"]))

        # Pad/trim formatted element to fit the field min/max length respectively
        formatted_element += " "*(e_format["length"]["min"]-len(formatted_element))
        formatted_element = formatted_element[:e_format["length"]["max"]]

        # Add element to list
        return formatted_element