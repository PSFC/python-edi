"""
Parses a provided EDI message and tries to build a dictionary from the data
Provides hints if data is missing, incomplete, or incorrect.
"""

import datetime

from .supported_formats import supported_formats
from .debug import Debug

class EDIParser(object):
    def __init__(self, edi_format=None, element_delimiter="^", segment_delimiter="\n", data_delimiter="`"):
        # Set default delimiters
        self.element_delimiter = element_delimiter
        self.segment_delimiter = segment_delimiter
        self.data_delimiter = data_delimiter

        # Set EDI format to use
        if edi_format in supported_formats:
            self.edi_format = supported_formats[edi_format]
        elif edi_format is None:
            self.edi_format = None
        else:
            raise ValueError("Unsupported EDI format {}".format(edi_format))

    def parse_isa_header(self, data):
        # make sure this is EDI data
        if not data.startswith('ISA'):
            raise ValueError("EDI data must start with 'ISA'")

        # element delimiter follows header id
        element_delimiter = data[3 : 4]

        self.element_delimiter = element_delimiter

        header_field_list = data.split(element_delimiter)

        for index, isa in enumerate(header_field_list):
            if index == 11:
                self.data_delimiter = isa
            if index == 12:
                self.version = isa
            #elif index <= 15:
            #    pass
            elif index == 16:
                last_header_field = header_field_list[16]

                # The sub-element separator is always the first character in this element.
                self.component_element_delimiter = last_header_field[0 : 1]

                # find segment delimiter
                if last_header_field[1 : 2]:
                    self.segment_delimiter = last_header_field[1 : 2]

                    # add any cr-lf chars to segment delimiter
                    if last_header_field[2 : 4]:
                        for delimiter in last_header_field[2 : 4]:
                            if delimiter in ('\r', '\n'):
                                self.segment_delimiter += delimiter
            elif index > 16:
                break

    def parse_required_segments(self, edi_segments):
        edi_segment_map = { segment.split(self.element_delimiter)[0]: segment for segment in edi_segments }

        self.parse_st_header(edi_segment_map)
        self.verify_ending_segments(edi_segment_map)

    def parse_st_header(self, edi_segment_map):
        st = edi_segment_map.get('ST', None)

        if st is None:
            raise ValueError(f"EDI data missing required segment 'ST'")

        # if trans_set not explicitly provided, retrieve from header
        if not self.trans_set_specified:
            self.trans_set = st.split(self.element_delimiter)[1]

    def verify_ending_segments(self, edi_segment_map):
        for seg_id in ('IEA', 'SE'):
            segment_format = self.get_segment_format(seg_id)

            if segment_format['id'] not in edi_segment_map:
                raise ValueError(f"EDI data missing required segment '{segment_format['id']}'")

    def get_segment_format(self, segment_id):
        if segment_id not in supported_formats:
            raise ValueError("Missing EDI segment format: '{}'".format(segment_id))

        segment_format = supported_formats[segment_id]

        if len(segment_format) == 0:
            raise ValueError("Empty EDI segment format: '{}'".format(segment_id))

        return segment_format[0]

    # parse multiple documents (multiple ST/SE sets within a file)
    def parse_set_group(self, data):
        edi_sets = []

        self.parse_isa_header(data)

        edi_segments = data.split(self.segment_delimiter)

        self.parse_group_segments(edi_segments)

        st_indicies = self.get_st_indicies(edi_segments)
        st_segs_found = len(st_indicies)

        if st_segs_found == 0:
            raise ValueError(f"EDI data missing required ST/SE segment pairs")
        elif st_segs_found != self.group_count:
            raise ValueError(f"EDI data ST/SE segment pairs found: {st_segs_found}, does not match count in GE: {self.group_count}")

        first_index = st_indicies[0][0]
        last_index = st_indicies[st_segs_found - 1][1]

        for st_index, se_index in st_indicies:
            st_segment = edi_segments[: first_index] + edi_segments[st_index : se_index + 1] + edi_segments[last_index + 1:]                
            edi_sets.append(self.parse_segments(st_segment))

        return edi_sets

    def parse_group_segments(self, edi_segments):
        gs_found = False

        for segment in edi_segments:
            elements = segment.split(self.element_delimiter)

            if elements[0] == 'GS':
                gs_found = True
            elif elements[0] == 'GE':
                if not gs_found:
                    raise ValueError(f"EDI data contains GE segment with no matching GS")

                self.groups_defined = True
                self.group_count = int(elements[1])
                break

    def get_st_indicies(self, edi_segments):
        st_indicies = []
        st_index = se_index = -1

        for index, segment in enumerate(edi_segments):
            seg_id = segment.split(self.element_delimiter)[0]

            if seg_id == 'ST':
                st_index = index
            elif seg_id == 'SE':
                se_index = index

            if st_index > -1 and se_index > -1:
                st_indicies.append((st_index, se_index))
                st_index = se_index = -1

        return st_indicies

    def parse(self, data):
        self.parse_isa_header(data)

        return self.parse_segments(data.split(self.segment_delimiter))

    def parse_segments(self, edi_segments):
        """ Processes each line in the string `data`, attempting to auto-detect the EDI type.

        Returns the parsed message as a dict. """

        # PSFC: Ensure required segments exist, determine trans_set if needed, then load the message into list
        self.parse_required_segments(edi_segments)
        # Break the message up into chunks
        #edi_segments = edi_segments = data.split(self.segment_delimiter)

        # PSFC: If trans_set has been parsed from ST segment, load edi format
        if not self.edi_format:
            self.edi_format = supported_formats.get(self.trans_set, None)

        if self.edi_format is None:
            raise ValueError("EDI format missing or could not be detected.")

        to_return = {}
        found_segments = []

        while len(edi_segments) > 0:
            segment = edi_segments[0]
            if segment == "":
                edi_segments = edi_segments[1:]
                continue # Line is blank, skip
            # Capture current segment name
            segment_name = segment.split(self.element_delimiter)[0]
            segment_obj = None
            # Find corresponding segment/loop format
            for seg_format in self.edi_format:
                # Check if segment is just a segment, a repeating segment, or part of a loop
                if seg_format["id"] == segment_name and seg_format["max_uses"] == 1:
                    # Found a segment
                    segment_obj = self.parse_segment(segment, seg_format)
                    edi_segments = edi_segments[1:]
                    break
                # PSFC: allow max_uses set to -1 to mean unbounded
                elif seg_format["id"] == segment_name and (seg_format["max_uses"] == -1 or seg_format["max_uses"] > 1):
                    # Found a repeating segment
                    segment_obj, edi_segments = self.parse_repeating_segment(edi_segments, seg_format)
                    break
                elif self.is_list_type(seg_format["id"], segment_name):
                    # Found a loop
                    segment_name = seg_format["id"]
                    segment_obj, edi_segments = self.parse_loop(edi_segments, seg_format)
                    break

            if segment_obj is None:
                Debug.log_error("Unrecognized segment: {}".format(segment))
                edi_segments = edi_segments[1:] # Skipping segment
                continue
                # raise ValueError

            # PSFC: If a segment repeats (even if schema doesn't allow it) add to data:
            if segment_name in to_return:
                if isinstance(to_return[segment_name], dict):
                    to_return[segment_name] = [ to_return[segment_name] ]

                if isinstance(segment_obj, list):
                    to_return[segment_name].extend(segment_obj)
                else:
                    to_return[segment_name].append(segment_obj)
            else:
                found_segments.append(segment_name)
                to_return[segment_name] = segment_obj
            '''
            found_segments.append(segment_name)
            to_return[segment_name] = segment_obj
            '''

        return found_segments, to_return

    def parse_segment(self, segment, segment_format):
        """ Parse a segment into a dict according to field IDs """
        fields = segment.split(self.element_delimiter)
        if fields[0] != segment_format["id"]:
            raise ValueError("Segment {} does not match provided segment format {}".format(fields[0], segment_format["id"]))
        elif len(fields) - 1 > len(segment_format["elements"]):
            Debug.explain(segment_format)
            raise ValueError("Segment '{}' has more elements than segment definition. Expected {}, found {}".format(segment_format["id"], len(segment_format["elements"]), len(fields) - 1))

        #segment_name = fields[0]
        to_return = {}

        # PSFC: set empty fields to None
        for field, element in zip(fields[1:], segment_format["elements"]): # Skip the segment name field
            # PSFC: factored parsing element to allow for composite elements
            if element["type"] == 'element':
                to_return[element["id"]] = self.parse_element(field, element)
            elif element["type"] == 'composite':
                to_return[element["id"]] =\
                    { comp_element["id"]: self.parse_element(comp_field, comp_element) for comp_field, comp_element in zip(field.split(self.component_element_delimiter), element['elements']) }
            else:
                raise ValueError("Element '{}' of segment {}, has unknown type {}".format(element["id"], segment_format["id"], element["type"]))

        return to_return

    def parse_element(self, field, element):
        # PSFC: define value to prevent usage before assignment exception
        value = None

        if element["data_type"] == "DT":
            if len(field) == 8:
                value = datetime.datetime.strptime(field, "%Y%m%d")
            elif len(field) == 6:
                value = datetime.datetime.strptime(field, "%y%m%d")
            elif not field:
                value = None
            else:
                value = field
        elif element["data_type"] == "TM":
            if len(field) == 4:
                value = datetime.datetime.strptime(field, "%H%M")
            elif len(field) == 6:
                value = datetime.datetime.strptime(field, "%H%M%S")
            elif not field:
                value = None
        elif element["data_type"] == "N0":
            value = int(field) if field else None
        elif element["data_type"].startswith("N"):
            # PSFC: sanity check: strip decimal point, which should not be present
            value = float(field.replace('.','')) / (10**int(element["data_type"][-1])) if field else None
        elif element["data_type"] == "R":
            value = float(field) if field else None
        elif element["data_type"] in ("AN", "ID"):
            value = field if field else None
        else:
            value = field

        return value

    def parse_repeating_segment(self, edi_segments, segment_format):
        """ Parse all instances of this segment, and return any remaining segments with the seg_list """
        seg_list = []

        while len(edi_segments) > 0:
            segment = edi_segments[0]
            segment_name = segment.split(self.element_delimiter)[0]
            if segment_name != segment_format["id"]:
                break
            seg_list.append(self.parse_segment(segment, segment_format))
            edi_segments = edi_segments[1:]

        return seg_list, edi_segments

    def parse_loop(self, edi_segments, loop_format):
        """ Parse all segments that are part of this loop, and return any remaining segments with the loop_list """
        loop_list = []
        loop_dict = {}

        while len(edi_segments) > 0:
            segment = edi_segments[0]
            segment_name = segment.split(self.element_delimiter)[0]
            segment_obj = None

            # Find corresponding segment/loop format
            for seg_format in loop_format["segments"]:
                # Check if segment is just a segment, a repeating segment, or part of a loop
                if seg_format["id"] == segment_name and seg_format["max_uses"] == 1:
                    # Found a segment
                    segment_obj = self.parse_segment(segment, seg_format)
                    edi_segments = edi_segments[1:]
                # PSFC: allow max_uses set to -1 to mean unbounded
                elif seg_format["id"] == segment_name and (seg_format["max_uses"] == -1 or seg_format["max_uses"] > 1):
                    # Found a repeating segment
                    segment_obj, edi_segments = self.parse_repeating_segment(edi_segments, seg_format)
                elif self.is_list_type(seg_format["id"], segment_name):
                    # Found a loop
                    segment_name = seg_format["id"]
                    segment_obj, edi_segments = self.parse_loop(edi_segments, seg_format)
            #print(segment_name, segment_obj)
            if segment_obj is None:
                # Reached the end of valid segments; return what we have
                break
            elif segment_name == loop_format["segments"][0]["id"] and loop_dict != {}: 
                # Beginning a new loop, tie off this one and start fresh
                loop_list.append(loop_dict.copy())
                loop_dict = {}
            loop_dict[segment_name] = segment_obj
        if loop_dict != {}:
            loop_list.append(loop_dict.copy())
        return loop_list, edi_segments

    # determine if format definition is a loop or set
    def is_list_type(self, seg_id, segment_name):
        return seg_id == "L_" + segment_name or seg_id == "S_" + segment_name
