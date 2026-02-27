"""
Validates a provided EDI message against a given EDI format definition.
"""

from datetime import datetime
from typing import Union

from .utils import EDIUtils

class ValidationException(Exception):
    def __init__(self, message, errors):            
        super().__init__(message)

        self.errors = errors

class ValidationError:
    def __init__(self, data_type, name, segment, error):
        self.data_type = data_type
        self.name = name
        self.segment = segment
        self.error = error

    def __str__(self):
        return f"{self.data_type} {self.name}, segment: {self.segment}, error: {self.error}"

REQUIRED_SEGMENTS = ('ISA', 'ST', 'SE', 'IEA')

class EDIValidator(object):
    def validate(self, edi_data, edi_format : Union[dict, list]) -> list:
        self.edi_data = edi_data
        self.edi_format : Union[dict, list] = edi_format
        self.validation_errors : list = []

        for req_seg in REQUIRED_SEGMENTS:
            if req_seg not in self.edi_data.keys():
                self.add_error(name =  req_seg, segment = req_seg, error = "Required segment not found")

        self.validate_children(None, self.edi_data, self.edi_format)

        return self.validation_errors 

    def validate_children(self, parent, children : Union[dict, list], schemas : list[dict]):
        if not schemas:
            self.add_error(type = f"{type(children)}", error = f"Children have no associated schema list") 
        elif isinstance(children, dict):
            self.validate_required(children, schemas)

            # check each child against schema list
            for name, data in children.items():
                child_schema = self.find_schema(name, schemas)
                if child_schema:
                    data_type = child_schema['type']

                    if isinstance(data, (dict, list)) and data_type != 'composite':
                        if data_type == 'segment':
                            self.validate_segment(name, data, child_schema)
                        elif data_type == 'loop':
                            self.validate_loop(name, data, child_schema)
                        else:
                            self.add_error(data_type, name, error = f"Unknown type '{child_schema['type']}'")

                        self.validate_children(name, data, self.get_child_schemas(child_schema))
                    else:
                        if data_type == 'element':
                            self.validate_element(parent, name, data, child_schema)
                        elif data_type == 'composite':
                            comp_schemas = self.get_child_schemas(child_schema)

                            for comp_name, comp_data in data.items():
                                self.validate_element(parent, comp_name, comp_data, self.find_schema(comp_name, comp_schemas))
                        elif data: # there was data present but not one of the expected types
                            self.add_error(data_type, name, error = f"Unexpected type '{child_schema['type']}'")
                else:
                    self.add_error(type(name), name, error = f"Found unexpected child for schema list: {self.schema_id_list(schemas)}")

        # make sure children contain any required schema entries
        elif isinstance(children, list):
            for each in children:
                self.validate_children(parent, each, schemas)
        else:
            self.add_error(data_type = f"{type(children)}", error = f"Children must be of type dict or list")

    def validate_required(self, children : Union[dict, list], schemas : list[dict]):
        for schema in schemas:
            if schema['type'] in ('segment', 'loop') and schema['req'] == "M" and schema['id'] not in children:
                self.add_error(schema['type'], schema['id'], error = f"Missing required {schema['type']}")

    def validate_loop(self, loop_id, loop_data : list, loop_schema : dict):
        # Check number of occurrences against limit
        loop_count = len(loop_data)
        max_repeat = loop_schema.get('repeat', -1)

        if max_repeat > -1 and loop_count > max_repeat:
            self.add_error(type = "loop", name = loop_id, segment = None, error = f"Loop repeats {loop_count} times. Max allowed is {max_repeat}")

    def validate_segment(self, seg_id, seg_data : Union[dict, list], seg_schema : dict):
        # Check number of occurrences against limit
        if isinstance(seg_data, list):
            num_uses = len(seg_data)
            max_uses = seg_schema.get('max_uses', -1)

            if max_uses > -1 and num_uses > max_uses:
                self.add_error(name = seg_id, segment = seg_id, error = f"Segment repeats {num_uses} times. Max allowed is {max_uses}")

            # validate each repeated segment
            for segment in seg_data:
                self.validate_single_segment(seg_id, segment, seg_schema)   
        else:
            self.validate_single_segment(seg_id, seg_data, seg_schema)
 
    def validate_single_segment(self, seg_id, seg_data : dict, seg_schema : dict):
            num_elements = len(seg_data)
            num_schema_elements = len(seg_schema['elements'])

            if num_elements > num_schema_elements:
                self.add_error(name = seg_id, segment = seg_id, error = f"Segment contains more elements than definition. Defined: {num_schema_elements} Found: {num_elements}")

            # ensure syntax requirements are met
            if 'syntax' in seg_schema:
                for rule in seg_schema['syntax']:
                    if rule["rule"] == "ATLEASTONE": # At least one of the elements in `criteria` must be present
                        found = False
                        for idx in rule["criteria"]:
                            if seg_data.get(EDIUtils.element_name(seg_id, idx), None):
                                found = True
                                break
                        if found is False:
                            # None of the elements were found
                            required_elements = self.required_elements(seg_id, rule)
                            self.add_error(name = seg_id, segment = seg_id, error = f"At least one of {required_elements} is required.")
                    elif rule["rule"] == "ALLORNONE": # Either all the elements in `criteria` must be present, or none of them may be
                        found = 0
                        for idx in rule["criteria"]:
                            if seg_data.get(EDIUtils.element_name(seg_id, idx), None):
                                found += 1
                        if 0 < found < len(rule["criteria"]):
                            # Some but not all the elements are present
                            required_elements = self.required_elements(seg_id, rule)
                            self.add_error(name = seg_id, segment = seg_id, error = f"If one of {required_elements} is present, all are required.")
                    elif rule["rule"] == "IFATLEASTONE": # If the first element in `criteria` is present, at least one of the others must be
                        found = 0
                        # Check if first element exists and is set
                        first_element = EDIUtils.element_name(seg_id, rule["criteria"][0])

                        if seg_data.get(first_element, None):
                            for idx in rule["criteria"][1:]:
                                if seg_data.get(EDIUtils.element_name(seg_id, idx), None):
                                    found += 1
                            if found == 0:
                                # None of the other elements were found
                                required_elements = self.required_elements(seg_id, rule)
                                self.add_error(name = seg_id, segment = seg_id, error = f"If {first_element} is present, at least one of {required_elements} are required.")

    def validate_element(self, seg_id, element_id, element_value, element_schema : dict):
        #print(f"Validate element: {element_id}, value: {element_value}, for segment: {seg_id}")
        if element_value is None:
            if element_schema["req"] == "M":
                self.add_error("element", element_id, segment = seg_id, error = f"Element is mandatory in segment '{seg_id}'")
            elif element_schema["req"] not in ("O", "C"):
                self.add_error("element", element_id, error = f"Unknown 'req' value '{element_schema['req']}' when processing element in segment '{seg_id}'")
        else:
            element_type = element_schema["data_type"]
            min_len = element_schema["length"]["min"]
            max_len = element_schema["length"]["max"]

            if element_type == "DT":
                if max_len not in (6, 8):
                    self.add_error("element", element_id, segment = seg_id, error = f"Invalid length ({max_len}) for date field in segment '{seg_id}'")
                if not isinstance(element_value, datetime):
                    self.add_error("element", element_id, segment = seg_id, error = f"Invalid data type ({type(element_value)}) for date field in segment '{seg_id}'")
            elif element_type== "TM":
                if max_len not in (4, 6, 7, 8):
                    self.add_error("element", element_id, segment = seg_id, error = f"Invalid length ({max_len}) for time field in segment '{seg_id}'")
                if not isinstance(element_value, datetime):
                    self.add_error("element", element_id, error = f"Invalid data type ({type(element_value)}) for time field in segment '{seg_id}'")
            elif element_type == "R":
                if not isinstance(element_value, float):
                    self.add_error("element", element_id, segment = seg_id, error = f"Invalid data type ({type(element_value)}) for decimal field in segment '{seg_id}'")
            elif element_type.startswith("N"):
                if not isinstance(element_value, (float, int)):
                    self.add_error("element", element_id, segment = seg_id, error = f"Invalid data type ({type(element_value)}) for number field in segment '{seg_id}'")
            elif element_type == "ID":
                data_type_ids = element_schema.get("data_type_ids", None)

                if not data_type_ids:
                    # Some id fields (ex N402, N403) have no associated lookup table
                    #self.add_error("element", element_id, error = f"No valid IDs provided for id field value '{element_value}' in segment '{seg_id}'")
                    pass
                elif element_value not in data_type_ids:
                    self.add_error("element", element_id, segment = seg_id, error = f"Invalid data value '{element_value}' for id field in segment '{seg_id}'. Valid values: {self.data_type_list(data_type_ids)}")

            # date/time types already have min/max data length specifiers validated.
            if  element_type not in ("DT", "TM"):
                data_len = len(str(element_value))

                if element_type.startswith('N'):
                    # For numeric data, only validate max length, as it will be left padded with zero's
                    if data_len > max_len:
                        self.add_error("element", element_id, segment = seg_id, error = f"Element data length {data_len} greater than {max_len} in segment '{seg_id}'")
                elif data_len < min_len or data_len > max_len:
                    self.add_error("element", element_id, segment = seg_id, error = f"Element data length {data_len} outside range of {min_len} to {max_len} in segment '{seg_id}'")

    def required_elements(self, seg_id, rule) -> str:
        return ", ".join([EDIUtils.element_name(seg_id, e) for e in rule["criteria"]])

    def data_type_list(self, data_type_ids) -> str:
        return ", ".join(f"'{each}'" for each in data_type_ids)

    def add_error(self, data_type = 'segment', name = 'unknown', segment = None, error = ''):
        self.validation_errors.append(ValidationError(data_type, name, segment, error))

    def schema_id_list(self, schemas : list[dict]) -> list:
        return [each['id'] for each in schemas]

    def find_schema(self, name, schemas : list[dict]) -> dict:
        try:
            return EDIUtils.find_schema(schemas, name)
        except:
            return None

    def get_child_schemas(self, schema):
        try:
            return schema['segments'] if schema['type'] == 'loop' else schema['elements']
        except:
            return None
