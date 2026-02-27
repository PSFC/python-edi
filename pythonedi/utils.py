"""
EDI message parsing/generation support.
"""

import re
from pathlib import Path
from typing import Union

''' Defines EDI data delimiters '''
class Delimiters:
    def __init__(self, segment_delimiter: str = "\n", element_delimiter: str = "*", repetition_delimiter: str = "^", component_element_delimiter: str = ":"):
        self.segment_delimiter = segment_delimiter
        self.element_delimiter = element_delimiter
        self.repetition_delimiter = repetition_delimiter
        self.component_element_delimiter = component_element_delimiter

    def delimiter_list(self) -> list[str]:
        return [ self.segment_delimiter, self.element_delimiter, self.repetition_delimiter, self.component_element_delimiter ]

    # strip delimiters from value, remove redundant whitespace
    def format(self, value : str) -> str:
        formatted_value = value

        for each in self.delimiter_list():
            formatted_value = formatted_value.replace(each, '')

        return re.sub(r'\s{2,}', ' ', formatted_value)

''' Converts EDI elements between dicts and lists '''
class EDIConverter:
    @classmethod
    # Element values are in lists when importing/exporting/validating edi data. Empty placeholders are used for missing values.
    def to_element_list(cls, input_data : dict) -> Union[dict, list]:
        output_data = { }
 
        if isinstance(input_data, dict):
            for key, data in input_data.items():
                if isinstance(data, dict):
                    output_data[key] = [ data.get(value) for value in data ] # segment
                elif isinstance(data, list):
                    output_data[key] = [ cls.to_element_list(list_value) for list_value in data ] # loop, or list of segments
                elif data:
                    output_data = list(input_data.values()) # data for list of repeating segments
                    break
        else:
            raise TypeError(f"Found invalid input type: {type(input_data)}")

        return output_data

    @classmethod
    # Element values are in dict format while creating/building edi data. Dicts are keyed by segment name and number (ex 'ISA01': '00')
    def to_element_dict(cls, input_data : Union[dict, list], name = None) -> Union[dict, list]:
        output_data = { }

        if isinstance(input_data, dict):
            for key, data in input_data.items():
                output_data[key] = cls.to_element_dict(data, key) # segment, repeating segments, or loop
        elif isinstance(input_data, list):
            if len(input_data) == 0:
                return []
            elif isinstance(input_data[0], (list, dict)):
                return [ cls.to_element_dict(each, name) for each in input_data ] # repeating segments or loop
            else:
                return { EDIUtils.element_name(name, index + 1): value for index, value in enumerate(input_data) } # segment
        else:
            raise TypeError(f"Found invalid input type: {type(input_data)}")

        return output_data

class FileUtils:
    @classmethod
    def from_string_or_file(cls, data):
        return cls.file_to_string(data) if cls.is_file(data) else data

    @classmethod
    def is_file(cls, edi_file):
        try:
            is_file = Path(edi_file).is_file()
        except (AttributeError, OSError):
            is_file = False

        return is_file

    @classmethod
    def file_to_string(cls, edi_file):
        try:
            with open(edi_file, "r", encoding = "utf-8") as file:
                return file.read()
        except FileNotFoundError:
            print(f"unable to find {edi_file}")
            raise
        except OSError:
            print(f"failed to read {edi_file}")
            raise

class EDIUtils(FileUtils):
    @classmethod
    def element_name(cls, seg_id, idx) -> str:
        return "{}{:02d}".format(seg_id, idx)

    @classmethod
    def composite_element_name(cls, seg_id, idx, sub_idx) -> str:
        return "{}{:02d}-{:02d}".format(seg_id, idx, sub_idx)

    @classmethod
    def loop_name(cls, seg_id) -> str:
        return f"L_{seg_id}"

    @classmethod
    def set_name(cls, seg_id) -> str:
        return f"S_{seg_id}"

    @classmethod
    def create_segment(cls, seg_schema) -> dict:
        return { cls.element_name(seg_schema['id'], index + 1): None for index in range(0, len(seg_schema['elements'])) }

    @classmethod
    def create_segments(cls, edi_data : dict, schemas : list[dict], create_required = True) -> dict:
        # create required segments and loops
        for schema in schemas:
            edi_data[schema['id']] =\
                cls.create_segment(schema) if create_required and cls.is_required_single_segment(schema) else None

        return edi_data

    @classmethod
    def remove_empty_data(cls, edi_data : dict):
        # remove any empty top level loops/segments. Don't recurse or empty elements will be deleted
        empty_keys = []

        for each in edi_data.items():
            if not each[1]:
                empty_keys.append(each[0])

        for each in empty_keys:
            edi_data.pop(each)

    @classmethod
    def entry_count(cls, input_data : Union[dict, list] = None):
        count = 0

        if isinstance(input_data, dict):
            for entry in input_data.values():
                if isinstance(entry, dict):
                    # found a child segment
                    count += 1
                elif isinstance(entry, list):
                    # loop (can be nested) or repeating segments
                    for each in entry:
                        count += cls.entry_count(each)
                else:
                    # found first element in a segment, so this dict is a segment
                    return 1 if entry else 0
        elif isinstance(input_data, list):
            for each in input_data:
                count += cls.entry_count(each)
        else:
            raise TypeError(f"Found invalid input type: {type(input_data)}")

        return count

    @classmethod
    def get_count_between(cls, edi_data : dict, seg_id_start, seg_id_end):
        segment_count = 0
        start_found = False

        for seg_id, entry_data in edi_data.items():
            if seg_id == seg_id_start:
                start_found = True

            if start_found:
                segment_count += cls.entry_count(entry_data)

            if seg_id == seg_id_end:
                break

        return segment_count

    @classmethod
    def find_schema(cls, schemas : list[dict], seg_id) -> dict:
        for schema in schemas:
            if schema['id'] == seg_id:
                return schema

        raise ValueError(f"Schema entry {seg_id} not found")

    @classmethod
    def segment_repeats(cls, edi_format : list[dict], seg_id):
        return cls.allows_multiples(cls.find_schema(edi_format, seg_id))

    @classmethod
    def is_required_single_segment(cls, schema : dict):
        return schema['type'] == 'segment' and schema['req'] == 'M' and not cls.allows_multiples(schema)

    @classmethod
    def allows_multiples(cls, schema : dict):
        max_uses = schema.get('max_uses', -1)

        return max_uses == -1 or max_uses > 1

    @classmethod
    def create_control_number(cls, value, max_places = 9) -> int:
        return int(value / 10 ** max_places) + (value % 10 ** max_places)

