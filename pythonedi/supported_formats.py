"""
Imports and manages EDI format definitions
"""

import os
import json

format_dir = os.path.join(os.path.dirname(__file__), "formats")

def load_format_codes(format_codes_path):
    supported_format_codes = {}
    for filename in os.listdir(format_codes_path):
        if filename.endswith(".json"):
            format_name = filename[:-5]
            with open(os.path.join(format_codes_path, filename)) as format_file:
                format_code_def = json.load(format_file)
            if not isinstance(format_code_def, dict):
                raise TypeError("Imported code list {} is not an id list".format(format_name))
            supported_format_codes[format_name] = format_code_def
    return supported_format_codes

format_codes = load_format_codes(os.path.join(format_dir, "codes"))

'''
Iterate formats, populating loop, segment and element references from data.
'''
def replace_segment_placeholders():
    # scan formats and replace placeholder segments if necessary
    for edi_format in supported_formats.items():
        replace_format_segment_placeholders(edi_format[0], edi_format[1])

    # scan formats again and replace element references if necessary (scan twice to avoid unnecessary deep copies)
    for edi_format in supported_formats.items():
        replace_format_element_placeholders(edi_format[0], edi_format[1])

'''
Iterate formats, populating segments and loops of type 'placeholder'.
'''
def replace_format_segment_placeholders(format_name, format_data, loop_name = None):
    for index, segment in enumerate(format_data):
        if segment['type'] == 'placeholder':
            # replace the placeholder with real segment schema data
            replacement_id = segment.get('replacement', segment['id'])
            seg_data = supported_formats.get(replacement_id, None)

            if not seg_data or len(seg_data) < 1 or seg_data[0]['id'] != segment['id']:
                raise ValueError("Missing segment data {} for placeholder {} in format {}, loop {}".format(replacement_id, segment['id'], format_name, loop_name))

            replacement_segment = copy.deepcopy(seg_data[0])

            # allow placeholder owner to override certain replacement values
            for seg_val in ('req', 'max_uses', 'repeat'):
                if seg_val in segment:
                    replacement_segment[seg_val] = segment[seg_val]

            format_data[index] = replacement_segment

            if replacement_segment['type'] == 'loop':
                # if placeholder is a loop, iterate its segments
                replace_format_segment_placeholders(format_name, replacement_segment['segments'], replacement_segment['id'])
        # process loop
        elif segment['type'] == 'loop':
            replace_format_segment_placeholders(format_name, segment['segments'], segment['id'])

'''
Populate id code lists from dicts keyed by code id in form 'ID<code_id>'
'''
def replace_format_element_placeholders(format_name, format_data):
    for segment in format_data:
        # process loop
        if segment['type'] == 'loop':
            replace_format_element_placeholders(format_name, segment['segments'])
        # iterate the segment, replacing code list id's with corresponding data
        elif segment['type'] == 'segment':
            for each in segment['elements']:
                if each.get('data_type', '').upper() == 'ID':
                    data_type_ids = each.get('data_type_ids', None)

                    if isinstance(data_type_ids, str):
                        code_data = format_codes.get(data_type_ids, None)

                        if not code_data:
                            raise ValueError("Missing segment {} element data {} for placeholder {}". segment['id'], each['id'], data_type_ids)

                        # not doing deep copy as expectation is that data will not be changed
                        each['data_type_ids'] = code_data

def load_supported_formats(formats_path):
    supported_formats = {}
    for filename in os.listdir(formats_path):
        if filename.endswith(".json"):
            format_name = filename[:-5]
            with open(os.path.join(formats_path, filename)) as format_file:
                format_def = json.load(format_file)
            if type(format_def) is not list:
                raise TypeError("Imported definition {} is not a list of segments".format(format_name))
            supported_formats[format_name] = format_def
    return supported_formats

supported_formats = load_supported_formats(format_dir)

# scan formats and replace placeholder segments/elements if necessary
replace_segment_placeholders()
