import logging
import os
from typing import List
import graphql

from appsec_discovery.parsers import Parser
from appsec_discovery.models import CodeObject, CodeObjectField

logger = logging.getLogger(__name__)

class GraphqlParser(Parser):

    def find_graphql_files(self, root_dir):
        graphql_files = []
        for root, _, files in os.walk(root_dir):
            for file in files:
                if file.endswith('.graphql'):
                    graphql_files.append(os.path.join(root, file))
        return sorted(graphql_files)


    def run_scan(self) -> List[CodeObject]:

        objects_list: List[CodeObject] = []

        gql_files = self.find_graphql_files(self.source_folder)
        gql_data = {}

        for gql_file in gql_files:

            local_gql_file = gql_file.replace(self.source_folder, "")

            try:
                with open(gql_file) as file:
                    file_str = file.read()
                    gql_data[local_gql_file] = graphql.parse(file_str, no_location=False)
            except Exception as ex:
                logger.error(f"Failed to parse {self.parser} for file {local_gql_file}: {ex}")

        objects_list = self.parse_report(gql_data)

        return objects_list

    def resolve_fields(self, type_name, types_dict, depth):
        
        resolved_fields = {}

        if depth > 10 :
            return resolved_fields

        for field_name, field in types_dict[type_name]['fields'].items():

            if field['output'] in types_dict and types_dict[field['output']]['fields'] :

                out_resolved = self.resolve_fields(field['output'], types_dict, depth + 1)

                for out_field_name, out_field in out_resolved.items():
                    resolved_fields[f"{type_name}.{field_name}.{field['output']}.{out_field_name}"] = out_field

            else:
                resolved_fields[f"{type_name}.{field_name}"] = {
                    'type': field['output'],
                    'file': field['file'],
                    'line': field['line'],
                } 

        return resolved_fields

    def parse_report(self, gql_data) -> List[CodeObject]:

        parsed_objects: List[CodeObject] = []

        extend_types = {}

        types = {}

        for file, file_gql in gql_data.items():

            for type_def in file_gql.definitions:

                if hasattr(type_def, 'name') and type_def.kind == 'object_type_extension':
                    extend_types[type_def.name.value] = 1

                if hasattr(type_def, 'name') and type_def.name.value not in types:

                    types[type_def.name.value] = {
                        'name': type_def.name.value,
                        'type': type_def.kind,
                        'file': file,
                        'line': type_def.loc.start,
                        'fields': {}
                    }

                if hasattr(type_def, 'fields'):
                    for field_def in type_def.fields:

                        output = ''

                        if hasattr(field_def.type, 'name'):
                            output = field_def.type.name.value
                        elif hasattr(field_def.type, 'type') and hasattr(field_def.type.type, 'name'):
                            output = field_def.type.type.name.value
                        elif hasattr(field_def.type, 'type') and hasattr(field_def.type.type, 'type') and hasattr(field_def.type.type.type, 'name'):
                            output = field_def.type.type.type.name.value
                        elif hasattr(field_def.type, 'type') and hasattr(field_def.type.type, 'type') and hasattr(field_def.type.type.type, 'type') and hasattr(field_def.type.type.type.type, 'name'):
                            output = field_def.type.type.type.type.name.value

                        if hasattr(field_def, 'name') and field_def.name.value not in types[type_def.name.value]['fields']:
                            types[type_def.name.value]['fields'][field_def.name.value] = {
                                'name': field_def.name.value,
                                'file': file,
                                'line': field_def.loc.start,
                                'inputs': {},
                                'output': output, 
                            }

                        if hasattr(field_def, 'arguments'):
                            for input_def in field_def.arguments:
                                if hasattr(input_def, 'name') and input_def.name.value not in types[type_def.name.value]['fields'][field_def.name.value]['inputs']:
                                    input_type = ''
                                    if hasattr(input_def.type, 'name'):
                                        input_type = input_def.type.name.value
                                    elif hasattr(input_def.type, 'type') and hasattr(input_def.type.type, 'name'):
                                        input_type = input_def.type.type.name.value
                                    elif hasattr(input_def.type, 'type') and hasattr(input_def.type.type, 'type') and hasattr(input_def.type.type.type, 'name'):
                                        input_type = input_def.type.type.type.name.value
                                    elif hasattr(input_def.type, 'type') and hasattr(input_def.type.type, 'type') and hasattr(input_def.type.type.type, 'type') and hasattr(input_def.type.type.type.type, 'name'):
                                        input_type = input_def.type.type.type.type.name.value

                                    types[type_def.name.value]['fields'][field_def.name.value]['inputs'][input_def.name.value] = input_type
    

        for type_name, type_dict in types.items():

            if type_name in extend_types :

                for field_name, field in type_dict['fields'].items():

                    if field['output'] not in extend_types:
            
                        gql_type = 'Query'
                        gql_name = f"{type_name}.{field_name}"

                        if type_name in ['Query', 'Mutation']:
                            gql_type = type_name
                            gql_name = field_name
                        
                        elif 'Mutation' in types and types['Mutation']['fields']:
                            for mutation_field in types['Mutation']['fields'].values():
                                if mutation_field['output'] == type_name:
                                    gql_type = 'Mutation'

                        result_fields = {}

                        for input_name, input_type in field['inputs'].items():

                            if input_type in types and types[input_type]['fields']:

                                inputs_resolved = self.resolve_fields(input_type, types, 0)

                                for input_resolved_name, input_resolved in inputs_resolved.items():

                                    result_fields[f"{input_name}.{input_resolved_name}"] = input_resolved
                            else:

                                result_fields[f"{input_name}"] = {
                                    'type': input_type,
                                    'file': field['file'],
                                    'line': field['line'],
                                }

                        if field['output'] in types and types[field['output']]['fields'] :

                            outputs_resolved = self.resolve_fields(field['output'], types, 0)

                            for output_resolved_name, output_resolved in outputs_resolved.items():

                                result_fields[f"output.{output_resolved_name}"] = output_resolved

                        else:
                            result_fields["output"] = {
                                'type': field['output'],
                                'file': field['file'],
                                'line': field['line'],
                            }

                        unique_hash = self.calc_uniq_hash([field_name, gql_type, field['file']])

                        code_object = CodeObject(
                            hash=unique_hash,
                            object_name=f"{gql_type} {gql_name}",
                            object_type=gql_type.lower(),
                            parser=self.parser,
                            file=field['file'],
                            line=field['line'],
                            properties={},
                            fields={}
                        )

                        for result_field_name, result_field in result_fields.items():
                            code_object.fields[result_field_name] = CodeObjectField(
                                field_name=result_field_name,
                                field_type=result_field['type'],
                                file=result_field['file'],
                                line=result_field['line']
                            )

                        parsed_objects.append(code_object)

        logger.info(f"For scan {self.parser} data parse {len(parsed_objects)} objects")

        return parsed_objects