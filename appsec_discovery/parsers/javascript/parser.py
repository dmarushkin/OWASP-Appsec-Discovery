import logging
import os
from typing import List, Dict
from pathlib import Path

from appsec_discovery.parsers import Parser
from appsec_discovery.models import CodeObject, CodeObjectProp

logger = logging.getLogger(__name__)


class JsGqlParser(Parser):

    def run_scan(self) -> List[CodeObject]:

        objects_list: List[CodeObject] = []

        parser_folder = str(Path(__file__).resolve().parent)

        rules_folder = os.path.join(parser_folder, "scanner_rules")

        if os.path.isdir(rules_folder):
            
            semgrep_data = self.run_semgrep(source_folder=self.source_folder, rules_folder=rules_folder)
            objects_list = self.parse_report(semgrep_data)
        
        return objects_list


    def parse_report(self, semgrep_data) -> List[CodeObject]:

        parsed_objects: List[CodeObject] = []
        parsed_objects_dict: Dict[str, CodeObject] = {}

        for finding in semgrep_data:

            finding_file = finding.get('path')
            finding_line_int = finding.get('start',{}).get('line',0)

            rule_id = finding.get('check_id',"").split('.')[-1]

            object_type = None

            # parse dto rules
            if rule_id.startswith("js-graphql-queries"):

                request = finding.get('extra').get('metavars').get('$QUERY', {}).get('abstract_content',"").strip()
                
                # get only queries and mutations, no fragments
                # mutation ContractorCreateMutation($input: CreateContractorInput!) vs query OkfsCodesQuery {
                
                if ('query' in request.lower() or 'mutation' in request.lower()) and not 'fragment ' in request.lower() :

                    if len(request.split('(')[0]) < len(request.split('{')[0]):
                        req_name = request.split('(')[0].strip()
                    else:
                        req_name = request.split('{')[0].strip()

                    gql_type = req_name.split(' ')[0].lower()  # mutation ContractorCreateMutation => mutation

                    req_name = req_name.split(' ')[-1]

                    resolvers = self.find_resolvers(request)

                    for resolver in resolvers:

                        if len(resolver.split('(')[0]) < len(resolver.split('{')[0]):
                            resolver_name = resolver.split('(')[0].strip()
                        else:
                            resolver_name = resolver.split('{')[0].strip()

                        object_type=f"js-gql-{gql_type}"
                        object_name = f"JS GQL Resolver {resolver_name} in {gql_type} {req_name}"

                        hash_key = self.calc_uniq_hash([finding_file, request, resolver])

                        if hash_key not in parsed_objects_dict:

                            parsed_objects_dict[hash_key] = CodeObject(
                                hash=hash_key,
                                object_name=object_name,
                                object_type=object_type,
                                parser=self.parser,
                                file=finding_file,
                                line=finding_line_int,
                                properties={},
                                fields=[]
                            )

                        parsed_objects_dict[hash_key].properties['request_name'] = CodeObjectProp(
                            prop_name='request_name',
                            prop_value=req_name
                        )

                        parsed_objects_dict[hash_key].properties['request_text'] = CodeObjectProp(
                            prop_name='request_text',
                            prop_value=request
                        )

                        parsed_objects_dict[hash_key].properties['resolver_name'] = CodeObjectProp(
                            prop_name='resolver_name',
                            prop_value=resolver_name
                        )

                        parsed_objects_dict[hash_key].properties['resolver_text'] = CodeObjectProp(
                            prop_name='resolver_text',
                            prop_value=resolver
                        )
            
        if parsed_objects_dict:
            parsed_objects = list(parsed_objects_dict.values())

        logger.info(f"For scan {self.parser} data parse {len(parsed_objects)} objects")
        return parsed_objects
    
    def find_resolvers(self, all_text):

        start = True

        brackets_counter = 0
        s_brackets_counter = 0

        resolvers = []
        cur_resolver = ""

        some_processed = False

        for char in all_text:

            cur_resolver = cur_resolver + char

            if char == '{' and s_brackets_counter == 0 and start:
                cur_resolver = "" 

            if s_brackets_counter > 1 and start:
                start = False

            if char == '{' and brackets_counter == 0:
                s_brackets_counter = s_brackets_counter + 1

            if char == '}' and brackets_counter == 0:
                s_brackets_counter = s_brackets_counter - 1

            if char == '(':
                brackets_counter = brackets_counter + 1

            if char == ')':
                brackets_counter = brackets_counter - 1

            if start == False and s_brackets_counter == 1 and cur_resolver.strip():
                resolvers.append(cur_resolver.strip())
                cur_resolver = ""
                start = True
                some_processed = True

            if some_processed and s_brackets_counter == 0:
                break

        return resolvers
