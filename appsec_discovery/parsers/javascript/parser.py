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

                query_text = finding.get('extra').get('metavars').get('$QUERY', {}).get('abstract_content',"").strip()
                
                # get only queries and mutations, no fragments
                # mutation ContractorCreateMutation($input: CreateContractorInput!) vs query OkfsCodesQuery {
                
                if 'query' in query_text.lower() or 'mutation' in query_text.lower():
                    if len(query_text.split('(')[0]) < len(query_text.split('{')[0]):
                        req_name = query_text.split('(')[0].strip()
                    else:
                        req_name = query_text.split('{')[0].strip()

                gql_type = req_name.split(' ')[0].lower()  # mutation ContractorCreateMutation => mutation

                object_type=f"js-gql-{gql_type}"
                object_name = f"Javascript graphql {req_name}"

                hash_key = self.calc_uniq_hash([finding_file, query_text])

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

                    parsed_objects_dict[hash_key].properties['text'] = CodeObjectProp(
                        prop_name='text',
                        prop_value=query_text
                    )
        
        if parsed_objects_dict:
            parsed_objects = list(parsed_objects_dict.values())

        logger.info(f"For scan {self.parser} data parse {len(parsed_objects)} objects")
        return parsed_objects