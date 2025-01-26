from typing import List
import logging
import yaml
import re

from appsec_discovery.models import ScoreConfig, CodeObject
from appsec_discovery.parsers import ParserFactory, Parser
from appsec_discovery.services.ai_service import AiService

logger = logging.getLogger(__name__)

severities_int = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}

class ScanService:

    def __init__(self, source_folder=None, conf_file=None, only_scored_objects=False):

        self.conf_file = conf_file
        self.source_folder = source_folder

        self.config = None

        if conf_file:
            self.config = self.load_conf_from_yaml(conf_file)
        else:
            self.config = ScoreConfig()

        self.only_scored_objects = only_scored_objects

    def load_conf_from_yaml(self, score_config_file_stream):

        try:

            config_data = yaml.safe_load(score_config_file_stream)
            score_config = ScoreConfig(**config_data)

            if score_config :
                return score_config
                
        except Exception as ex:
            logger.error(f"Failed to load config scan folder {self.source_folder}: {ex}")

    def scan_folder(self) -> List[CodeObject]:

        parsed_objects: List[CodeObject] = []

        all_parsers = ParserFactory.get_parser_types()

        parsers_to_scan = []

        if 'all' in self.config.parsers:
            parsers_to_scan = all_parsers
        else:
            for parser in self.config.parsers:
                if parser in all_parsers:
                    parsers_to_scan.append(parser)

        for parser in parsers_to_scan:

            ParserCls = ParserFactory.get_parser(parser)
            parser_instance: Parser = ParserCls(parser=parser, source_folder=self.source_folder)

            res = parser_instance.run_scan()

            if res:
                parsed_objects += res

        filtered_objects = self.filter_objects(parsed_objects)
        scored_objects = self.score_objects(filtered_objects)

        if self.config.ai_local or self.config.ai_api:
            ai = AiService(exclude_scoring=self.config.exclude_scoring, ai_local=self.config.ai_local, ai_api=self.config.ai_api)
            ai_scored_objects = ai.ai_score_objects(scored_objects)

            result_objects = [ obj for obj in ai_scored_objects if obj.severity or not self.only_scored_objects ]
            return result_objects

        result_objects = [ obj for obj in scored_objects if obj.severity or not self.only_scored_objects ]
        return result_objects

    
    def filter_objects(self, parsed_objects: List[CodeObject]):

        filtered_objects: List[CodeObject] = []

        for object in parsed_objects:

            fitered = False

            for exclude in self.config.exclude_scan:

                if ( exclude.file or exclude.object_name or exclude.object_type or exclude.parser ) \
                    and (exclude.parser is None or exclude.parser.lower() == object.parser.lower()) \
                    and (exclude.file is None or re.match(exclude.file, object.file) or exclude.file.lower() in object.file.lower()) \
                    and (exclude.object_name is None or re.match(exclude.object_name, object.object_name) or exclude.object_name.lower() in object.object_name.lower()) \
                    and (exclude.object_type is None or re.match(exclude.object_type, object.object_type) or exclude.object_type.lower() in object.object_type.lower()) :
                    
                    fitered = True

            if not fitered:
                filtered_objects.append(object)

        return filtered_objects
    

    def score_objects(self, filtered_objects: List[CodeObject]):

        scored_objects: List[CodeObject] = []

        for object in filtered_objects:

            for tag, severities in self.config.score_tags.items():
                for severity, keywords in severities.items():
                    for keyword in keywords:

                        for prop_name, prop in object.properties.items():

                            if re.match(keyword, prop.prop_value) or keyword.lower() in prop.prop_value.lower():

                                excluded = False

                                for exclude in self.config.exclude_scoring:

                                    if ( exclude.file or exclude.parser or exclude.object_name or exclude.object_type or exclude.prop_name 
                                         or exclude.field_name or exclude.field_type or exclude.tag or exclude.keyword ) \
                                        and (exclude.parser is None or exclude.parser.lower() == object.parser.lower()) \
                                        and (exclude.file is None or re.match(exclude.file, object.file) or exclude.file.lower() in object.file.lower()) \
                                        and (exclude.object_name is None or re.match(exclude.object_name, object.object_name) or exclude.object_name.lower() in object.object_name.lower()) \
                                        and (exclude.object_type is None or re.match(exclude.object_type, object.object_type) or exclude.object_type.lower() in object.object_type.lower()) \
                                        and (exclude.prop_name is None or re.match(exclude.prop_name, prop_name) or exclude.prop_name.lower() in prop_name.lower()) \
                                        and (exclude.field_name is None ) \
                                        and (exclude.field_type is None ) \
                                        and (exclude.tag is None or exclude.tag == tag ) \
                                        and (exclude.keyword is None or exclude.tag == keyword) :
                                        
                                        excluded = True

                                if not excluded :

                                    if not object.properties[prop_name].severity:
                                        object.properties[prop_name].severity = severity
                                        object.properties[prop_name].tags = [tag]                                            
                                    else:
                                        if tag not in object.properties[prop_name].tags:
                                            object.properties[prop_name].tags.append(tag)

                                        if severities_int[severity] > severities_int[object.properties[prop_name].severity]:
                                            object.properties[prop_name].severity = severity

                                    if not object.severity:
                                        object.severity = severity
                                        object.tags=[tag]
                                    else:
                                        if tag not in object.tags:
                                            object.tags.append(tag)

                                        if severities_int[severity] > severities_int[object.severity]:
                                            object.severity = severity

                        scored_fields = {}

                        for field_name, field in object.fields.items():

                            if re.match(keyword, field.field_name) or keyword.lower() in field.field_name.lower():

                                excluded = False

                                for exclude in self.config.exclude_scoring:

                                    if ( exclude.file or exclude.parser or exclude.object_name or exclude.object_type or exclude.prop_name 
                                         or exclude.field_name or exclude.field_type or exclude.tag or exclude.keyword ) \
                                        and (exclude.parser is None or exclude.parser.lower() == object.parser.lower()) \
                                        and (exclude.file is None or re.match(exclude.file, object.file) or exclude.file.lower() in object.file.lower()) \
                                        and (exclude.object_name is None or re.match(exclude.object_name, object.object_name) or exclude.object_name.lower() in object.object_name.lower()) \
                                        and (exclude.object_type is None or re.match(exclude.object_type, object.object_type) or exclude.object_type.lower() in object.object_type.lower()) \
                                        and (exclude.prop_name is None ) \
                                        and (exclude.field_name is None or re.match(exclude.field_name, field.field_name) or exclude.field_name.lower() in field.field_name.lower()) \
                                        and (exclude.field_type is None or re.match(exclude.field_type, field.field_type) or exclude.field_type.lower() in field.field_type.lower()) \
                                        and (exclude.tag is None or exclude.tag == tag ) \
                                        and (exclude.keyword is None or exclude.tag == keyword) :
                                        
                                        excluded = True

                                if not excluded :

                                    if not field.severity:
                                        field.severity = severity
                                        field.tags = [tag]
                                    else:
                                        if tag not in field.tags:
                                            field.tags.append(tag)

                                        if severities_int[severity] > severities_int[field.severity]:
                                            field.severity = severity

                                    if not object.severity:
                                        object.severity = severity
                                        object.tags = [tag]
                                    else:
                                        if tag not in object.tags:
                                            object.tags.append(tag)

                                        if severities_int[severity] > severities_int[object.severity]:
                                            object.severity = severity
  
                            scored_fields[field_name] = field
                        
                        object.fields = scored_fields

            scored_objects.append(object)

        return scored_objects
