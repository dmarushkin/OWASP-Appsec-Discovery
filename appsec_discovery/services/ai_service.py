from llama_cpp import Llama, LlamaRAMCache
from openai import OpenAI

import re

from typing import List, Dict
import logging

from appsec_discovery.models import CodeObject, ExcludeScoring, AiLocal, AiApi

severities_int = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
skip_ai = ['created_at', 'updated_at', 'deleted_at']

logger = logging.getLogger(__name__)

class AiService:

    def __init__(self, exclude_scoring: List[ExcludeScoring], ai_local: AiLocal = None, ai_api: AiApi = None):

        self.ai_local = ai_local
        self.ai_api = ai_api

        self.exclude_scoring = exclude_scoring       

    def ai_score_objects(self, code_objects: List[CodeObject]) -> List[CodeObject]:

        scored_objects: List[CodeObject] = []

        try:

            for object in code_objects:

                object_to_score: Dict[str: List[str]] = {'field_names': []}
                
                scored_list = {}

                for field in object.fields.values() :

                    if field.field_name.split('.')[0].lower() in ['input','output'] and len(field.field_name.split('.')) > 1 :
                        field_name = ".".join(field.field_name.split('.')[1:])
                    else:
                        field_name = field.field_name

                    question = f'''
                        For object: {object.object_name}
                        
                        Field name: {field_name}

                        Can contain private data? Answer only 'yes' or 'no',
                    '''

                    question2 = f'''
                        For object: {object.object_name}
                        
                        Field name: {field_name}

                        Choose category for field private data from lost: pii, finance, auth, other 

                        Answer only with category name word.
                    '''
                    
                    # Local
                    if self.ai_local:

                        llm = Llama.from_pretrained(
                            repo_id=self.ai_local.model_id,
                            filename=self.ai_local.gguf_file,
                            verbose=False,
                            cache_dir=self.ai_local.model_folder,
                            max_tokens=5,
                            seed=112358,
                        )

                        response = llm.create_chat_completion(
                            messages = [
                                {"role": "system", "content": self.ai_local.system_prompt},
                                {"role": "user", "content": question },
                            ]
                        )

                        llm.reset()
                        llm.set_cache(None)

                        answer = response['choices'][0]["message"]["content"]

                        if 'yes' in answer.lower():

                            response2 = llm.create_chat_completion(
                                messages = [
                                    {"role": "system", "content": self.ai_local.system_prompt},
                                    {"role": "user", "content": question2 },
                                ]
                            )

                            answer2 = response2['choices'][0]["message"]["content"]

                            for cat in ['pii', 'auth', 'finance', 'other']:
                                if cat in answer2.lower():
                                    scored_list[field.field_name] = f"llm-{cat}"
                                    logger.info(f"For {object.object_name} and {field.field_name} llm answer is {answer}, cat {answer2}")

                    # API
                    if self.ai_api:

                        client = OpenAI(api_key=self.ai_api.api_key, base_url=self.ai_api.base_url)

                        response = client.chat.completions.create(
                            model=self.ai_api.model,
                            messages=[
                                {"role": "system", "content": self.ai_api.system_prompt},
                                {"role": "user", "content": question},
                            ],
                            stream=False
                        )

                        answer = response.choices[0].message.content

                        if 'yes' in answer.lower():

                            response2 = client.chat.completions.create(
                                model=self.ai_api.model,
                                messages=[
                                    {"role": "system", "content": self.ai_api.system_prompt},
                                    {"role": "user", "content": question2},
                                ],
                                stream=False
                            )

                            answer2 = response2.choices[0].message.content

                            for cat in ['pii', 'auth', 'finance', 'other']:
                                if cat in answer2.lower():
                                    scored_list[field.field_name] = f"llm-{cat}"
                                    logger.info(f"For {object.object_name} and {field.field_name} llm answer is {answer}, cat {answer2}")
                
                scored_fields = {}

                severity = "medium"

                for field_name, field in object.fields.items():

                    if field.field_name in scored_list.keys():

                        excluded = False

                        tag = scored_list[field.field_name]

                        for exclude in self.exclude_scoring:

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
                                and (exclude.keyword is None ) :
                                
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

        except Exception as ex:
            logger.error(f"Error while ai scoring: {ex}")

        # Check that all processed
        if len(scored_objects) == len(code_objects):
            return scored_objects
        
        else:
            return code_objects
