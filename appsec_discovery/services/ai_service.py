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

                choosen_fields = []
                fields_str = ''

                scored_fields = {}

                for field in object.fields.values():
                    if ( 'int' in field.field_type.lower() or 'str' in field.field_type.lower() ) and \
                    ( 'idempotency' not in field.field_name.lower() 
                        and not field.field_name.endswith('Id')
                        and not field.field_name.endswith('ID')
                        and not field.field_name.lower().endswith('_id')
                        and not field.field_name.lower().endswith('_ids')
                        and not field.field_name.lower().endswith('.id')
                        and not field.field_name.lower().endswith('.ids')
                        and not field.field_name.lower().endswith('_date')
                        and not field.field_name.lower().endswith('page')
                        and not field.field_name.lower().endswith('per_page')
                        and not field.field_name.lower().endswith('limit')
                        and not field.field_name.lower().endswith('total')
                        and not field.field_name.lower().endswith('total_items') 
                        and not field.field_name.lower().endswith('_filename') 
                        and not field.field_name.lower().endswith('_size') 
                        and not field.field_name.lower().endswith('id_in') 
                        and not field.field_name.lower().endswith('ids_in') 
                        and not field.field_name.lower() == 'id') :
                        
                        fields_str += f" - {field.field_name}\n"
                        choosen_fields.append(field.field_name)

                question1 = f'''
                    For object: {object.object_name}
                    Fields: 
                    {fields_str}
                    Can contain private data? Answer only 'yes' or 'no',
                '''

                question2 = f'''
                    For object: {object.object_name}
                    Fields: 
                    {fields_str}
                    Choose category for private data from lost: pii, finance, auth, other 
                    Answer only with category name word.
                '''

                question3 = f'''
                    For object: {object.object_name}
                    Fields: 
                    {fields_str}
                    Choose only fields that can contain private data.
                    Answer only with choosen field names separated by comma.
                '''
                
                # Local
                if choosen_fields and self.ai_local:

                    llm = Llama.from_pretrained(
                        repo_id=self.ai_local.model_id,
                        filename=self.ai_local.gguf_file,
                        verbose=False,
                        cache_dir=self.ai_local.model_folder,

                    )

                    response = llm.create_chat_completion(
                        messages = [
                            {"role": "system", "content": self.ai_local.system_prompt},
                            {"role": "user", "content": question1 },
                        ]
                    )

                    answer1 = response['choices'][0]["message"]["content"]

                    logger.info(f"For question {question1} llm answer is {answer1}")

                    if 'yes' in answer1.lower():

                        response2 = llm.create_chat_completion(
                            messages = [
                                {"role": "system", "content": self.ai_local.system_prompt},
                                {"role": "user", "content": question2 },
                            ]
                        )

                        answer2 = response2['choices'][0]["message"]["content"]

                        logger.info(f"For question {question2} llm answer is {answer2}")

                        result_cats = []

                        for cat in ['pii', 'auth', 'finance', 'other']:
                            if cat in answer2.lower():
                                result_cats.append(f'llm-{cat}')

                        response3 = llm.create_chat_completion(
                            messages = [
                                {"role": "system", "content": self.ai_local.system_prompt},
                                {"role": "user", "content": question3 },
                            ]
                        )

                        answer3 = response3['choices'][0]["message"]["content"]

                        logger.info(f"For question {question3} llm answer is {answer3}")

                        for field in object.fields.values():
                            if field.field_name in choosen_fields and field.field_name.split('.')[-1].lower() in answer3.lower():

                                scored_fields[field.field_name] = result_cats
                                logger.info(f"For object {object.object_name} field {field.field_name} scored as {result_cats}")


                # API
                if choosen_fields and self.ai_api and not self.ai_local:

                    client = OpenAI(api_key=self.ai_api.api_key, base_url=self.ai_api.base_url)

                    response1 = client.chat.completions.create(
                        model=self.ai_api.model,
                        messages=[
                            {"role": "system", "content": self.ai_api.system_prompt},
                            {"role": "user", "content": question1},
                        ],
                        stream=False
                    )
                    
                    answer1 = response1.choices[0].message.content

                    logger.info(f"For question {question1} llm answer is {answer1}")

                    if 'yes' in answer1.lower():

                        response2 = client.chat.completions.create(
                            model=self.ai_api.model,
                            messages=[
                                {"role": "system", "content": self.ai_api.system_prompt},
                                {"role": "user", "content": question2},
                            ],
                            stream=False
                        )

                        answer2 = response2.choices[0].message.content

                        logger.info(f"For question {question2} llm answer is {answer2}")

                        result_cats = []

                        for cat in ['pii', 'auth', 'finance', 'other']:
                            if cat in answer2.lower():
                                result_cats.append(f'llm-{cat}')
                        
                        response3 = client.chat.completions.create(
                            model=self.ai_api.model,
                            messages=[
                                {"role": "system", "content": self.ai_api.system_prompt},
                                {"role": "user", "content": question3},
                            ],
                            stream=False
                        )

                        answer3 = response3.choices[0].message.content

                        logger.info(f"For question {question3} llm answer is {answer3}")

                        for field in object.fields.values():
                            if field.field_name in choosen_fields and field.field_name.split('.')[-1].lower() in answer3.lower():

                                scored_fields[field.field_name] = result_cats
                                logger.info(f"For object {object.object_name} field {field.field_name} scored as {result_cats}")
                                
                        
                severity = "medium"

                all_fields = {}

                for field_name, field in object.fields.items():

                    if field.field_name in scored_fields.keys():

                        excluded = False

                        tags = scored_fields[field.field_name]

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
                                and (exclude.tag is None or exclude.tag in tags ) \
                                and (exclude.keyword is None ) :
                                
                                excluded = True

                        if not excluded :

                            if not field.severity:
                                field.severity = severity
                                field.tags = tags
                            else:

                                for tag in tags:
                                    if tag not in field.tags:
                                        field.tags.append(tag)

                                if severities_int[severity] > severities_int[field.severity]:
                                    field.severity = severity

                            if not object.severity:
                                object.severity = severity
                                object.tags = tags
                            else:
                                for tag in tags:
                                    if tag not in object.tags:
                                        object.tags.append(tag)

                                if severities_int[severity] > severities_int[object.severity]:
                                    object.severity = severity

                    all_fields[field_name] = field
                
                object.fields = all_fields

                scored_objects.append(object)

        except Exception as ex:
            logger.error(f"Error while ai scoring: {ex}")

        # Check that all processed
        if len(scored_objects) == len(code_objects):
            return scored_objects
        
        else:
            return code_objects
