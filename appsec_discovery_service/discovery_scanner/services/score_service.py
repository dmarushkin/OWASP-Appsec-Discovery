import re
from typing import List, Dict

from models import DbCodeObject
from logger import get_logger
from llama_cpp import Llama, LlamaRAMCache
from openai import OpenAI

from config import LLM_API_KEY, LLM_API_MODEL, LLM_API_URL, LLM_LOCAL_FILE, LLM_LOCAL_MODEL, LLM_PROMPT

import re

severities_int = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
skip_ai = ['created_at', 'updated_at', 'deleted_at']


logger = get_logger(__name__)

def score_field(service, object, object_type, field_name, field_type, score_rules):

    for rule in score_rules:

        if ( not rule.service_re or re.match(rule.service_re, service) or rule.service_re.lower() in service.lower()) \
          and ( not rule.object_re or re.match(rule.object_re, object) or rule.object_re.lower() in object.lower() ) \
          and ( not rule.object_type_re or re.match(rule.object_type_re, object_type) or rule.object_type_re.lower() in object_type.lower() ) \
          and ( not rule.field_re or re.match(rule.field_re, field_name) or rule.field_re.lower() in field_name.lower() ) \
          and ( not rule.field_type_re or re.match(rule.field_type_re, field_type) or rule.field_type_re.lower() in field_type.lower() ) :
            logger.info(f"Object {object}, field {field_name} scored as risky for {str(rule.risk_score)}")
            return rule.risk_score
    
    return 0 


def llm_score_objects(objects_to_score: List[DbCodeObject]):
    
    scored_objects = []


    for object in objects_to_score:
        
        try:
                        
            scored_list = {}

            for field in object.fields:

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
                if LLM_LOCAL_MODEL:

                    llm = Llama.from_pretrained(
                        repo_id=LLM_LOCAL_MODEL,
                        filename=LLM_LOCAL_FILE,
                        verbose=False,
                        cache_dir="/hf_models",
                    )

                    response = llm.create_chat_completion(
                        messages = [
                            {"role": "system", "content": LLM_PROMPT},
                            {"role": "user", "content": question },
                        ]
                    )

                    answer = response['choices'][0]["message"]["content"]

                    if 'yes' in answer.lower():

                        response2 = llm.create_chat_completion(
                            messages = [
                                {"role": "system", "content": LLM_PROMPT},
                                {"role": "user", "content": question2 },
                            ]
                        )

                        answer2 = response2['choices'][0]["message"]["content"]

                        for cat in ['pii', 'auth', 'finance', 'other']:
                            if cat in answer2.lower():
                                scored_list[field.field_name] = f"llm-{cat}"
                                logger.info(f"For {object.object_name} and {field.field_name} llm answer is {answer}, cat {answer2}")

                # API
                if LLM_API_URL:

                    client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_API_URL)

                    response = client.chat.completions.create(
                        model=LLM_API_MODEL,
                        messages=[
                            {"role": "system", "content": LLM_PROMPT},
                            {"role": "user", "content": question},
                        ],
                        stream=False
                    )

                    answer = response.choices[0].message.content

                    if 'yes' in answer.lower():

                        response2 = client.chat.completions.create(
                            model=LLM_API_MODEL,
                            messages=[
                                {"role": "system", "content": LLM_PROMPT},
                                {"role": "user", "content": question2},
                            ],
                            stream=False
                        )

                        answer2 = response2.choices[0].message.content

                        for cat in ['pii', 'auth', 'finance', 'other']:
                            if cat in answer2.lower():
                                scored_list[field.field_name] = f"llm-{cat}"
                                logger.info(f"For {object.object_name} and {field.field_name} llm answer is {answer}, cat {answer2}")
            
            scored_fields = []

            severity = "medium"

            for field in object.fields:

                if field.field_name in scored_list.keys():

                    excluded = False

                    tag = scored_list[field.field_name]

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

                scored_fields.append(field)
            
            object.fields = scored_fields

            scored_objects.append(object)

        except Exception as ex:
            logger.error(f"Error while ai scoring: {ex}")
            scored_objects.append(object)

    return scored_objects
