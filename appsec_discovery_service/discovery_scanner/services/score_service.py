import re
from typing import List, Dict

from models import DbObject, DbLLMScore
from logger import get_logger
from llama_cpp import Llama, LlamaRAMCache
from openai import OpenAI

from config import LLM_API_KEY, LLM_API_MODEL, LLM_API_URL, LLM_LOCAL_FILE, LLM_LOCAL_MODEL, LLM_PROMPT, LLM_PROMPT_VER



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


def llm_score_objects(objects_to_score: List[DbObject]):
    
    scored_fields = []

    for object in objects_to_score:
        
        try:
            
            choosen_fields = []
            fields_str = ''

            for field in object.fields:
                if ( 'int' in field.type.lower() or 'str' in field.type.lower() ) and \
                   ( 'idempotency' not in field.name.lower() 
                     and not field.name.endswith('Id')
                     and not field.name.endswith('ID')
                     and not field.name.lower().endswith('_id')
                     and not field.name.lower().endswith('_ids')
                     and not field.name.lower().endswith('.id')
                     and not field.name.lower().endswith('.ids')
                     and not field.name.lower().endswith('_date')
                     and not field.name.lower().endswith('page')
                     and not field.name.lower().endswith('per_page')
                     and not field.name.lower().endswith('limit')
                     and not field.name.lower().endswith('total')
                     and not field.name.lower().endswith('total_items') 
                     and not field.name.lower().endswith('_filename') 
                     and not field.name.lower().endswith('_size') 
                     and not field.name.lower().endswith('id_in') 
                     and not field.name.lower().endswith('ids_in') 
                     and not field.name.lower() == 'id') :
                    
                    fields_str += f" - {field.name}\n"
                    choosen_fields.append(field.name)

            question1 = f'''
                For object: {object.name}
                Fields: 
                {fields_str}
                Can contain private data? Answer only 'yes' or 'no',
            '''

            question2 = f'''
                For object: {object.name}
                Fields: 
                {fields_str}
                Choose category for private data from lost: pii, finance, auth, other 
                Answer only with category name word.
            '''

            question3 = f'''
                For object: {object.name}
                Fields: 
                {fields_str}
                Choose only fields that can contain private data.
                Answer only with choosen field names separated by comma.
            '''
            
            # Local
            if fields_str and LLM_LOCAL_MODEL :

                llm = Llama.from_pretrained(
                    repo_id=LLM_LOCAL_MODEL,
                    filename=LLM_LOCAL_FILE,
                    verbose=False,
                    cache_dir="/hf_models",
                )

                response = llm.create_chat_completion(
                    messages = [
                        {"role": "system", "content": LLM_PROMPT},
                        {"role": "user", "content": question1 },
                    ]
                )

                answer1 = response['choices'][0]["message"]["content"]

                logger.info(f"For question {question1} llm answer is {answer1}")

                if 'yes' in answer1.lower():

                    response2 = llm.create_chat_completion(
                        messages = [
                            {"role": "system", "content": LLM_PROMPT},
                            {"role": "user", "content": question2 },
                        ]
                    )

                    answer2 = response2['choices'][0]["message"]["content"]

                    logger.info(f"For question {question2} llm answer is {answer2}")

                    result_cat = 'other'

                    for cat in ['pii', 'auth', 'finance', 'other']:
                        if cat in answer2.lower():

                            result_cat = cat

                    response3 = llm.create_chat_completion(
                        messages = [
                            {"role": "system", "content": LLM_PROMPT},
                            {"role": "user", "content": question3 },
                        ]
                    )

                    answer3 = response3['choices'][0]["message"]["content"]

                    logger.info(f"For question {question3} llm answer is {answer3}")

                    for field in object.fields:
                        if field.name in choosen_fields and field.name.split('.')[-1].lower() in answer3.lower():

                            field_score = DbLLMScore(
                                field_id=field.id,
                                model=LLM_LOCAL_MODEL,
                                prompt_ver=LLM_PROMPT_VER,
                                severity='medium',
                                tag=result_cat,             
                            )

                            scored_fields.append(field_score)

                            logger.info(f"For object {object.name} field {field.name} scored as {result_cat}")              

            # API
            if fields_str and LLM_API_URL and not LLM_LOCAL_MODEL:

                client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_API_URL)

                response = client.chat.completions.create(
                    model=LLM_API_MODEL,
                    messages=[
                        {"role": "system", "content": LLM_PROMPT},
                        {"role": "user", "content": question1},
                    ],
                    stream=False
                )

                answer1 = response.choices[0].message.content

                logger.info(f"For question {question1} llm answer is {answer1}")

                if 'yes' in answer1.lower():

                    response2 = client.chat.completions.create(
                        model=LLM_API_MODEL,
                        messages=[
                            {"role": "system", "content": LLM_PROMPT},
                            {"role": "user", "content": question2},
                        ],
                        stream=False
                    )

                    answer2 = response2.choices[0].message.content

                    logger.info(f"For question {question2} llm answer is {answer2}")

                    result_cat = 'other'

                    for cat in ['pii', 'auth', 'finance', 'other']:
                        if cat in answer2.lower():
                            result_cat = cat
                    
                    response3 = client.chat.completions.create(
                        model=LLM_API_MODEL,
                        messages=[
                            {"role": "system", "content": LLM_PROMPT},
                            {"role": "user", "content": question3},
                        ],
                        stream=False
                    )

                    answer3 = response3.choices[0].message.content

                    logger.info(f"For question {question3} llm answer is {answer3}")

                    for field in object.fields:
                        if field.name in choosen_fields and field.name.split('.')[-1].lower() in answer3.lower():

                            field_score = DbLLMScore(
                                field_id=field.id,
                                model=LLM_API_MODEL,
                                prompt_ver=LLM_PROMPT_VER,
                                severity='medium',
                                tag=result_cat,             
                            )

                            scored_fields.append(field_score)

                            logger.info(f"For object {object.name} field {field.name} scored as {result_cat}")

        except Exception as ex:
            logger.error(f"Error while ai scoring: {ex}")

    return scored_fields
