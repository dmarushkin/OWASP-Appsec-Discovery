from pydantic import BaseModel
from typing import List, Dict, Optional

default_rules = {
    'pii': {
       'high': [
          'full_name',
          'fullname',
          'first_name',
          'firstname',
          'last_name',
          'lastname',
          'phone',
          'passport',
          'ssn'
       ],
       'medium': [
          'address',
          'email'
       ],
       'low': [
          'city'
       ]
    },
    'finance': {
       'high': [
          'pan',
          'card_number'
          'cardnumber'
       ],
       'medium': [
          'account_number',
          'accountnumber',
          'balance',
          'amount'
       ],
       'low': [
       ]
    },
    'auth': {
       'high': [
          'password',
          'pincode',
          'codeword',
          'token'
       ],
       'medium': [
          'login',
          'email',
          'phone',
          'username',
       ],
       'low': [
       ]
    },
}

class ExcludeScan(BaseModel):
    file: Optional[str]
    parser: Optional[str]
    object_name: Optional[str]
    object_type: Optional[str]

class ExcludeScoring(BaseModel):
    file: Optional[str]
    parser: Optional[str]
    object_name: Optional[str]
    object_type: Optional[str]
    prop_name: Optional[str]
    field_name: Optional[str]
    field_type: Optional[str]
    tag: Optional[str]
    keyword: Optional[str]

class AiLocal(BaseModel):
    model_folder: str
    model_id: str
    gguf_file: str
    system_prompt: str

class AiApi(BaseModel):
    base_url: str
    api_key: str
    model: str
    system_prompt: str

class ScoreConfig(BaseModel):
    parsers: List[str] = ['all']
    object_types: List[str] = ['all']
    score_tags: Dict[str,Dict[str,List[str]]] = default_rules
    ai_local: Optional[AiLocal]
    ai_api: Optional[AiApi]
    exclude_scan: List[ExcludeScan] = []
    exclude_scoring: List[ExcludeScoring] = []

