from pydantic import BaseModel
from typing import List, Dict, Optional

class CodeObjectField(BaseModel):
    field_name: str
    field_type: str
    file: Optional[str]
    line: Optional[int]
    severity: Optional[str]
    tags: Optional[List[str]]

class CodeObjectProp(BaseModel):
    prop_name: str
    prop_value: str
    file: Optional[str]
    line: Optional[int]
    severity: Optional[str]
    tags: Optional[List[str]]

class CodeObject(BaseModel):
    hash: str
    object_name: str
    object_type: str
    parser: str
    severity: Optional[str]
    tags: Optional[List[str]]
    file: str
    line: int
    properties: Dict[str, CodeObjectProp]
    fields: Dict[str, CodeObjectField]


