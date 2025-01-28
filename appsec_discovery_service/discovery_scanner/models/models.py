from typing import List, Optional
from sqlmodel import SQLModel, Field, Relationship
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, ARRAY, String

from datetime import datetime
from enum import Enum

class Project(SQLModel, table=True):
    __tablename__ = "gitlab_projects"
    id: Optional[int] = Field(default=None, primary_key=True)
    project_name: str
    full_path: str
    description: Optional[str] = None
    default_branch: Optional[str] = None
    visibility: str
    created_at: datetime
    updated_at: datetime
    processed_at: Optional[datetime] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = Field(
        sa_column=Column(ARRAY(String)),
        default=None
    )
    branches: List["Branch"] = Relationship(back_populates="project")
    mrs: List["MR"] = Relationship(back_populates="project")

class Branch(SQLModel, table=True):
    __tablename__ = "gitlab_branches"
    id: Optional[int] = Field(default=None, primary_key=True)
    branch_name: str
    is_main: bool = Field(default=False) 
    created_at: datetime
    updated_at: datetime
    commit: str
    processed_at: Optional[datetime] = None
    project_id: int = Field(default=None, foreign_key="gitlab_projects.id")
    project: Project = Relationship(back_populates="branches")
    project_path: str

class MR(SQLModel, table=True):
    __tablename__ = "gitlab_mrs"
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="gitlab_projects.id")
    project_path: str
    project: Project = Relationship(back_populates="mrs")
    source_branch_id: int
    source_branch: str
    source_branch_commit: str    
    target_branch_id: int
    target_branch: str
    target_branch_commit: str
    mr_id: int
    title: str 
    description: Optional[str] = None
    state: str
    diff: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    alerted_at: Optional[datetime] = None
    processed_at: Optional[datetime] = None

class Scan(SQLModel, table=True):
    __tablename__ = "discovery_scans"
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="gitlab_projects.id")
    branch_id: int = Field(default=None, foreign_key="gitlab_branches.id")
    project_path: str
    branch_name: str
    branch_commit: str
    scanner: str
    rules_version: str
    parsers: Optional[List[str]] = Field(
        sa_column=Column(ARRAY(String)),
        default=None
    )
    scanned_at: datetime

class DbCodeObjectField(SQLModel, table=True):
    __tablename__ = "discovery_code_object_fields"
    code_object_id: int = Field(
        foreign_key="discovery_code_objects.id",
        primary_key=True
    )
    field_name: str = Field(primary_key=True)
    field_type: str
    file: Optional[str] = None
    line: Optional[int] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = Field(
        sa_column=Column(ARRAY(String)),
        default=None
    )
    code_object: Optional["DbCodeObject"] = Relationship(
        back_populates="fields",
        sa_relationship_kwargs={"cascade": "all, delete"}
    )

class DbCodeObjectProp(SQLModel, table=True):
    __tablename__ = "discovery_code_object_props"
    code_object_id: int = Field(
        foreign_key="discovery_code_objects.id",
        primary_key=True
    )
    prop_name: str = Field(primary_key=True)
    prop_value: str
    file: Optional[str] = None
    line: Optional[int] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = Field(
        sa_column=Column(ARRAY(String)),
        default=None
    )
    code_object: Optional["DbCodeObject"] = Relationship(
        back_populates="properties",
        sa_relationship_kwargs={"cascade": "all, delete"}
    )

class DbCodeObject(SQLModel, table=True):
    __tablename__ = "discovery_code_objects"
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="gitlab_projects.id")
    branch_id: int = Field(default=None, foreign_key="gitlab_branches.id")
    hash: str
    object_name: str
    object_type: str
    parser: str
    properties: List[DbCodeObjectProp] = Relationship(
        back_populates="code_object",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}                                     
    )
    fields: List[DbCodeObjectField] = Relationship(
        back_populates="code_object",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}                                     
    )
    file: str
    line: int
    severity: Optional[str] = None
    tags: Optional[List[str]] = Field(
        sa_column=Column(ARRAY(String)),
        default=None
    )
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    alerted_at: Optional[datetime] = None
    ai_processed_at: Optional[datetime] = None

'''
class TableObject(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="project.id")
    branch_id: int = Field(default=None, foreign_key="branch.id")
    table_name: str
    table_comment: Optional[str]
    field: str
    field_comment: Optional[str]
    type: str
    file: str
    line: int
    score: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ProtoObject(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="project.id")
    branch_id: int = Field(default=None, foreign_key="branch.id")
    url: str
    package: str
    service: str
    method: str
    method_comment: Optional[str]
    message: str
    message_type: str
    field: str
    field_comment: Optional[str]
    type: str
    file: str
    line: int
    score: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ClientObject(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="project.id")
    branch_id: int = Field(default=None, foreign_key="branch.id")
    package: str
    method: str
    client_name: str
    client_url: str
    client_input: str
    client_output: str
    file: str
    line: int
    score: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class TfObject(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="project.id")
    branch_id: int = Field(default=None, foreign_key="branch.id")
    vm_name: str
    vm_domain: Optional[str]
    vm_template: Optional[str]
    vm_pool: Optional[str]
    vm_desc: Optional[str]
    vm_server_cluster_name: Optional[str]
    vm_server_role: Optional[str]
    vm_server_owning_team: Optional[str]
    vm_server_maintaining_team: Optional[str]
    vm_prometheus_env: Optional[str]
    vlan_id: Optional[str]
    dc: Optional[str]
    file: str
    line: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None



class ProjectInfo(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="project.id")
    service_name: Optional[str]
    vault_stg: Optional[str]
    vault_prod: Optional[str]
    tags: Optional[Set[str]] = Field(default=None, sa_column=Column(postgresql.ARRAY(String())))
    risk_score: Optional[int]
    created_at: datetime
    updated_at: datetime



####################################################
#   Scoring rules                               ####
####################################################


class GrpcService(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="project.id")
    object_type: str
    object_name: str
    object_fields: Optional[Set[str]] = Field(default=None, sa_column=Column(postgresql.ARRAY(String())))
    file_path: Optional[str]
    file_line: Optional[int]
    risk_score: Optional[int]
    created_at: datetime
    updated_at: datetime

class DatabaseTable(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="project.id")
    object_type: str
    object_name: str
    object_fields: Optional[Set[str]] = Field(default=None, sa_column=Column(postgresql.ARRAY(String())))
    file_path: Optional[str]
    file_line: Optional[int]
    risk_score: Optional[int]
    created_at: datetime
    updated_at: datetime

class GrpcClientCall(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(default=None, foreign_key="project.id")
    object_type: str
    object_name: str
    object_fields: Optional[Set[str]] = Field(default=None, sa_column=Column(postgresql.ARRAY(String())))
    file_path: Optional[str]
    file_line: Optional[int]
    risk_score: Optional[int]
    created_at: datetime
    updated_at: datetime

'''


####################################################
#   Scoring rules                               ####
####################################################

class DbScoreRuleStatus(str, Enum):
    mark = "mark"
    skip = "skip"
    alert = "alert"

class DbScoreRuleSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class DbScoreRule(SQLModel, table=True):
    __tablename__ = "discovery_score_rules"
    id: Optional[int] = Field(default=None, primary_key=True)
    project: Optional[str]
    object: Optional[str]
    object_type: Optional[str]
    field: Optional[str]
    field_type: Optional[str]
    severity: Optional[DbScoreRuleSeverity]
    tag: Optional[str]
    status: DbScoreRuleStatus = DbScoreRuleStatus.mark