from typing import List, Dict, Any, Optional
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, ARRAY, JSON, String, UniqueConstraint

from datetime import datetime
from enum import Enum

class Project(SQLModel, table=True):
    __tablename__ = "gitlab_projects"
    id: Optional[int] = Field(default=None, primary_key=True, sa_column_kwargs={"autoincrement": True})
    project_name: str
    full_path: str
    description: Optional[str] = None
    default_branch: Optional[str] = None
    visibility: str
    branches: List["Branch"] = Relationship(back_populates="project")
    mrs: List["MR"] = Relationship(back_populates="project")
    severity: Optional[str] = None
    tags: Optional[List[str]] = Field(
        sa_column=Column(ARRAY(String)),
        default=None
    )
    created_at: datetime
    updated_at: datetime
    processed_at: Optional[datetime] = None

class Branch(SQLModel, table=True):
    __tablename__ = "gitlab_branches"
    id: Optional[int] = Field(default=None, primary_key=True, sa_column_kwargs={"autoincrement": True})
    branch_name: str
    is_main: bool = Field(default=False) 
    commit: str
    processed_at: Optional[datetime] = None
    project_id: int = Field(default=None, foreign_key="gitlab_projects.id")
    project: Project = Relationship(back_populates="branches")
    project_path: str
    created_at: datetime
    updated_at: datetime

class MR(SQLModel, table=True):
    __tablename__ = "gitlab_mrs"
    id: Optional[int] = Field(default=None, primary_key=True, sa_column_kwargs={"autoincrement": True})
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
    id: Optional[int] = Field(default=None, primary_key=True, sa_column_kwargs={"autoincrement": True})
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

class DbObjectField(SQLModel, table=True):
    __tablename__ = "discovery_object_fields"
    id: Optional[int] = Field(default=None, primary_key=True, sa_column_kwargs={"autoincrement": True})
    object_id: int = Field(default=None, foreign_key="discovery_objects.id")
    name: str
    type: str
    file: Optional[str] = None
    line: Optional[int] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = Field(
        sa_column=Column(ARRAY(String)),
        default=None
    )
    llm_scores: List["DbLLMScore"] = Relationship(
        back_populates="object_field",
        sa_relationship_kwargs={"cascade": "all, delete"}                                     
    )
    object: Optional["DbObject"] = Relationship(
        back_populates="fields",
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    __table_args__ = (UniqueConstraint('object_id', 'name', name='uq_object_field'),)

class DbLLMScoreStatus(str, Enum):
    new = "new"
    fp = "fp"
    tp = "tp"

class DbLLMScore(SQLModel, table=True):
    __tablename__ = "discovery_llm_scores"
    id: Optional[int] = Field(default=None, primary_key=True, sa_column_kwargs={"autoincrement": True})
    field_id: int = Field(foreign_key="discovery_object_fields.id")
    model: str
    prompt_ver: str
    severity: Optional[str] = None
    tag: Optional[str] = None
    status: DbLLMScoreStatus = DbLLMScoreStatus.new
    object_field: Optional["DbObjectField"] = Relationship(
        back_populates="llm_scores",
        sa_relationship_kwargs={"cascade": "all, delete"}
    )
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    __table_args__ = (UniqueConstraint('field_id', 'model', 'prompt_ver'),)

class DbObject(SQLModel, table=True):
    __tablename__ = "discovery_objects"
    id: Optional[int] = Field(default=None, primary_key=True, sa_column_kwargs={"autoincrement": True})
    project_id: int = Field(default=None, foreign_key="gitlab_projects.id")
    branch_id: int = Field(default=None, foreign_key="gitlab_branches.id")
    hash: str
    name: str
    type: str
    parser: str
    props: Optional[Dict[str, Any]] = Field(
        default=None,
        sa_column=Column(JSON)
    )
    fields: List[DbObjectField] = Relationship(
        back_populates="object",
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
    __table_args__ = (UniqueConstraint('project_id', 'branch_id', 'name', 'type'),)


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
    id: Optional[int] = Field(default=None, primary_key=True, sa_column_kwargs={"autoincrement": True})
    project: Optional[str]
    object: Optional[str]
    object_type: Optional[str]
    field: Optional[str]
    field_type: Optional[str]
    severity: Optional[DbScoreRuleSeverity]
    tag: Optional[str]
    status: DbScoreRuleStatus = DbScoreRuleStatus.mark