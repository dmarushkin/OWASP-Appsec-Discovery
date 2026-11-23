"""DB models shared by the scanner and the API (P2-5).

The schema is owned by the Alembic migrations in ``discovery_common/migrations`` (no
``create_all`` at startup any more); these classes mirror the schema at the migration
head (``tests/test_common_migrations.test_fresh_database_migrates_and_matches_models``
checks that).

Storage design (refactoring report, stage 4, storage design AGREED REVISIONS):

* ``objects``        content-addressed object versions, shared by every branch having them.
* ``object_fields``  one row per field of an object version (relational, indexed by name).
* ``branch_objects`` main branch rows = full snapshot (``change`` NULL); MR source branch
                     rows = only the delta vs the target branch (added/modified/removed,
                     removed rows have no ``content_hash``).
* ``rules`` / ``rule_hits``  rules (keyword / llm) and one hit per (rule, subject); human
                     decisions live on the hit (``reviewer`` set) and are never overwritten by
                     scans.
* ``jobs``           the scanner's job queue (P2-4, see ``discovery_common.jobs``).

No ORM relationships: deletes are done by the database (``ON DELETE CASCADE``), which
also removes the cascade-on-many-to-one bug of the old models (P0-3).
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    ARRAY, BigInteger, Boolean, CheckConstraint, Column, DateTime, Float, ForeignKey, Index, Integer,
    PrimaryKeyConstraint, String, Text, UniqueConstraint, text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlmodel import Field, SQLModel


def _fk(target: str, ondelete: Optional[str] = None, nullable: bool = False, **kwargs) -> Column:
    return Column(Integer, ForeignKey(target, ondelete=ondelete), nullable=nullable, **kwargs)


####################################################
#   GitLab inventory                            ####
####################################################

class Project(SQLModel, table=True):
    __tablename__ = "gitlab_projects"
    __table_args__ = (Index("gitlab_projects_full_path_key", "full_path", unique=True),)
    id: Optional[int] = Field(default=None, primary_key=True)
    # GitLab project id: the upsert key (project_name was not unique, P0-3). Nullable only
    # for rows created before migration 0002; the GitLab sync fills it in by full_path.
    gitlab_id: Optional[int] = Field(default=None, sa_column=Column(Integer, unique=True))
    project_name: str
    full_path: str
    description: Optional[str] = None
    default_branch: Optional[str] = None
    visibility: str
    severity: Optional[str] = None
    tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(String)))
    created_at: datetime
    updated_at: datetime
    processed_at: Optional[datetime] = None
    # rules (default): keyword + LLM rules categorise objects; inventory: objects / fields are
    # stored only, people label them by hand (MANUAL_RULE hits via REST / MCP)
    scan_mode: str = Field(default="rules", sa_column=Column(
        Text, CheckConstraint("scan_mode IN ('rules','inventory')", name="gitlab_projects_scan_mode_check"),
        nullable=False, server_default=text("'rules'")))
    # gitlab: synced and parsed by the scanner; external: objects pushed via POST /ingest
    source: str = Field(default="gitlab", sa_column=Column(
        Text, CheckConstraint("source IN ('gitlab','external')", name="gitlab_projects_source_check"),
        nullable=False, server_default=text("'gitlab'")))
    created_by: Optional[str] = Field(default=None, sa_column=Column(Text))     # external projects


class Branch(SQLModel, table=True):
    """Tracked branches: the main branch of every project and the source (and target)
    branches of open MRs. Deleting a row removes its ``branch_objects`` (CASCADE)."""
    __tablename__ = "gitlab_branches"
    __table_args__ = (
        UniqueConstraint("project_id", "branch_name", name="gitlab_branches_project_id_branch_name_key"),
        Index("branches_one_main", "project_id", unique=True, postgresql_where=text("is_main")),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    branch_name: str
    is_main: bool = Field(default=False)
    commit: str                                    # head commit in GitLab
    scanned_commit: Optional[str] = Field(default=None, sa_column=Column(Text))   # what branch_objects reflect
    # Diff-based scan skip (migration 0029, scanner services.diff_service): the scan configuration
    # (core version, parsers, keyword rules) the snapshot was made with, when it was last fully parsed
    # (a skip moves scanned_commit without touching these), and for an MR source branch the target
    # commit its stored delta was computed against.
    scan_fingerprint: Optional[str] = Field(default=None, sa_column=Column(Text))
    full_scanned_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    delta_target_commit: Optional[str] = Field(default=None, sa_column=Column(Text))
    processed_at: Optional[datetime] = None
    project_id: int = Field(sa_column=_fk("gitlab_projects.id", ondelete="CASCADE"))
    project_path: str
    created_at: datetime
    updated_at: datetime


class MR(SQLModel, table=True):
    __tablename__ = "gitlab_mrs"
    __table_args__ = (
        UniqueConstraint("project_id", "mr_id", name="gitlab_mrs_project_id_mr_id_key"),
        Index("mrs_open", "project_id", postgresql_where=text("state = 'opened'")),
        Index("mrs_source", "source_branch_id"),
        Index("mrs_target_open", "target_branch_id", postgresql_where=text("state = 'opened'")),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(sa_column=_fk("gitlab_projects.id", ondelete="CASCADE"))
    project_path: str
    source_branch_id: Optional[int] = Field(default=None, sa_column=_fk("gitlab_branches.id", ondelete="SET NULL", nullable=True))
    source_branch: str
    source_branch_commit: str
    target_branch_id: Optional[int] = Field(default=None, sa_column=_fk("gitlab_branches.id", ondelete="SET NULL", nullable=True))
    target_branch: str
    target_branch_commit: str
    mr_id: int                                     # GitLab MR iid
    title: str
    description: Optional[str] = None
    state: str
    diff: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    processed_at: Optional[datetime] = None
    closed_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))


class Scan(SQLModel, table=True):
    __tablename__ = "discovery_scans"
    __table_args__ = (
        UniqueConstraint("branch_id", "branch_commit", "scanner", "rules_version", "parsers", name="uq_scan"),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(sa_column=_fk("gitlab_projects.id", ondelete="CASCADE", nullable=True))
    branch_id: int = Field(sa_column=_fk("gitlab_branches.id", ondelete="CASCADE", nullable=True))
    project_path: str
    branch_name: str
    branch_commit: str
    scanner: str
    rules_version: str
    parsers: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(String)))
    scanned_at: datetime


####################################################
#   Objects                                     ####
####################################################

class ObjectVersion(SQLModel, table=True):
    """Immutable, content-addressed object version (``content_hash``), shared by branches."""
    __tablename__ = "objects"
    __table_args__ = (
        Index("objects_key", "object_key"),
        Index("objects_proj_name", "project_id", "name"),
        Index("objects_name_key", "name", "object_key"),        # name-ordered pages of /objects (migration 0030)
    )
    content_hash: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), primary_key=True))
    object_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    project_id: int = Field(sa_column=_fk("gitlab_projects.id", ondelete="CASCADE"))
    parser: Optional[str] = Field(default=None, sa_column=Column(Text))
    type: Optional[str] = Field(default=None, sa_column=Column(Text))
    name: Optional[str] = Field(default=None, sa_column=Column(Text))
    file: Optional[str] = Field(default=None, sa_column=Column(Text))
    props: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSONB))
    comment: Optional[str] = Field(default=None, sa_column=Column(Text))          # code comment / description
    # what an LLM object rule sees of the version (migration 0030; ``keys.names_hash``: the object name + its
    # sorted field names = ``llm_names_hash(name, ARRAY(field names))``), written with the row and when the name
    # changes, so the candidate / coverage queries compare stored hashes instead of hashing every row per run
    names_hash: Optional[str] = Field(default=None, sa_column=Column(Text))


class ObjectField(SQLModel, table=True):
    __tablename__ = "object_fields"
    __table_args__ = (
        PrimaryKeyConstraint("content_hash", "field_name", name="object_fields_pkey"),
        Index("fields_proj_name", "project_id", "field_name"),
        Index("fields_key", "field_key"),
        Index("fields_name_trgm", "field_name", postgresql_using="gin", postgresql_ops={"field_name": "gin_trgm_ops"}),
    )
    content_hash: uuid.UUID = Field(sa_column=Column(
        UUID(as_uuid=True), ForeignKey("objects.content_hash", ondelete="CASCADE"), nullable=False))
    field_name: str = Field(sa_column=Column(Text, nullable=False))
    field_type: Optional[str] = Field(default=None, sa_column=Column(Text))
    field_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))   # = rule_hits.subject_key
    project_id: int = Field(sa_column=Column(Integer, nullable=False))
    comment: Optional[str] = Field(default=None, sa_column=Column(Text))          # code comment / description
    # example values; none_as_null: a field without samples is SQL NULL, not the JSON value null
    samples: Optional[List[str]] = Field(default=None, sa_column=Column(JSONB(none_as_null=True)))
    # what an LLM field rule sees of the field (migration 0030; ``keys.field_subject_hash`` = ``llm_field_hash(name,
    # type, comment, samples)``), stored once with the immutable row (= ``rule_hits.subject_hash`` of a field hit)
    llm_hash: Optional[str] = Field(default=None, sa_column=Column(Text))


class BranchObject(SQLModel, table=True):
    """Created WITH (fillfactor = 80) by the migration (frequent in-place updates)."""
    __tablename__ = "branch_objects"
    __table_args__ = (
        PrimaryKeyConstraint("branch_id", "object_key", name="branch_objects_pkey"),
        CheckConstraint("change IN ('added','modified','removed')", name="branch_objects_change_check"),
        CheckConstraint("is_main = (change IS NULL)", name="branch_objects_check"),
        Index("bo_content", "content_hash", "is_main"),
        Index("bo_mr_rows", "content_hash", postgresql_include=["branch_id", "change"], postgresql_where=text("NOT is_main")),
    )
    branch_id: int = Field(sa_column=_fk("gitlab_branches.id", ondelete="CASCADE"))
    object_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    # NO ACTION on purpose: a GC race fails the scan transaction, which is retried.
    content_hash: Optional[uuid.UUID] = Field(default=None, sa_column=Column(UUID(as_uuid=True), ForeignKey("objects.content_hash")))
    is_main: bool = Field(sa_column=Column(Boolean, nullable=False))
    change: Optional[str] = Field(default=None, sa_column=Column(Text))
    line: Optional[int] = None
    field_lines: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSONB))


####################################################
#   Rules and hits                              ####
####################################################

class RuleMode(str, Enum):
    auto = "auto"        # hits are a match right away
    review = "review"    # hits wait in the review queue (pending_review)


class HitStatus(str, Enum):
    """The verdict words (migration 0023; were ``confirmed`` / ``rejected``): who decided is ``decided_tier``."""
    pending_review = "pending_review"
    need_more_info = "need_more_info"
    match = "match"
    no_match = "no_match"


# statuses before migration 0023, accepted as aliases by the REST / MCP status filters for one release
LEGACY_HIT_STATUSES = {"confirmed": HitStatus.match.value, "rejected": HitStatus.no_match.value}


class Rule(SQLModel, table=True):
    """``scope`` (jsonb), keyword rules: ``project_re``, ``parser``, ``object_re``,
    ``object_type_re``, ``field_re``, ``field_type_re`` and ``action`` (``score`` |
    ``exclude``; exclude rules feed core exclusions and never produce hits); LLM rules:
    ``project_re``, ``object_re``, ``object_type_re``, ``field_re``, ``field_type_re``.
    ``scope.source`` marks built-in rules (``core``: the core keyword scoring, ``env``: the
    LLM rule once synced from LLM_PROMPT, removed by migration 0028). ``version`` is bumped on every edit of
    scope/prompt/target; it is data on the hits, not part of their key. Deleting a rule is a
    soft delete (``deleted_at`` set, ``enabled`` false) so hits never dangle."""
    __tablename__ = "rules"
    __table_args__ = (
        CheckConstraint("kind IN ('keyword','llm','manual')", name="rules_kind_check"),
        CheckConstraint("target IN ('object','field')", name="rules_target_check"),
        CheckConstraint("mode IN ('auto','review')", name="rules_mode_check"),
        Index("rules_name_live", "name", unique=True, postgresql_where=text("deleted_at IS NULL")),
        Index("rules_tags", "tags", postgresql_using="gin", postgresql_where=text("tags IS NOT NULL")),
    )
    id: Optional[int] = Field(default=None, primary_key=True)
    kind: Optional[str] = Field(default=None, sa_column=Column(Text))
    name: Optional[str] = Field(default=None, sa_column=Column(Text))
    category: Optional[str] = Field(default=None, sa_column=Column(Text))
    severity: Optional[str] = Field(default=None, sa_column=Column(Text))
    target: Optional[str] = Field(default=None, sa_column=Column(Text))
    mode: Optional[str] = Field(default=None, sa_column=Column(Text))
    scope: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSONB))
    prompt: Optional[str] = Field(default=None, sa_column=Column(Text))
    version: int = Field(default=1, sa_column=Column(Integer, nullable=False, server_default=text("1")))
    enabled: Optional[bool] = Field(default=True, sa_column=Column(Boolean, server_default=text("true")))
    updated_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), server_default=text("now()")))
    deleted_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    updated_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    # tags set on the object of every match hit (read at query time)
    tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    # LLM rules (migration 0024): the projection of the active ``rule_versions`` row - the core prompts family
    # version its verdicts are pinned to (``classifier3`` / ``rule3``; NULL: the code's) and the service model
    # they belong to (NULL: any). ``prompt`` / ``scope`` / ``target`` / ``version`` are the active version's too.
    core_prompt_version: Optional[str] = Field(default=None, sa_column=Column(Text))
    llm_model: Optional[str] = Field(default=None, sa_column=Column(Text))


class RuleHit(SQLModel, table=True):
    """One row per (rule, subject); branch-agnostic, so a decision made on an MR carries
    over to main. ``reviewer`` is set for human decisions; scans never overwrite those (LLM
    object rules whose object got other field names: carried over or back to review, see the
    scanner's ``db_service._reasked_human_hits``)."""
    __tablename__ = "rule_hits"
    # Created / altered WITH (fillfactor = 85, autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor
    # = 0.01) by migration 0030: ``last_seen_at`` is bumped on every main scan, and the retention index makes those
    # updates non-HOT.
    __table_args__ = (
        PrimaryKeyConstraint("rule_id", "subject_key", name="rule_hits_pkey"),
        CheckConstraint("status IN ('pending_review','need_more_info','match','no_match')", name="rule_hits_status_check"),
        Index("hits_subject", "subject_key"),
        Index("hits_queue", "project_id", "status", postgresql_where=text("status IN ('pending_review','need_more_info')")),
        CheckConstraint("decided_tier IN ('service', 'harness', 'human')", name="rule_hits_decided_tier_check"),
        Index("hits_model_questions", "project_id",
              postgresql_where=text("asked_by_model AND status = 'need_more_info'")),
        # migration 0030 (scale): the hits of one object (siblings, labels / tags of /objects, cascades, field marks,
        # presence refresh) and of one project / rule (scan cleanups, relabel, stale counts)
        Index("hits_object", "object_key"),
        Index("hits_project_rule", "project_id", "rule_id"),
        # presence (``discovery_common.presence``): live hits in list order, the open review queue per project, and
        # the retention scan over the hits that are in no branch any more
        Index("hits_live_seen", text("first_seen_at DESC NULLS LAST"), "rule_id", "subject_key",
              postgresql_where=text("in_main OR in_open_mr")),
        Index("hits_live_queue", "project_id", text("first_seen_at DESC NULLS LAST"),
              postgresql_where=text("(in_main OR in_open_mr) AND status IN ('pending_review', 'need_more_info')")),
        Index("hits_seen", text("(COALESCE(last_seen_at, first_seen_at, '-infinity'))"), "status",
              postgresql_where=text("NOT in_main AND NOT in_open_mr")),
    )
    rule_id: int = Field(sa_column=Column(Integer, ForeignKey("rules.id"), nullable=False))
    subject_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    project_id: int = Field(sa_column=Column(Integer, nullable=False))
    object_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    field_name: Optional[str] = Field(default=None, sa_column=Column(Text))
    rule_version: int = Field(sa_column=Column(Integer, nullable=False))
    model: Optional[str] = Field(default=None, sa_column=Column(Text))
    # LLM hits: the core prompts version (LLM_PROMPTS_VERSION) the verdict was made with
    prompt_version: Optional[str] = Field(default=None, sa_column=Column(Text))
    category: Optional[str] = Field(default=None, sa_column=Column(Text))
    severity: Optional[str] = Field(default=None, sa_column=Column(Text))
    status: str = Field(sa_column=Column(Text, nullable=False))
    reviewer: Optional[str] = Field(default=None, sa_column=Column(Text))
    reviewed_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    note: Optional[str] = Field(default=None, sa_column=Column(Text))
    reason: Optional[str] = Field(default=None, sa_column=Column(Text))     # LLM explanation
    # object hits of combination / LLM object rules: the fields that made the object match
    fields: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    # extra tags of this hit set by hand (manual labels); the rule's tags come from rules.tags
    tags: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    # where a human decision was made: rest (UI / REST) | mcp (MCP tools, e.g. an AI agent)
    decided_via: Optional[str] = Field(default=None, sa_column=Column(
        Text, CheckConstraint("decided_via IN ('rest','mcp')", name="rule_hits_decided_via_check")))
    # LLM hits: what the model saw (``discovery_common.keys``, migration 0018): the object name +
    # sorted field names, and the content (object rules: the content hash; field rules: name, type,
    # comment, samples). A change asks the rule again (see the scanner's LLM_CANDIDATE_COND).
    names_hash: Optional[str] = Field(default=None, sa_column=Column(Text))
    subject_hash: Optional[str] = Field(default=None, sa_column=Column(Text))
    # the status the scanner (model) had set, recorded when a human first decides the hit (migration 0019): the
    # machine verdict a human decision disagrees with (prompt trials, ``llm_mislabeled``); NULL: decided earlier
    machine_status: Optional[str] = Field(default=None, sa_column=Column(Text))
    # who made the current decision (migrations 0020, 0021): service (the service model / a scan), harness (the
    # harness model verified it: final unless the content changes), human (a reviewer). The service model never
    # overwrites harness or human decisions, the harness model never a human one (see the README, LLM rules).
    decided_tier: str = Field(default="service", sa_column=Column(Text, nullable=False,
                                                                 server_default=text("'service'")))
    verifier_model: Optional[str] = Field(default=None, sa_column=Column(Text))
    verified_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    # the harness model could not decide and asked a human (status need_more_info, the question in ``note``)
    asked_by_model: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, server_default=text("false")))
    # the service model's verdict a verify item was made for (escalation / QA sample once per verdict)
    verify_key: Optional[str] = Field(default=None, sa_column=Column(Text))
    first_seen_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    last_seen_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    # presence of the subject (migration 0030, ``discovery_common.presence``): in some main snapshot / in the delta
    # of an open MR - maintained by the scanner on every snapshot, MR and branch change; the API filters on them
    in_main: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, server_default=text("false")))
    in_open_mr: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, server_default=text("false")))


# Names of the synthetic rules created by migration 0002.
# (migration 0028: were ``core:score_tags:field`` / ``core:score_tags:object``; disabled on new installs)
CORE_FIELD_RULE = "kw-fields"                 # core keyword scoring of field names
CORE_OBJECT_RULE = "kw-props"                 # core keyword scoring of the object's properties (object level)
LEGACY_CORE_RULES = {"core:score_tags:field": CORE_FIELD_RULE, "core:score_tags:object": CORE_OBJECT_RULE}
MANUAL_RULE = "manual:labels"                 # hits labelled by hand (REST / MCP), kind 'manual'
SCAN_MODES = ("rules", "inventory")
# the core's parser types (appsec_discovery.parsers.ParserFactory.get_parser_types(), checked by
# a scanner test): the API cannot import the core (pydantic v2 vs v1)
# Versions of the core's LLM prompts (``score_service.core_prompts_version()``, checked by a
# scanner test): stored on every LLM hit (``rule_hits.prompt_version``); a hit made with other
# prompts and not decided by a human is asked again (scanner candidates, API dry run).
LLM_PROMPTS_VERSION = "core3.3"
# Since migration 0024 a hit stores the version of its prompt FAMILY (``discovery_common.lifecycle``): the classifier
# (a field rule without category, ``classifier{PROMPT_VERSION}``) or the rule prompts (``rule{RULE_PROMPT_VERSION}``),
# so a new classifier prompt does not make the verdicts of the other rules stale (checked against the core by a
# scanner test).
CORE_PROMPT_FAMILIES = {"classifier": "classifier3", "rule": "rule3"}

PARSER_TYPES = ("client", "db", "golang", "graphql", "java", "javascript", "migrations", "protobuf", "python", "swagger",
                "terraform")

# Hit status transitions a reviewer may make (``reopen`` = back to pending_review).
REVIEW_TRANSITIONS = {
    HitStatus.pending_review.value: {HitStatus.need_more_info.value, HitStatus.match.value, HitStatus.no_match.value},
    HitStatus.need_more_info.value: {HitStatus.match.value, HitStatus.no_match.value, HitStatus.pending_review.value},
    HitStatus.match.value: {HitStatus.pending_review.value},
    HitStatus.no_match.value: {HitStatus.pending_review.value},
}


####################################################
#   Job queue (P2-4)                            ####
####################################################

JOB_KINDS = ("sync_projects", "sync_branches_mrs", "scan_branch", "scan_mr", "llm_score", "cleanup", "ingest",
             "llm_apply", "llm_prepare", "llm_coverage", "llm_trial", "llm_verify", "llm_rollout",
             # migration 0031 (scale): statistics snapshots, batched relabel / adopt of verdicts
             "stats_refresh", "llm_relabel")
# jobs.priority (migration 0026): claimed in ORDER BY priority DESC, run_after, id; the slices of a rule rollout run
# below the fresh work, prompt trials (a human waits) above it
JOB_PRIORITY_ROLLOUT = -10
JOB_PRIORITY_TRIAL = 5
JOB_STATUSES = ("pending", "running", "done", "failed")
ACTIVE_JOB_STATUSES = ("pending", "running")


def _in(values) -> str:
    return ", ".join(f"'{value}'" for value in values)


class Job(SQLModel, table=True):
    """One unit of scanner work (``discovery_common.jobs``). ``dedup_key`` is unique among
    the active (pending / running) jobs only, so the same work can be queued again once the
    previous job finished. ``locked_by`` / ``locked_at`` are the lease of the running worker
    (renewed by its heartbeat); an expired lease puts the job back to pending."""
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint(f"kind IN ({_in(JOB_KINDS)})", name="jobs_kind_check"),
        CheckConstraint(f"status IN ({_in(JOB_STATUSES)})", name="jobs_status_check"),
        Index("jobs_dedup_active", "dedup_key", unique=True,
              postgresql_where=text(f"status IN ({_in(ACTIVE_JOB_STATUSES)})")),
        Index("jobs_ready", text("priority DESC"), "run_after", "id", postgresql_where=text("status = 'pending'")),
        # a claim restricted to some kinds (control / LLM workers) walks only those (migration 0030)
        Index("jobs_ready_kind", "kind", text("priority DESC"), "run_after", "id",
              postgresql_where=text("status = 'pending'")),
        Index("jobs_lease", "locked_at", postgresql_where=text("status = 'running'")),
        Index("jobs_kind_created", "kind", "created_at"),
        # the jobs of one main branch / MR (parse scan progress, migration 0015)
        Index("jobs_scan_branch_subject", text("(payload ->> 'branch_id')"), "id",
              postgresql_where=text("kind = 'scan_branch'")),
        Index("jobs_scan_mr_subject", text("(payload ->> 'mr_id')"), "id", postgresql_where=text("kind = 'scan_mr'")),
        # the LLM runs of one branch (LLM coverage progress, migration 0017)
        Index("jobs_llm_branch_subject", text("(payload ->> 'branch_id')"), "id",
              postgresql_where=text("kind IN ('llm_score', 'llm_prepare')")),
    )
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    kind: str = Field(sa_column=Column(Text, nullable=False))
    payload: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")))
    dedup_key: Optional[str] = Field(default=None, sa_column=Column(Text))
    status: str = Field(default="pending", sa_column=Column(Text, nullable=False, server_default=text("'pending'")))
    attempts: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    max_attempts: int = Field(default=5, sa_column=Column(Integer, nullable=False, server_default=text("5")))
    run_after: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    locked_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    locked_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    # when the last attempt was claimed (migration 0031); unlike ``locked_at`` (the lease) it stays on the finished row,
    # so run / wait times can be computed (``GET /jobs/health`` typical_run_s / typical_wait_s)
    started_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    last_error: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    updated_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    finished_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    # llm_score / llm_prepare jobs: {executor, phase, total_objects, done_objects, failed_objects, rule_ids, ...}
    progress: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSONB))
    priority: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))


# LLM rule runs: who calls the model. service: the scanner with its LLM_API_URL; external: a model
# in a local harness (e.g. an agent connected to the MCP server) answers llm_work_items.
LLM_EXECUTORS = ("service", "external")
LLM_WORK_STATUSES = ("pending", "leased", "answered", "applied", "failed", "expired")
LLM_WORK_OPEN = ("pending", "leased", "answered")
# score: a call of an external LLM rule run; verify: a harness model checks one hit (migration 0020)
LLM_WORK_PURPOSES = ("score", "verify")


class LlmWorkItem(SQLModel, table=True):
    """One model call of an external LLM rule run (``discovery_common.llm_work``): the prompts
    are recorded by the scanner exactly as a service run would send them (``prompt_hash`` =
    sha256 of system prompt, user prompt and schema); the answer is applied by the scanner
    with the core parser, so the hits are the same as a service run's (``model`` =
    ``answer_model``)."""
    __tablename__ = "llm_work_items"
    __table_args__ = (
        CheckConstraint(f"status IN ({_in(LLM_WORK_STATUSES)})", name="llm_work_items_status_check"),
        Index("llm_work_claim", "status", "job_id", "id"),
        Index("llm_work_job", "job_id"),
        CheckConstraint(f"purpose IN ({_in(LLM_WORK_PURPOSES)})", name="llm_work_items_purpose_check"),
        Index("llm_work_open", "rule_id", "rule_version", "object_key", "call_index", unique=True,
              postgresql_where=text(f"status IN ({_in(LLM_WORK_OPEN)}) AND purpose = 'score'")),
        Index("llm_verify_open", "rule_id", "subject_key", unique=True,
              postgresql_where=text(f"status IN ({_in(LLM_WORK_OPEN)}) AND purpose = 'verify'")),
        Index("llm_work_purpose", "purpose", "status"),
        # the verify items of a rule by creation time: the day's escalation / QA counts (verify_service, 0031)
        Index("llm_verify_rule_created", "rule_id", "created_at", postgresql_where=text("purpose = 'verify'")),
    )
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    job_id: int = Field(sa_column=Column(BigInteger, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False))
    rule_id: int = Field(sa_column=Column(Integer, ForeignKey("rules.id"), nullable=False))
    rule_version: int = Field(sa_column=Column(Integer, nullable=False))
    project_id: int = Field(sa_column=Column(Integer, nullable=False))
    branch_id: int = Field(sa_column=Column(Integer, nullable=False))
    mr_id: Optional[int] = Field(default=None, sa_column=Column(Integer))
    object_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    content_hash: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    call_index: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    prompt_hash: str = Field(sa_column=Column(Text, nullable=False))
    system_prompt: Optional[str] = Field(default=None, sa_column=Column(Text))
    user_prompt: str = Field(sa_column=Column(Text, nullable=False))
    json_schema: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSONB))
    status: str = Field(default="pending", sa_column=Column(Text, nullable=False, server_default=text("'pending'")))
    lease_owner: Optional[str] = Field(default=None, sa_column=Column(Text))
    lease_token: Optional[str] = Field(default=None, sa_column=Column(Text))
    lease_until: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    answer: Optional[str] = Field(default=None, sa_column=Column(Text))
    answer_model: Optional[str] = Field(default=None, sa_column=Column(Text))
    answered_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    answered_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    error: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    updated_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    # migration 0020: verify items (``discovery_common.llm_verify``) name one hit and carry the service model's
    # verdict
    purpose: str = Field(default="score", sa_column=Column(Text, nullable=False, server_default=text("'score'")))
    subject_key: Optional[uuid.UUID] = Field(default=None, sa_column=Column(UUID(as_uuid=True)))
    field_name: Optional[str] = Field(default=None, sa_column=Column(Text))
    verify: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSONB))


VERIFY_SAMPLES = ("escalation", "qa", "reverify", "manual")
VERIFY_OUTCOMES = ("final", "asked_human", "stale")


class LlmVerification(SQLModel, table=True):
    """One harness-model decision about a service model verdict (migrations 0020, 0021), kept after its work item
    is gone: the QA metrics (agreement service vs harness per rule) and ``llm_mislabeled(source="verification")``
    read it."""
    __tablename__ = "llm_verifications"
    __table_args__ = (
        CheckConstraint(f"sample IN ({_in(VERIFY_SAMPLES)})", name="llm_verifications_sample_check"),
        CheckConstraint(f"outcome IN ({_in(VERIFY_OUTCOMES)})", name="llm_verifications_outcome_check"),
        Index("llm_verifications_rule", "rule_id", "created_at"),
        Index("llm_verifications_created", "created_at"),
    )
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    rule_id: int = Field(sa_column=Column(Integer, ForeignKey("rules.id"), nullable=False))
    rule_version: int = Field(sa_column=Column(Integer, nullable=False))
    subject_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    object_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    field_name: Optional[str] = Field(default=None, sa_column=Column(Text))
    project_id: int = Field(sa_column=Column(Integer, nullable=False))
    sample: str = Field(sa_column=Column(Text, nullable=False))
    service_status: str = Field(sa_column=Column(Text, nullable=False))
    service_verdict: str = Field(sa_column=Column(Text, nullable=False))
    service_model: Optional[str] = Field(default=None, sa_column=Column(Text))
    verdict: Optional[str] = Field(default=None, sa_column=Column(Text))
    confidence: Optional[str] = Field(default=None, sa_column=Column(Text))
    needs_human: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, server_default=text("false")))
    outcome: str = Field(sa_column=Column(Text, nullable=False))
    verifier_model: Optional[str] = Field(default=None, sa_column=Column(Text))
    verified_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    question: Optional[str] = Field(default=None, sa_column=Column(Text))
    investigation: Optional[str] = Field(default=None, sa_column=Column(Text))
    work_item_id: Optional[int] = Field(default=None, sa_column=Column(BigInteger))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    # the core's VERIFY_PROMPT_VERSION of the verify item (migration 0024; NULL: made before)
    verify_prompt_version: Optional[str] = Field(default=None, sa_column=Column(Text))


class LlmCoverage(SQLModel, table=True):
    """Coverage of one LLM rule on one branch (main snapshot or MR delta), written by the
    scanner (``services.llm_coverage_service``) after each run of the rule on the branch,
    after each snapshot save and by the ``llm_coverage`` job for stale rows; read by
    ``GET /llm_progress``. ``candidates_total``: subjects of the snapshot in the rule's scope
    the rule asks about when nothing is answered (fields - for the classifier rule only the
    fields it sends - or objects); ``answered``: those with a verdict of ``rule_version`` and
    ``prompt_version`` (LLM_PROMPTS_VERSION) or a human decision; of the others,
    ``pending_external`` are held by an external run and ``failed`` got no usable answer.
    Fresh while ``commit`` = the branch's ``scanned_commit`` and both versions are current."""
    __tablename__ = "llm_coverage"
    __table_args__ = (PrimaryKeyConstraint("branch_id", "rule_id", name="llm_coverage_pkey"),)
    branch_id: int = Field(sa_column=_fk("gitlab_branches.id", ondelete="CASCADE"))
    rule_id: int = Field(sa_column=_fk("rules.id", ondelete="CASCADE"))
    rule_version: int = Field(sa_column=Column(Integer, nullable=False))
    prompt_version: str = Field(sa_column=Column(Text, nullable=False))
    commit: Optional[str] = Field(default=None, sa_column=Column(Text))
    candidates_total: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    answered: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    pending_external: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    failed: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    computed_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    # migration 0026: of the remaining subjects, those with a verdict of an older version of the rule (another core
    # prompts version / service model): kept and scoring until a rule rollout asks them again (stale-while-revalidate)
    answered_stale: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))


class IngestBatch(SQLModel, table=True):
    """One full state of one external parser for one external project (``POST /ingest``)."""
    __tablename__ = "ingest_batches"
    __table_args__ = (
        CheckConstraint("status IN ('open','committed','processed','failed','superseded')",
                        name="ingest_batches_status_check"),
        Index("ingest_batches_latest", "project_id", "parser", text("id DESC")),
        Index("ingest_batches_idempotency", "project_id", "parser", "idempotency_key", unique=True,
              postgresql_where=text("idempotency_key IS NOT NULL")),
    )
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    project_id: int = Field(sa_column=_fk("gitlab_projects.id", ondelete="CASCADE"))
    parser: str = Field(sa_column=Column(Text, nullable=False))
    snapshot: str = Field(sa_column=Column(Text, nullable=False))
    status: str = Field(default="open", sa_column=Column(Text, nullable=False, server_default=text("'open'")))
    llm: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, server_default=text("false")))
    objects: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    fields: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    content_hash: Optional[str] = Field(default=None, sa_column=Column(Text))
    idempotency_key: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=False,
                                                                          server_default=text("now()")))
    committed_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    processed_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    stats: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSONB))
    error: Optional[str] = Field(default=None, sa_column=Column(Text))


class IngestChunk(SQLModel, table=True):
    """Objects of a batch (one chunk for a single POST /ingest, several for an upload session)."""
    __tablename__ = "ingest_chunks"
    __table_args__ = (PrimaryKeyConstraint("batch_id", "seq", name="ingest_chunks_pkey"),)
    batch_id: int = Field(sa_column=Column(BigInteger, ForeignKey("ingest_batches.id", ondelete="CASCADE"),
                                           nullable=False))
    seq: int = Field(sa_column=Column(Integer, nullable=False))
    payload: Dict[str, Any] = Field(sa_column=Column(JSONB, nullable=False))
    objects: int = Field(sa_column=Column(Integer, nullable=False))
    fields: int = Field(sa_column=Column(Integer, nullable=False))
    content_hash: str = Field(sa_column=Column(Text, nullable=False))


class ApiToken(SQLModel, table=True):
    """A service token (only its sha256 is stored): scope ``ingest`` on project path prefixes."""
    __tablename__ = "api_tokens"
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column(Text, nullable=False))
    token_hash: str = Field(sa_column=Column(Text, nullable=False, unique=True))
    scopes: List[str] = Field(sa_column=Column(ARRAY(Text), nullable=False))
    project_prefixes: List[str] = Field(sa_column=Column(ARRAY(Text), nullable=False))
    created_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=False,
                                                                          server_default=text("now()")))
    last_used_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    revoked_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))



####################################################
#   Prompt trials and proposals (0019)          ####
####################################################

LLM_VERDICTS = ("match", "no_match", "need_more_info")
TRIAL_STATUSES = ("queued", "running", "done", "failed")
TRIAL_ROLES = ("target", "control")
PROPOSAL_STATUSES = ("open", "accepted", "rejected", "superseded")


class PromptTrial(SQLModel, table=True):
    """A candidate system prompt of an LLM rule tried with the SERVICE model on a few subjects
    (``prompt_trial_items``) by an ``llm_trial`` job; never writes ``rule_hits`` or the rule."""
    __tablename__ = "prompt_trials"
    __table_args__ = (
        CheckConstraint(f"status IN ({_in(TRIAL_STATUSES)})", name="prompt_trials_status_check"),
        Index("prompt_trials_rule", "rule_id", "id"),
        Index("prompt_trials_created", "created_at"),
    )
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    rule_id: int = Field(sa_column=Column(Integer, ForeignKey("rules.id"), nullable=False))
    rule_version: int = Field(sa_column=Column(Integer, nullable=False))
    prompt_version: str = Field(sa_column=Column(Text, nullable=False))        # core prompts (LLM_PROMPTS_VERSION)
    base_prompt: Optional[str] = Field(default=None, sa_column=Column(Text))
    candidate_prompt: str = Field(sa_column=Column(Text, nullable=False))
    prompt_hash: str = Field(sa_column=Column(Text, nullable=False))           # sha256 of candidate_prompt
    rerun_current: bool = Field(default=True, sa_column=Column(Boolean, nullable=False, server_default=text("true")))
    status: str = Field(default="queued", sa_column=Column(Text, nullable=False, server_default=text("'queued'")))
    job_id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, ForeignKey("jobs.id", ondelete="SET NULL")))
    planned_calls: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    calls: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    failed_calls: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    model: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    note: Optional[str] = Field(default=None, sa_column=Column(Text))
    error: Optional[str] = Field(default=None, sa_column=Column(Text))
    totals: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSONB))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    started_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    finished_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))


class PromptTrialItem(SQLModel, table=True):
    """One subject of a trial: ``expected`` verdict, the stored verdict of the current prompt
    (``current_*``), the current prompt asked again in the same job (``rerun_*``) and the
    candidate's (``new_*``)."""
    __tablename__ = "prompt_trial_items"
    __table_args__ = (
        CheckConstraint(f"role IN ({_in(TRIAL_ROLES)})", name="prompt_trial_items_role_check"),
        CheckConstraint(f"expected IN ({_in(LLM_VERDICTS)})", name="prompt_trial_items_expected_check"),
        UniqueConstraint("trial_id", "subject_key", name="prompt_trial_items_subject_key"),
    )
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    trial_id: int = Field(sa_column=Column(BigInteger, ForeignKey("prompt_trials.id", ondelete="CASCADE"), nullable=False))
    subject_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    object_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    content_hash: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    project_id: int = Field(sa_column=Column(Integer, nullable=False))
    field_name: Optional[str] = Field(default=None, sa_column=Column(Text))
    role: str = Field(sa_column=Column(Text, nullable=False))
    expected: str = Field(sa_column=Column(Text, nullable=False))
    current_verdict: Optional[str] = Field(default=None, sa_column=Column(Text))
    current_reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    current_status: Optional[str] = Field(default=None, sa_column=Column(Text))
    rerun_verdict: Optional[str] = Field(default=None, sa_column=Column(Text))
    rerun_reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    rerun_fields: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    new_verdict: Optional[str] = Field(default=None, sa_column=Column(Text))
    new_reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    new_fields: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    error: Optional[str] = Field(default=None, sa_column=Column(Text))
    asked_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))


class PromptProposal(SQLModel, table=True):
    """A candidate prompt proposed to a human with a finished trial of the same text; accepted
    (by a human only) through the normal rule update (version bump)."""
    __tablename__ = "prompt_proposals"
    __table_args__ = (
        CheckConstraint(f"status IN ({_in(PROPOSAL_STATUSES)})", name="prompt_proposals_status_check"),
        Index("prompt_proposals_rule", "rule_id", "status"),
    )
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    rule_id: int = Field(sa_column=Column(Integer, ForeignKey("rules.id"), nullable=False))
    base_version: int = Field(sa_column=Column(Integer, nullable=False))
    prompt: str = Field(sa_column=Column(Text, nullable=False))
    prompt_hash: str = Field(sa_column=Column(Text, nullable=False))
    trial_id: int = Field(sa_column=Column(BigInteger, ForeignKey("prompt_trials.id"), nullable=False))
    rationale: str = Field(sa_column=Column(Text, nullable=False))
    status: str = Field(default="open", sa_column=Column(Text, nullable=False, server_default=text("'open'")))
    created_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    decided_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    decided_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    decision_note: Optional[str] = Field(default=None, sa_column=Column(Text))
    accepted_version: Optional[int] = Field(default=None, sa_column=Column(Integer))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    # the candidate rule version the accepted proposal became (migration 0024)
    version_id: Optional[int] = Field(default=None, sa_column=Column(BigInteger))


####################################################
#   LLM rule lifecycle (0024 - 0026)            ####
####################################################

RULE_VERSION_STATUSES = ("draft", "candidate", "active", "retired", "rolled_back")
ROLLOUT_STATUSES = ("planned", "canary", "awaiting_approval", "running", "paused", "done", "cancelled",
                    "rolled_back", "failed")
ROLLOUT_OPEN = ("planned", "canary", "awaiting_approval", "running", "paused")
ROLLOUT_MODES = ("immediate", "canary", "staged")


class RuleVersion(SQLModel, table=True):
    """One version of an LLM rule (``discovery_common.lifecycle``): draft -> candidate -> active -> retired |
    rolled_back. ``rules`` holds the projection of the active one (``rules.version`` = its ``version``)."""
    __tablename__ = "rule_versions"
    __table_args__ = (
        CheckConstraint(f"status IN ({_in(RULE_VERSION_STATUSES)})", name="rule_versions_status_check"),
        UniqueConstraint("rule_id", "version", name="rule_versions_rule_version_key"),
        Index("rule_versions_one_active", "rule_id", unique=True, postgresql_where=text("status = 'active'")),
    )
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    rule_id: int = Field(sa_column=Column(Integer, ForeignKey("rules.id"), nullable=False))
    version: int = Field(sa_column=Column(Integer, nullable=False))
    status: str = Field(sa_column=Column(Text, nullable=False))
    prompt: Optional[str] = Field(default=None, sa_column=Column(Text))
    target: str = Field(sa_column=Column(Text, nullable=False))
    matchers: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")))
    core_prompt_version: Optional[str] = Field(default=None, sa_column=Column(Text))
    model: Optional[str] = Field(default=None, sa_column=Column(Text))
    # manual | proposal:<id> | core_bump | model_change | env | rollback:<version> | backfill
    source: str = Field(default="manual", sa_column=Column(Text, nullable=False, server_default=text("'manual'")))
    parent_version: Optional[int] = Field(default=None, sa_column=Column(Integer))
    proposal_id: Optional[int] = Field(default=None, sa_column=Column(BigInteger))
    created_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    activated_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    retired_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    note: Optional[str] = Field(default=None, sa_column=Column(Text))


class HitVerdict(SQLModel, table=True):
    """Verdict history of the LLM hits (migration 0025): a row per change of a ``rule_hits`` row (status, version,
    prompts, model, reason, fields, tier, reviewer, hashes; written by triggers), kept HIT_HISTORY_DAYS - the last
    row of every rule version of a subject always."""
    __tablename__ = "hit_verdicts"
    __table_args__ = (
        # (rule, subject, version, id) since migration 0030: the retention's "a newer row of the same version
        # exists" probe and ``ADOPT_SQL`` read one version of a subject
        Index("hit_verdicts_subject", "rule_id", "subject_key", "rule_version", "id"),
        Index("hit_verdicts_created", "created_at"),
        Index("hit_verdicts_rollout", "rollout_id", postgresql_where=text("rollout_id IS NOT NULL")),
        Index("hit_verdicts_batch", "batch_id", postgresql_where=text("batch_id IS NOT NULL")),
    )
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    rule_id: int = Field(sa_column=Column(Integer, nullable=False))
    subject_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    object_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    field_name: Optional[str] = Field(default=None, sa_column=Column(Text))
    project_id: int = Field(sa_column=Column(Integer, nullable=False))
    rule_version: int = Field(sa_column=Column(Integer, nullable=False))
    prompt_version: Optional[str] = Field(default=None, sa_column=Column(Text))
    model: Optional[str] = Field(default=None, sa_column=Column(Text))
    status: str = Field(sa_column=Column(Text, nullable=False))
    category: Optional[str] = Field(default=None, sa_column=Column(Text))
    severity: Optional[str] = Field(default=None, sa_column=Column(Text))
    reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    fields: Optional[List[str]] = Field(default=None, sa_column=Column(ARRAY(Text)))
    names_hash: Optional[str] = Field(default=None, sa_column=Column(Text))
    subject_hash: Optional[str] = Field(default=None, sa_column=Column(Text))
    decided_tier: str = Field(sa_column=Column(Text, nullable=False))
    reviewer: Optional[str] = Field(default=None, sa_column=Column(Text))
    verifier_model: Optional[str] = Field(default=None, sa_column=Column(Text))
    # service | harness | human (the tier, by default) | adopt | relabel | backfill
    source: str = Field(sa_column=Column(Text, nullable=False))
    rollout_id: Optional[int] = Field(default=None, sa_column=Column(BigInteger))
    # the review batch (``POST /hits/decide``, migration 0032) that wrote / undid this verdict
    batch_id: Optional[int] = Field(default=None, sa_column=Column(BigInteger))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))


class LlmRollout(SQLModel, table=True):
    """Migration of the verdicts of an LLM rule to its active version (``to_version``) in budgeted slices by the
    ``llm_rollout`` controller job (scanner ``services.lifecycle_service``); at most one open rollout per rule."""
    __tablename__ = "llm_rollouts"
    __table_args__ = (
        CheckConstraint(f"status IN ({_in(ROLLOUT_STATUSES)})", name="llm_rollouts_status_check"),
        CheckConstraint(f"mode IN ({_in(ROLLOUT_MODES)})", name="llm_rollouts_mode_check"),
        Index("llm_rollouts_one_open", "rule_id", unique=True,
              postgresql_where=text(f"status IN ({_in(ROLLOUT_OPEN)})")),
        Index("llm_rollouts_rule", "rule_id", "id"),
    )
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    rule_id: int = Field(sa_column=Column(Integer, ForeignKey("rules.id"), nullable=False))
    from_version: Optional[int] = Field(default=None, sa_column=Column(Integer))
    to_version: int = Field(sa_column=Column(Integer, nullable=False))
    status: str = Field(sa_column=Column(Text, nullable=False))
    mode: str = Field(default="staged", sa_column=Column(Text, nullable=False, server_default=text("'staged'")))
    source: str = Field(default="manual", sa_column=Column(Text, nullable=False, server_default=text("'manual'")))
    budget: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")))
    progress: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")))
    created_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    started_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    started_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    finished_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    paused_reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    note: Optional[str] = Field(default=None, sa_column=Column(Text))


class LlmRuntime(SQLModel, table=True):
    """What the scanner runs with, for the API (migration 0024): ``service_model`` (LLM_API_MODEL)."""
    __tablename__ = "llm_runtime"
    key: str = Field(sa_column=Column(Text, primary_key=True))
    value: Optional[str] = Field(default=None, sa_column=Column(Text))
    updated_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))


####################################################
#   Statistics snapshots (0030)                 ####
####################################################

class StatsSnapshot(SQLModel, table=True):
    """Precomputed statistics the API serves instead of aggregating millions of rows per request (migration 0030):
    one row per ``name`` (``overview``, ``job_health``, ``scan_progress``, ``llm_progress``, ``llm_quality``,
    ``hits_aggregate``), ``data`` = exactly what the live computation returns, ``computed_at`` = when; written by the
    scanner's ``stats_refresh`` job every STATS_REFRESH_S, read by the API while fresh (else computed live)."""
    __tablename__ = "stats_snapshots"
    name: str = Field(sa_column=Column(Text, primary_key=True))
    data: Dict[str, Any] = Field(sa_column=Column(JSONB, nullable=False))
    computed_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))


####################################################
#   LLM rate limit (0031)                       ####
####################################################

class LlmRateBucket(SQLModel, table=True):
    """A token bucket shared by every scanner worker (and replica) that calls the service model
    (``discovery_common.llm_rate``, migration 0031): ``tokens`` left at ``updated_at``, refilled at LLM_RATE_PER_MIN;
    one row per bucket name (``service``)."""
    __tablename__ = "llm_rate_buckets"
    name: str = Field(sa_column=Column(Text, primary_key=True))
    tokens: float = Field(sa_column=Column(Float, nullable=False))
    updated_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))


####################################################
#   Review batches: decisions by filter (0032)  ####
####################################################

class ReviewBatch(SQLModel, table=True):
    """One applied ``POST /hits/decide`` (``discovery_api/services/aggregate_service``): the filter, the action, who
    and how many; ``undone_at`` once undone. The verdict history rows of the hits carry ``batch_id``."""
    __tablename__ = "review_batches"
    __table_args__ = (Index("review_batches_reviewer", "reviewer", "id"),)
    id: Optional[int] = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    filter: Dict[str, Any] = Field(sa_column=Column(JSONB, nullable=False))
    action: str = Field(sa_column=Column(Text, nullable=False))
    target_status: str = Field(sa_column=Column(Text, nullable=False))
    note: Optional[str] = Field(default=None, sa_column=Column(Text))
    category: Optional[str] = Field(default=None, sa_column=Column(Text))
    severity: Optional[str] = Field(default=None, sa_column=Column(Text))
    reviewer: str = Field(sa_column=Column(Text, nullable=False))
    via: str = Field(default="rest", sa_column=Column(Text, nullable=False, server_default=text("'rest'")))
    expected_total: int = Field(sa_column=Column(Integer, nullable=False))
    matched: int = Field(sa_column=Column(Integer, nullable=False))
    applied: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    cascaded: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default=text("0")))
    applied_at: Optional[datetime] = Field(default=None, sa_column=Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")))
    undone_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    undone_by: Optional[str] = Field(default=None, sa_column=Column(Text))
    restored: Optional[int] = Field(default=None, sa_column=Column(Integer))


class ReviewBatchItem(SQLModel, table=True):
    """A hit of a review batch with the state the decision replaced (for the undo); ``cascaded``: a field hit decided
    through its object (mark_fields)."""
    __tablename__ = "review_batch_items"
    __table_args__ = (
        PrimaryKeyConstraint("batch_id", "rule_id", "subject_key", name="review_batch_items_pkey"),
        Index("review_batch_items_hit", "rule_id", "subject_key"),
    )
    batch_id: int = Field(sa_column=Column(BigInteger, ForeignKey("review_batches.id", ondelete="CASCADE"),
                                           nullable=False))
    rule_id: int = Field(sa_column=Column(Integer, nullable=False))
    subject_key: uuid.UUID = Field(sa_column=Column(UUID(as_uuid=True), nullable=False))
    cascaded: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, server_default=text("false")))
    prev_status: str = Field(sa_column=Column(Text, nullable=False))
    prev_reviewer: Optional[str] = Field(default=None, sa_column=Column(Text))
    prev_reviewed_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True)))
    prev_decided_via: Optional[str] = Field(default=None, sa_column=Column(Text))
    prev_decided_tier: Optional[str] = Field(default=None, sa_column=Column(Text))
    prev_asked_by_model: Optional[bool] = Field(default=None, sa_column=Column(Boolean))
    prev_category: Optional[str] = Field(default=None, sa_column=Column(Text))
    prev_severity: Optional[str] = Field(default=None, sa_column=Column(Text))
    prev_note: Optional[str] = Field(default=None, sa_column=Column(Text))
    prev_machine_status: Optional[str] = Field(default=None, sa_column=Column(Text))
