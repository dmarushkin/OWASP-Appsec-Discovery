"""discovery_api: rules, review queue and MCP (stage 5b, P1-6 / P3-2).

* ``/keyword_rules``, ``/llm_rules``  CRUD (react-admin simple-rest), soft delete,
  ``version`` bumped when what a rule matches changes;
* ``/hits``                           review queue (filters: project_id, status, category,
  rule_id, kind, severity, q, presence = main | mr | live | all), ``GET /hits/{id}`` with
  the object and its fields, ``POST /hits/{id}/review`` (confirm | reject | request_info |
  reopen -> status match | no_match | need_more_info | pending_review; the status filter
  accepts the old confirmed / rejected for one release), ``PATCH /hits/{id}`` (category /
  severity / note);
* ``/hits/aggregate``, ``/hits/clusters``, ``POST /hits/decide[/{batch}/undo]``, ``/review_batches``
                                      review at scale: counts by dimension, clusters, decisions by filter (contract 6);
* ``/rules``, ``/categories``, ``/object_types``, ``/groups``  autocompletes (contract 7);
* ``/projects``, ``/projects/{id}``   read-only (filters of the queue; the project page);
* ``/jobs``, ``/jobs/{id}``, ``/jobs/stats``  the scanner's job queue (P2-4), ``POST /jobs/{id}/retry|cancel``;
* ``/jobs/health``, ``/jobs/errors``, ``/llm_work/stats``   read-only aggregations for the UI's "Pipeline health"
                                      and "Harness work";
* ``/llm_rules/{id}/mislabeled|trials|proposals``, ``/prompt_trials/{id}``, ``/prompt_proposals/{id}[/reask|accept|reject]``
                                      prompt trials (service model on a few subjects) and proposals (human accept);
* ``/llm_quality``, ``POST /hits/{id}/request_human``, ``POST /llm_work/claim`` (``purpose`` verify)
                                      tiered workflow: service model -> harness model -> human;
* ``/llm_rules/{id}/versions``, ``/llm_rule_versions/{id}[/estimate|activate|rollback|discard]``, ``/llm_rollouts[/{id}
  [/start|pause|resume|cancel]]``, ``/hits/{id}/history``  LLM rule lifecycle (versions, rollouts, verdict history);
* ``/mcp``                            MCP server (streamable HTTP), same bearer auth;
* ``/token``, ``/health``, ``/health/db``.

Behind nginx at ``/api``: uvicorn runs with ``--root-path /api`` (Dockerfile), so ``/api/docs`` works.
"""

from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.exc import DataError
from sqlalchemy.orm import Session
from starlette.routing import Route

import mcp_server
from auth import (
    authenticate_user, check_settings, create_access_token, get_admin_user, get_current_user, get_ingest_user,
)
from config import get_settings
from logger import get_logger
from models import Token, UserData
from schemas import (
    ApiTokenIn, BulkReviewIn, DecideIn, DryRunIn, HitDetail, IngestIn, IngestObjectsIn, IngestSessionIn, HitOut, HitUpdateIn, LabelBulkIn, LabelIn, LlmRuleRunIn, LlmRulesRunIn,
    LlmTakeOverIn, LlmWorkClaimIn, LlmWorkReleaseIn, LlmWorkSubmitIn,
    MrScanIn, ParseIn, ParseOneIn, ProjectUpdateIn, PromptProposalIn, PromptTrialIn, ProposalDecisionIn, RequestHumanIn,
    ReviewIn, RolloutActionIn, VersionActivateIn, VersionCreateIn,
)
from services import (
    aggregate_service, catalog_service, ingest_service, insights_service, tokens_service, jobs_service,
    llm_progress_service, objects_service, quality_service, review_service, rules_service, scan_progress_service,
    stats_service, trials_service, versions_service,
)
from services.db_service import get_db_session, health, init_db
from services.errors import ServiceError
from services.paging import content_range, parse_list_params, set_page_headers

logger = get_logger(__name__)

INGEST_MAX_BODY = 64 * 1024 * 1024

RULE_RESOURCES = {"keyword_rules": "keyword", "llm_rules": "llm"}


class IngestBodyLimit:
    """Bodies of the ingest endpoints are capped here too, not only by nginx (another ingress,
    a direct call): by Content-Length up front and, for bodies without one (chunked), by
    counting what is read. The route path is matched without ``root_path``: uvicorn
    ``--root-path /api`` puts ``/api/ingest`` in ``scope["path"]``."""

    def __init__(self, app):
        self.app = app

    @staticmethod
    def route_path(scope) -> str:
        path, root = scope.get("path", ""), scope.get("root_path", "")
        if root and (path == root or path.startswith(root.rstrip("/") + "/")):
            path = path[len(root.rstrip("/")):] or "/"
        return path

    async def __call__(self, scope, receive, send):
        path = self.route_path(scope) if scope["type"] == "http" else ""
        if not (path == "/ingest" or path.startswith("/ingest/")):
            await self.app(scope, receive, send)
            return
        limit = INGEST_MAX_BODY
        detail = {"detail": f"body larger than {limit} bytes"}
        length = dict(scope.get("headers") or []).get(b"content-length")
        if length is not None and (not length.strip().isdigit() or int(length) > limit):
            await JSONResponse(status_code=413, content=detail)(scope, receive, send)
            return
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise HTTPException(status_code=413, detail=detail["detail"])
            return message

        await self.app(scope, limited_receive, send)


def create_app(*, check_db: bool = True) -> FastAPI:
    mcp_endpoint = mcp_server.asgi_app()
    mcp_sessions = mcp_server.mcp.session_manager     # this app's MCP transport

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Validate configuration and wait for the (migrated) database at startup, not at import.
        check_settings(get_settings())
        if check_db:
            init_db()
        async with mcp_sessions.run():
            yield

    app = FastAPI(title="AppSec Discovery API", lifespan=lifespan)

    app.add_middleware(IngestBodyLimit)

    @app.exception_handler(RecursionError)
    async def too_deep(request: Request, exc: RecursionError):
        return JSONResponse(status_code=400, content={"detail": "JSON nested too deeply"})

    @app.exception_handler(ServiceError)
    async def service_error(request: Request, exc: ServiceError):
        return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})

    @app.exception_handler(DataError)
    async def bad_value(request: Request, exc: DataError):
        # a value Postgres cannot use (bad timestamp / number / regex in a filter): the
        # caller's mistake, not a server error; no SQL in the response
        logger.info("rejected a request with an invalid value: %s", str(exc.orig).splitlines()[0][:200])
        return JSONResponse(status_code=422, content={"detail": "invalid value in the request (e.g. a filter): "
                                                                + str(exc.orig).splitlines()[0][:200]})

    # ---- auth / health -----------------------------------------------------------------------

    @app.post("/token", response_model=Token)
    def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
        user = authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"access_token": create_access_token(user.username), "token_type": "bearer"}

    @app.get("/health")
    def get_health():
        """Liveness + database reachability (used by the compose healthcheck)."""
        try:
            health()
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise HTTPException(status_code=503, detail="database unavailable")
        return {"status": "ok"}

    @app.get("/health/db")
    def get_db_health(user: UserData = Depends(get_current_user)):
        """Schema revision, row counts and dead tuples per table (pg_stat_user_tables)."""
        return health()

    # ---- rules -------------------------------------------------------------------------------

    def add_rule_routes(resource: str, kind: str):

        @app.get(f"/{resource}", name=f"list_{resource}")
        def list_rules(response: Response, range: Optional[str] = Query(None), sort: Optional[str] = Query(None),
                       filter: Optional[str] = Query(None), db: Session = Depends(get_db_session),
                       user: UserData = Depends(get_current_user)):
            params = parse_list_params(range, sort, filter)
            items, total = rules_service.list_rules(db, kind, params)
            response.headers["Content-Range"] = content_range(resource, params.offset, len(items), total)
            return items

        @app.get(f"/{resource}/{{rule_id}}", name=f"get_{resource}")
        def get_rule(rule_id: int, db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
            return rules_service.to_out(rules_service.get_rule(db, kind, rule_id))

        @app.post(f"/{resource}", name=f"create_{resource}", status_code=201)
        def create_rule(data: Dict[str, Any] = Body(...), db: Session = Depends(get_db_session),
                        user: UserData = Depends(get_current_user)):
            rule = rules_service.create_rule(db, kind, data, user.username)
            db.commit()
            return rules_service.to_out(rule)

        @app.put(f"/{resource}/{{rule_id}}", name=f"update_{resource}")
        def update_rule(rule_id: int, data: Dict[str, Any] = Body(...), candidate: bool = Query(False),
                        db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
            """LLM rules: a prompt / scope / target edit is a new version, active at once with a rollout of the stale
            verdicts (``candidate=true``: a candidate version only, the rule unchanged)."""
            rule = rules_service.update_rule(db, kind, rule_id, data, user.username, candidate=candidate)
            db.commit()
            return rules_service.to_out(rule)

        @app.delete(f"/{resource}/{{rule_id}}", name=f"delete_{resource}")
        def delete_rule(rule_id: int, db: Session = Depends(get_db_session),
                        user: UserData = Depends(get_current_user)):
            rule = rules_service.delete_rule(db, kind, rule_id, user.username)
            db.commit()
            return rules_service.to_out(rule)

    for resource, kind in RULE_RESOURCES.items():
        add_rule_routes(resource, kind)

    @app.post("/llm_rules/run", status_code=202)
    def run_llm_rules(request: LlmRulesRunIn, db: Session = Depends(get_db_session),
                      user: UserData = Depends(get_current_user)):
        """Run LLM rules over projects already parsed (all, or ``project_ids``; ``mrs``: open MRs too)."""
        result = jobs_service.request_llm_rules_run(db, request.rule_ids, project_ids=request.project_ids,
                                                    mrs=request.mrs, requested_by=user.username,
                                                    executor=request.executor.value)
        db.commit()
        return result

    @app.post("/llm_rules/{rule_id}/run", status_code=202)
    def run_llm_rule(rule_id: int, request: LlmRuleRunIn = Body(default_factory=LlmRuleRunIn),
                     db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Run one LLM rule over projects already parsed (see ``POST /llm_rules/run``)."""
        result = jobs_service.request_llm_rules_run(db, [rule_id], project_ids=request.project_ids, mrs=request.mrs,
                                                    requested_by=user.username, executor=request.executor.value)
        db.commit()
        return result

    # ---- prompt trials and proposals (service model on a few subjects, human accepts) ----------

    @app.get("/llm_rules/{rule_id}/mislabeled")
    def get_mislabeled(rule_id: int, source: str = Query("human"), limit: int = Query(50), offset: int = Query(0),
                       db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Subjects where a human decision (``source=human``) or the harness model's final decision
        (``source=verification``) disagrees with the service model's verdict (prompt trial targets)."""
        return trials_service.mislabeled(db, rule_id, source, limit, offset)

    @app.post("/llm_rules/{rule_id}/trials", status_code=202)
    def create_trial(rule_id: int, data: PromptTrialIn, db: Session = Depends(get_db_session),
                     user: UserData = Depends(get_current_user)):
        """Run a candidate prompt with the service model on a few subjects (no hits written; daily budget)."""
        result = trials_service.create_trial(
            db, rule_id, data.prompt, user=user.username,
            subjects=[s.model_dump(mode="json") for s in data.subjects] if data.subjects else None,
            from_mislabeled=data.from_mislabeled, include_controls=data.include_controls,
            rerun_current=data.rerun_current, note=data.note, sample=data.sample)
        db.commit()
        return result

    @app.get("/llm_rules/{rule_id}/errors")
    def get_llm_rule_errors(rule_id: int, hours: int = Query(jobs_service.RULE_ERRORS_HOURS),
                            limit: int = Query(jobs_service.RULE_ERRORS_LIMIT), db: Session = Depends(get_db_session),
                            user: UserData = Depends(get_current_user)):
        """Why evaluations of this LLM rule failed in the last ``hours`` (default a week): the failed objects with
        their error and job, counts per error class, the runs that ended failed / incomplete and the refused
        harness answers (UI: rule studio, Runs tab, "Last errors")."""
        return jobs_service.rule_errors(db, rule_id, hours, limit)

    @app.get("/llm_rules/{rule_id}/trials")
    def list_trials(rule_id: int, limit: int = Query(20), db: Session = Depends(get_db_session),
                    user: UserData = Depends(get_current_user)):
        return trials_service.list_trials(db, rule_id, limit)

    @app.get("/prompt_trials/{trial_id}")
    def get_trial(trial_id: int, only: Optional[str] = Query(None), db: Session = Depends(get_db_session),
                  user: UserData = Depends(get_current_user)):
        """A trial with its metrics and per subject expected / current / re-run / new verdicts."""
        return trials_service.trial_result(db, trial_id, only=only)

    @app.get("/llm_rules/{rule_id}/proposals")
    def list_proposals(rule_id: int, status: Optional[str] = Query(None), db: Session = Depends(get_db_session),
                       user: UserData = Depends(get_current_user)):
        return trials_service.list_proposals(db, rule_id, status)

    @app.post("/llm_rules/{rule_id}/proposals", status_code=201)
    def create_proposal(rule_id: int, data: PromptProposalIn, db: Session = Depends(get_db_session),
                        user: UserData = Depends(get_current_user)):
        result = trials_service.create_proposal(db, rule_id, data.prompt, data.trial_id, data.rationale,
                                                user=user.username)
        db.commit()
        return result

    @app.get("/prompt_proposals")
    def list_all_proposals(status: Optional[str] = Query("open"), limit: int = Query(50),
                           db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Prompt proposals of every LLM rule (``status`` open by default, ``all`` for every status), each with
        ``rule_id`` / ``rule_name`` (UI Work desk: proposals waiting for a human)."""
        return trials_service.list_all_proposals(db, status, limit)

    @app.get("/prompt_proposals/{proposal_id}")
    def get_proposal(proposal_id: int, db: Session = Depends(get_db_session),
                     user: UserData = Depends(get_current_user)):
        return trials_service.get_proposal(db, proposal_id)

    @app.get("/prompt_proposals/{proposal_id}/reask")
    def proposal_reask(proposal_id: int, db: Session = Depends(get_db_session),
                       user: UserData = Depends(get_current_user)):
        """What accepting the proposal costs: the service verdicts asked again (dry run of the proposed prompt)."""
        return trials_service.reask_estimate(db, proposal_id)

    @app.post("/prompt_proposals/{proposal_id}/accept")
    def accept_proposal(proposal_id: int, data: ProposalDecisionIn = Body(default_factory=ProposalDecisionIn),
                        db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """A human adopts a proposal: a candidate version of the rule (``activate``: also active, its rollout running).
        Not available over MCP."""
        result = trials_service.accept_proposal(db, proposal_id, user=user.username, note=data.note, run=data.run,
                                                activate=data.activate, budget=_budget(data))
        db.commit()
        return result

    @app.post("/prompt_proposals/{proposal_id}/reject")
    def reject_proposal(proposal_id: int, data: ProposalDecisionIn = Body(default_factory=ProposalDecisionIn),
                        db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        result = trials_service.reject_proposal(db, proposal_id, user=user.username, note=data.note)
        db.commit()
        return result

    # ---- LLM rule lifecycle: versions, rollouts (humans activate / start; MCP reads) ----------

    def _budget(data):
        return data.budget.model_dump(exclude_none=True) if data.budget else None

    @app.get("/llm_rules/{rule_id}/versions")
    def list_rule_versions(rule_id: int, db: Session = Depends(get_db_session),
                           user: UserData = Depends(get_current_user)):
        """The versions of an LLM rule (newest first) with their diff to the active one and their rollout."""
        result = versions_service.list_versions(db, rule_id)
        db.commit()
        return result

    @app.post("/llm_rules/{rule_id}/versions", status_code=201)
    def create_rule_version(rule_id: int, data: VersionCreateIn, db: Session = Depends(get_db_session),
                            user: UserData = Depends(get_current_user)):
        """A candidate version (the active one with these changes); the rule is not changed."""
        result = versions_service.create_candidate(db, rule_id, data.model_dump(exclude_none=True), user.username)
        db.commit()
        return result

    @app.get("/llm_rule_versions/{version_id}")
    def get_rule_version(version_id: int, db: Session = Depends(get_db_session),
                         user: UserData = Depends(get_current_user)):
        return versions_service.get_version(db, version_id)

    @app.get("/llm_rule_versions/{version_id}/estimate")
    def estimate_rule_version(version_id: int, db: Session = Depends(get_db_session),
                              user: UserData = Depends(get_current_user)):
        """What activating the version costs (model calls: fresh subjects, the rollout's migration, protected)."""
        return versions_service.estimate(db, version_id)

    @app.post("/llm_rule_versions/{version_id}/activate")
    def activate_rule_version(version_id: int, data: VersionActivateIn = Body(default_factory=VersionActivateIn),
                              db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """A human makes a candidate the active version; its rollout runs (``start_rollout``) or is planned."""
        result = versions_service.activate(db, version_id, user=user.username, start_rollout=data.start_rollout,
                                           budget=_budget(data), note=data.note)
        db.commit()
        return result

    @app.post("/llm_rule_versions/{version_id}/rollback")
    def rollback_rule_version(version_id: int, data: VersionActivateIn = Body(default_factory=VersionActivateIn),
                              db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Back to the content of a retired version: a new active copy; its verdicts in the history are adopted
        without model calls, the rest migrates by a rollout."""
        version = versions_service.get_version(db, version_id)
        result = versions_service.rollback(db, version["rule_id"], version["version"], user=user.username,
                                           start_rollout=data.start_rollout, budget=_budget(data), note=data.note)
        db.commit()
        return result

    @app.post("/llm_rule_versions/{version_id}/discard")
    def discard_rule_version(version_id: int, data: RolloutActionIn = Body(default_factory=RolloutActionIn),
                             db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        result = versions_service.discard(db, version_id, user=user.username, note=data.reason)
        db.commit()
        return result

    @app.get("/llm_rollouts")
    def list_llm_rollouts(rule_id: Optional[int] = Query(None), status: Optional[str] = Query(None),
                          limit: int = Query(50), db: Session = Depends(get_db_session),
                          user: UserData = Depends(get_current_user)):
        """Rule rollouts (open first): progress (planned / remaining objects, calls, ETA, waiting reason)."""
        return versions_service.list_rollouts(db, rule_id, status.split(",") if status else None, limit)

    @app.get("/llm_rollouts/{rollout_id}")
    def get_llm_rollout(rollout_id: int, db: Session = Depends(get_db_session),
                        user: UserData = Depends(get_current_user)):
        return versions_service.get_rollout(db, rollout_id)

    @app.post("/llm_rollouts/{rollout_id}/{action}")
    def act_on_llm_rollout(rollout_id: int, action: str, data: RolloutActionIn = Body(default_factory=RolloutActionIn),
                           db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """start | pause | resume | cancel (humans only: not available over MCP)."""
        result = versions_service.rollout_action(db, rollout_id, action, user=user.username, reason=data.reason,
                                                 budget=_budget(data))
        db.commit()
        return result

    @app.get("/hits/{hit_id}/history")
    def get_hit_history(hit_id: str, limit: int = Query(100), db: Session = Depends(get_db_session),
                        user: UserData = Depends(get_current_user)):
        """The verdict history of a hit (newest first, what changed) and the last verdict of every rule version."""
        return versions_service.hit_history(db, hit_id, limit)

    # ---- LLM rule runs: progress, external executor ------------------------------------------

    @app.get("/llm_runs")
    def get_llm_runs(limit: int = Query(20), db: Session = Depends(get_db_session),
                     user: UserData = Depends(get_current_user)):
        """Active LLM rule runs (queued, running, external ones waiting for answers) with their
        progress, and the ones finished in the last 24 hours (dashboard)."""
        return jobs_service.llm_runs(db, limit)

    @app.get("/scan_progress")
    def get_scan_progress(request: Request, response: Response, status: Optional[str] = Query(None),
                          scan_mode: Optional[str] = Query(None), q: Optional[str] = Query(None),
                          project_id: Optional[str] = Query(None), limit: int = Query(50), offset: int = Query(0),
                          projects: bool = Query(True), live: bool = Query(False),
                          db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Progress of the parse scans of the tracked GitLab projects: totals of main branches
        (synced, scanned at the current commit, outdated, never scanned, partial, failed,
        queued, running; also by scan mode), of open MRs, of external projects and the job
        queue; plus the project list (``status``: comma separated states / queued / running /
        active / attention / not_synced; ``project_id``: comma separated ids), problems first.
        The totals come from the ``scan_progress`` snapshot while fresh (``computed_at``, ``snapshot``, ETag / 304
        without the project list; ``live=true`` forces a live computation), the project list is always live."""
        split = lambda v: [x for x in v.split(",") if x] if v else None      # noqa: E731
        totals = stats_service.serve(db, "scan_progress", lambda: scan_progress_service.totals(db), live=live,
                                     request=None if projects else request, response=None if projects else response)
        if not isinstance(totals, dict):
            return totals
        if projects:
            totals["projects"] = scan_progress_service.project_rows(
                db, status=split(status), scan_mode=split(scan_mode), q=q, project_ids=split(project_id),
                limit=limit, offset=offset)
        return totals

    @app.get("/llm_progress")
    def get_llm_progress(request: Request, response: Response, status: Optional[str] = Query(None),
                         q: Optional[str] = Query(None), project_id: Optional[str] = Query(None),
                         limit: int = Query(50), offset: int = Query(0), projects: bool = Query(True),
                         live: bool = Query(False), db: Session = Depends(get_db_session),
                         user: UserData = Depends(get_current_user)):
        """Coverage of the LLM rules over the projects in scan mode rules (from the scanner's
        ``llm_coverage`` rows, no candidate counting): main branches with current verdicts of
        every enabled LLM rule, outdated, never counted, not scanned, failed, queued / running /
        awaiting answers; open MRs; per rule answered / total subjects; plus the project list
        (``status``: comma separated states / queued / running / awaiting_answers / active /
        incomplete; ``project_id``: comma separated ids), problems first. Totals from the ``llm_progress``
        snapshot while fresh (as ``/scan_progress``)."""
        split = lambda v: [x for x in v.split(",") if x] if v else None      # noqa: E731
        totals = stats_service.serve(db, "llm_progress", lambda: llm_progress_service.totals(db), live=live,
                                     request=None if projects else request, response=None if projects else response)
        if not isinstance(totals, dict):
            return totals
        if projects:
            totals["projects"] = llm_progress_service.project_rows(db, status=split(status), q=q,
                                                                   project_ids=split(project_id), limit=limit,
                                                                   offset=offset)
        return totals

    @app.get("/llm_quality")
    def get_llm_quality(request: Request, response: Response, rule_id: Optional[int] = Query(None),
                        live: bool = Query(False), db: Session = Depends(get_db_session),
                        user: UserData = Depends(get_current_user)):
        """Tiered workflow: agreement of the service model with the harness model per LLM rule (QA sample), escalation
        rate, open questions of the model, verify backlog, rules that need improvement. Without ``rule_id`` from the
        ``llm_quality`` snapshot while fresh (``computed_at``, ``snapshot``, ETag / 304)."""
        return stats_service.serve(db, "llm_quality", lambda: quality_service.llm_quality(db, rule_id),
                                   live=live or rule_id is not None, request=request, response=response)

    @app.get("/llm_work/jobs")
    def get_llm_work_jobs(active: bool = Query(True), limit: int = Query(20), db: Session = Depends(get_db_session),
                          user: UserData = Depends(get_current_user)):
        """External LLM runs (``executor = external``) with their progress."""
        return jobs_service.llm_work_jobs(db, active, limit)

    @app.get("/llm_work/stats")
    def get_llm_work_stats(db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Harness work (read-only): work items by purpose and status, open verify items by sample, the leases held
        by owner and the answers of the last 24 hours by owner (UI "Harness work")."""
        return jobs_service.llm_work_stats(db)

    @app.post("/llm_work/claim")
    def claim_llm_work(data: LlmWorkClaimIn = Body(default_factory=LlmWorkClaimIn),
                       db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Lease work items of external LLM runs (prompts to answer); see MCP ``llm_work_claim``."""
        result = jobs_service.llm_work_claim(db, user.username, job_id=data.job_id, limit=data.limit,
                                             lease_seconds=data.lease_seconds, take_over_pending=data.take_over_pending,
                                             purpose=data.purpose)
        db.commit()
        return result

    @app.post("/llm_work/take_over")
    def take_over_llm_runs(data: LlmTakeOverIn = Body(default_factory=LlmTakeOverIn),
                           db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Pending service LLM runs (``llm_score`` jobs not started yet) become external runs under
        the same job ids; see MCP ``llm_take_over``."""
        result = jobs_service.llm_take_over(db, user.username, job_id=data.job_id, limit=data.limit)
        db.commit()
        return result

    @app.post("/llm_work/submit")
    def submit_llm_work(data: LlmWorkSubmitIn, db: Session = Depends(get_db_session),
                        user: UserData = Depends(get_current_user)):
        """Answers of leased work items; the scanner applies them (``llm_apply`` job)."""
        result = jobs_service.llm_work_submit(db, user.username, [i.model_dump() for i in data.items],
                                              lease=data.lease, via="rest")
        db.commit()
        return result

    @app.post("/llm_work/release")
    def release_llm_work(data: LlmWorkReleaseIn, db: Session = Depends(get_db_session),
                         user: UserData = Depends(get_current_user)):
        """Claimed items back to pending (``ids`` + ``lease``), or everything unanswered of an
        external run back to the service (``job_id`` + ``all_unanswered``)."""
        result = jobs_service.llm_work_release(db, user.username, data.ids, data.lease, job_id=data.job_id,
                                               all_unanswered=data.all_unanswered)
        db.commit()
        return result

    # ---- review queue ------------------------------------------------------------------------

    @app.get("/hits", response_model=list[HitOut])
    def list_hits(response: Response, range: Optional[str] = Query(None), sort: Optional[str] = Query(None),
                  filter: Optional[str] = Query(None), after: Optional[str] = Query(None),
                  exact: Optional[bool] = Query(None), db: Session = Depends(get_db_session),
                  user: UserData = Depends(get_current_user)):
        """The review queue. Paging: ``range`` (offset) or ``after`` (the ``X-Next-Cursor`` of the previous page);
        the total in ``Content-Range`` is an estimate above 10 000 rows (``X-Total-Estimate: true``) unless
        ``exact=true``. Filters: see ``review_service`` (``group``, ``cluster`` included)."""
        params = parse_list_params(range, sort, filter, after, exact)
        page = review_service.list_hits(db, params)
        set_page_headers(response, "hits", params, page)
        return page.items

    @app.get("/hits/aggregate")
    def hits_aggregate(by: str = Query("queue"), filter: Optional[str] = Query(None), live: bool = Query(False),
                       db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Counts of hits grouped by ``by`` (comma separated: status, queue, presence, rule_id, category, severity,
        decided_tier, asked_by_model, in_main, in_open_mr, field_mark, kind, project_id, group, object_type,
        first_seen_day) under the filters of ``GET /hits`` (``filter`` JSON). From the ``hits_aggregate`` snapshot when
        the filters and dimensions allow it (``snapshot: true``), else live."""
        params = parse_list_params(None, None, filter)
        return aggregate_service.hits_aggregate(db, [b for b in by.split(",") if b], params.filters, live=live)

    @app.get("/hits/clusters")
    def hits_clusters(by: str = Query("schema"), filter: Optional[str] = Query(None), limit: int = Query(25),
                      after: Optional[str] = Query(None), db: Session = Depends(get_db_session),
                      user: UserData = Depends(get_current_user)):
        """The filtered hits (default: open, live) grouped by ``by`` = schema | field_pattern | object_name |
        rule_group, biggest first, with counts, projects, presence share, new in 7 days, questions and sample ids;
        ``items[].cluster`` is the ``cluster`` filter value of ``GET /hits`` and ``POST /hits/decide``."""
        params = parse_list_params(None, None, filter)
        return aggregate_service.hits_clusters(db, by, params.filters, limit=limit, after=after)

    @app.post("/hits/decide")
    def decide_hits(data: DecideIn, db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """One review action on every hit of a filter. ``dry_run`` (default) reports ``matched`` (what would change)
        and ``kept`` (human decisions, questions of the model, hits whose status does not allow the action); the
        apply (``dry_run: false``) needs ``expected_total`` = the dry run's ``matched`` (409 when the set changed) and
        returns ``batch_id`` for ``POST /hits/decide/{batch_id}/undo``."""
        result = aggregate_service.decide(
            db, filters=data.filter, action=data.action, reviewer=user.username, note=data.note,
            category=data.category, severity=data.severity, expected_total=data.expected_total, dry_run=data.dry_run,
            include_human=data.include_human, include_harness=data.include_harness,
            skip_questions=data.skip_questions, via="rest")
        db.commit()
        return result

    @app.post("/hits/decide/{batch_id}/undo")
    def undo_decision(batch_id: int, db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Undo a decision by filter: the hits nobody touched since get their previous state back."""
        result = aggregate_service.undo_batch(db, batch_id, user=user.username, via="rest")
        db.commit()
        return result

    @app.get("/review_batches")
    def list_review_batches(limit: int = Query(50), reviewer: Optional[str] = Query(None),
                            db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Decisions by filter, newest first."""
        return aggregate_service.list_batches(db, limit, reviewer)

    @app.get("/review_batches/{batch_id}")
    def get_review_batch(batch_id: int, db: Session = Depends(get_db_session),
                         user: UserData = Depends(get_current_user)):
        return aggregate_service.get_batch(db, batch_id)

    @app.post("/hits/review_bulk")
    def review_hits_bulk(data: BulkReviewIn, db: Session = Depends(get_db_session),
                         user: UserData = Depends(get_current_user)):
        """The same review action on up to 50 hits (``dry_run`` by default), one transaction."""
        result = review_service.review_hits_bulk(db, data.hit_ids, data.action, user.username, note=data.note,
                                                 category=data.category, severity=data.severity,
                                                 dry_run=data.dry_run)
        db.commit()
        return result

    @app.get("/hits/{hit_id}", response_model=HitDetail)
    def get_hit(hit_id: str, db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        return review_service.get_hit_detail(db, hit_id)

    @app.post("/hits/{hit_id}/review", response_model=HitOut)
    def review_hit(hit_id: str, review: ReviewIn, db: Session = Depends(get_db_session),
                   user: UserData = Depends(get_current_user)):
        hit = review_service.review_hit(db, hit_id, review.action, user.username, category=review.category,
                                        severity=review.severity, note=review.note)
        db.commit()
        return hit

    @app.post("/hits/{hit_id}/request_human")
    def request_human(hit_id: str, data: RequestHumanIn, db: Session = Depends(get_db_session),
                      user: UserData = Depends(get_current_user)):
        """The harness model asks a human about a machine hit (need_more_info, "Questions from the model")."""
        result = review_service.request_human(db, hit_id, data.question, user=user.username, model=data.model,
                                              via="rest")
        db.commit()
        return result

    @app.patch("/hits/{hit_id}", response_model=HitOut)
    def update_hit(hit_id: str, update: HitUpdateIn, db: Session = Depends(get_db_session),
                   user: UserData = Depends(get_current_user)):
        hit = review_service.update_hit(db, hit_id, user.username, category=update.category,
                                        severity=update.severity, note=update.note)
        db.commit()
        return hit

    @app.put("/hits/{hit_id}", response_model=HitOut)
    def put_hit(hit_id: str, update: HitUpdateIn, db: Session = Depends(get_db_session),
                user: UserData = Depends(get_current_user)):
        """react-admin ``update`` (Edit form): same as PATCH (status changes go through /review)."""
        return update_hit(hit_id, update, db, user)

    # ---- projects ----------------------------------------------------------------------------

    @app.get("/projects")
    def list_projects(response: Response, range: Optional[str] = Query(None), sort: Optional[str] = Query(None),
                      filter: Optional[str] = Query(None), after: Optional[str] = Query(None),
                      exact: Optional[bool] = Query(None), db: Session = Depends(get_db_session),
                      user: UserData = Depends(get_current_user)):
        """Tracked projects (filters ``q``, ``id``, ``scan_mode``, ``group``, ``source``, ``severity``, ``tag``) with
        their parse state, LLM coverage and open live hits; paging as ``GET /hits``."""
        params = parse_list_params(range, sort, filter, after, exact)
        page = review_service.list_projects(db, params)
        set_page_headers(response, "projects", params, page)
        return page.items

    @app.get("/projects/{project_id}")
    def get_project(project_id: int, detail: bool = Query(True), db: Session = Depends(get_db_session),
                    user: UserData = Depends(get_current_user)):
        """One project: the list row plus (``detail``) ``hits_by_rule``, ``objects_by_type``, ``objects_in_open_mrs``,
        ``open_mrs`` and its last ``jobs`` (the project page)."""
        return review_service.get_project(db, project_id, detail=detail)

    # ---- autocompletes and groups (contract 7) --------------------------------------------------

    @app.get("/rules")
    def rules_autocomplete(q: Optional[str] = Query(None), kind: Optional[str] = Query(None), limit: int = Query(20),
                           include_disabled: bool = Query(True), db: Session = Depends(get_db_session),
                           user: UserData = Depends(get_current_user)):
        """Rules of any kind by name substring (dropdowns): ``[{id, name, kind, category, severity, mode, target,
        enabled, version}]``, prefix matches first."""
        return catalog_service.rules(db, q, kind, limit, include_disabled)

    @app.get("/categories")
    def categories(db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Every category a rule or a hit has, with rules / hits / matches per category."""
        return catalog_service.categories(db)

    @app.get("/object_types")
    def object_types(db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Object types of the main snapshots with counts."""
        return catalog_service.object_types(db)

    @app.get("/groups")
    def groups(q: Optional[str] = Query(None), depth: int = Query(2), parent: Optional[str] = Query(None),
               limit: int = Query(200), db: Session = Depends(get_db_session),
               user: UserData = Depends(get_current_user)):
        """GitLab groups = prefixes of the projects' paths (up to ``depth`` levels) with the projects under each;
        ``group=<path>`` of the hits / objects / projects lists scopes them to one."""
        return catalog_service.groups(db, q, depth, parent, limit)

    def update_project(project_id: int, data: ProjectUpdateIn, db: Session, user: UserData):
        result = objects_service.set_scan_mode(db, project_id, data.scan_mode.value, requested_by=user.username,
                                               parse=data.parse)
        db.commit()
        return {**result["project"], "previous_scan_mode": result["previous_scan_mode"],
                "removed_machine_hits": result["removed_machine_hits"], "parse": result.get("parse")}

    @app.patch("/projects/{project_id}")
    def patch_project(project_id: int, data: ProjectUpdateIn, db: Session = Depends(get_db_session),
                      user: UserData = Depends(get_current_user)):
        """Set the scan mode: ``rules`` or ``inventory`` (no categorisation; label by hand)."""
        return update_project(project_id, data, db, user)

    @app.put("/projects/{project_id}")
    def put_project(project_id: int, data: ProjectUpdateIn, db: Session = Depends(get_db_session),
                    user: UserData = Depends(get_current_user)):
        """react-admin ``update``: same as PATCH."""
        return update_project(project_id, data, db, user)

    @app.post("/projects/parse", status_code=202)
    def parse_projects(request: ParseIn = Body(default_factory=ParseIn), db: Session = Depends(get_db_session),
                       user: UserData = Depends(get_current_user)):
        """Parse projects again (all, or ``project_ids``), optionally by a parser subset; LLM off by default."""
        result = jobs_service.request_parse(db, request.project_ids, parsers=request.parsers, mains=request.mains,
                                            mrs=request.mrs, llm=request.llm, force=request.force,
                                            requested_by=user.username)
        db.commit()
        return result

    @app.post("/projects/{project_id}/parse", status_code=202)
    def parse_project(project_id: int, request: ParseOneIn = Body(default_factory=ParseOneIn),
                      db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Parse one project again (see ``POST /projects/parse``)."""
        result = jobs_service.request_parse(db, [project_id], parsers=request.parsers, mains=request.mains,
                                            mrs=request.mrs, llm=request.llm, force=request.force,
                                            requested_by=user.username)
        db.commit()
        return result

    # ---- external parsers ----------------------------------------------------------------------

    @app.post("/ingest", status_code=202)
    def ingest(data: IngestIn, db: Session = Depends(get_db_session), user: UserData = Depends(get_ingest_user),
               idempotency_key: Optional[str] = Header(None, max_length=200)):
        """The full state of one external parser (e.g. tables and columns of a SQL server) for one
        external project (``external/...``), applied by an ``ingest`` job: keyword rules, then the
        project's snapshot of that parser is replaced. ``unchanged: true`` when it equals the
        latest state. Larger states: upload sessions."""
        result = ingest_service.create_batch(db, data, user, idempotency_key)
        db.commit()
        return result

    @app.post("/ingest/sessions", status_code=201)
    def start_ingest_session(data: IngestSessionIn, db: Session = Depends(get_db_session),
                             user: UserData = Depends(get_ingest_user),
                             idempotency_key: Optional[str] = Header(None, max_length=200)):
        """Start uploading a large state in chunks (``PUT .../chunks/{seq}``, then ``POST .../commit``)."""
        result = ingest_service.start_session(db, data, user, idempotency_key)
        db.commit()
        return result

    @app.put("/ingest/sessions/{session_id}/chunks/{seq}")
    def put_ingest_chunk(session_id: int, seq: int, data: IngestObjectsIn, db: Session = Depends(get_db_session),
                         user: UserData = Depends(get_ingest_user)):
        """One chunk of the state (replaced when sent again with the same ``seq``)."""
        result = ingest_service.put_chunk(db, session_id, seq, data.objects, user)
        db.commit()
        return result

    @app.post("/ingest/sessions/{session_id}/commit", status_code=202)
    def commit_ingest_session(session_id: int, db: Session = Depends(get_db_session),
                              user: UserData = Depends(get_ingest_user)):
        result = ingest_service.commit_session(db, session_id, user)
        db.commit()
        return result

    @app.delete("/ingest/sessions/{session_id}")
    def abort_ingest_session(session_id: int, db: Session = Depends(get_db_session),
                             user: UserData = Depends(get_ingest_user)):
        result = ingest_service.abort_session(db, session_id, user)
        db.commit()
        return result

    @app.get("/ingest")
    def list_ingest_batches(project_id: Optional[int] = Query(None), limit: int = Query(50),
                            include_superseded: bool = Query(False),
                            db: Session = Depends(get_db_session), user: UserData = Depends(get_ingest_user)):
        """Pushed states, newest first; ``superseded`` ones (replaced by a newer processed
        state, kept only for Idempotency-Key replays) with ``include_superseded=true``."""
        return ingest_service.list_batches(db, user, project_id, limit, include_superseded)

    # ---- service tokens (admin) ----------------------------------------------------------------

    @app.post("/tokens", status_code=201)
    def create_token(data: ApiTokenIn, db: Session = Depends(get_db_session),
                     user: UserData = Depends(get_admin_user)):
        """A service token: scope ``ingest`` (a collector, on ``external/...`` path prefixes) and / or ``mcp`` (a
        harness / agent client with its own identity ``token:<name>``). Admin only."""
        result = tokens_service.create_token(db, data, user.username)
        db.commit()
        return result

    @app.get("/tokens")
    def list_tokens(db: Session = Depends(get_db_session), user: UserData = Depends(get_admin_user)):
        return tokens_service.list_tokens(db)

    @app.delete("/tokens/{token_id}")
    def revoke_token(token_id: int, db: Session = Depends(get_db_session), user: UserData = Depends(get_admin_user)):
        result = tokens_service.revoke_token(db, token_id)
        db.commit()
        return result

    # ---- rule analytics, overview, merge requests ---------------------------------------------

    @app.post("/rules/dry_run")
    def dry_run_rule(data: DryRunIn, db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """What a rule would hit on the stored main snapshots (keyword), or would send to the model (llm)."""
        return insights_service.dry_run_rule(db, kind=data.kind, rule=data.rule, rule_id=data.rule_id,
                                             project_ids=data.project_ids, sample=data.sample)

    @app.get("/rules/stats")
    def rule_stats(rule_id: Optional[int] = Query(None), since: Optional[str] = Query(None),
                   db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Per rule and version: hits by status and the precision of human decisions."""
        return insights_service.rule_stats(db, rule_id, since)

    @app.get("/overview")
    def get_overview(request: Request, response: Response, project_id: Optional[int] = Query(None),
                     category: Optional[str] = Query(None), tag: Optional[str] = Query(None),
                     rule_id: Optional[int] = Query(None), severity: Optional[str] = Query(None),
                     live: bool = Query(False), db: Session = Depends(get_db_session),
                     user: UserData = Depends(get_current_user)):
        """Inventory and hits in one call; ``category`` / ``tag`` / ``severity`` (comma separated) and ``rule_id``
        narrow ``matches_by_project`` and ``confirmed_by_category`` (UI Landscape). Without arguments from the
        ``overview`` snapshot while fresh (``computed_at``, ``snapshot``, ETag / 304); ``live=true`` computes."""
        split = lambda v: [x for x in v.split(",") if x] if v else None      # noqa: E731
        filtered = any(v not in (None, "") for v in (project_id, category, tag, rule_id, severity))
        return stats_service.serve(
            db, "overview", lambda: insights_service.overview(db, project_id, category=split(category), tag=split(tag),
                                                               rule_id=rule_id, severity=split(severity)),
            live=live or filtered, request=request, response=response)

    @app.get("/mrs")
    def list_mrs(project_id: Optional[int] = Query(None), state: str = Query("opened"), q: Optional[str] = Query(None),
                 limit: int = Query(50), offset: int = Query(0), db: Session = Depends(get_db_session),
                 user: UserData = Depends(get_current_user)):
        return insights_service.list_mrs(db, project_id, state, q, limit, offset)

    @app.get("/mrs/{mr_id}")
    def get_mr(mr_id: int, limit: int = Query(100), db: Session = Depends(get_db_session),
               user: UserData = Depends(get_current_user)):
        """An MR: its delta vs the target and the hits on it."""
        return insights_service.get_mr(db, mr_id, limit)

    @app.post("/mrs/{mr_id}/scan", status_code=202)
    def scan_mr(mr_id: int, data: MrScanIn = Body(default_factory=MrScanIn), db: Session = Depends(get_db_session),
                user: UserData = Depends(get_current_user)):
        result = insights_service.request_mr_scan(db, mr_id, llm=data.llm, requested_by=user.username)
        db.commit()
        return result

    # ---- object inventory and manual labels --------------------------------------------------

    @app.post("/objects/labels")
    def label_objects(data: LabelBulkIn, db: Session = Depends(get_db_session),
                      user: UserData = Depends(get_current_user)):
        """The same manual label on up to 50 objects / fields (``dry_run`` by default)."""
        result = objects_service.label_bulk(db, [i.model_dump() for i in data.items], category=data.category,
                                            severity=data.severity.value, reviewer=user.username, tags=data.tags,
                                            note=data.note, dry_run=data.dry_run)
        db.commit()
        return result

    @app.get("/objects")
    def list_objects(response: Response, range: Optional[str] = Query(None), sort: Optional[str] = Query(None),
                     filter: Optional[str] = Query(None), after: Optional[str] = Query(None),
                     exact: Optional[bool] = Query(None), db: Session = Depends(get_db_session),
                     user: UserData = Depends(get_current_user)):
        """The inventory (filters as MCP ``list_objects`` plus ``group``); paging as ``GET /hits``."""
        params = parse_list_params(range, sort, filter, after, exact)
        page = objects_service.list_objects(db, params)
        set_page_headers(response, "objects", params, page)
        return page.items

    @app.get("/objects/{object_key}")
    def get_object(object_key: str, db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        return objects_service.get_object(db, object_key)

    @app.post("/objects/{object_key}/labels", response_model=HitOut)
    def label_object(object_key: str, data: LabelIn, db: Session = Depends(get_db_session),
                     user: UserData = Depends(get_current_user)):
        """Label the object (or ``field_name``) by hand: a ``match`` hit of the ``manual:labels`` rule."""
        hit = objects_service.set_label(db, object_key, category=data.category, severity=data.severity,
                                        field_name=data.field_name, note=data.note, tags=data.tags,
                                        reviewer=user.username)
        db.commit()
        return hit

    @app.delete("/objects/{object_key}/labels")
    def unlabel_object(object_key: str, field_name: Optional[str] = Query(None), db: Session = Depends(get_db_session),
                       user: UserData = Depends(get_current_user)):
        result = objects_service.remove_label(db, object_key, field_name)
        db.commit()
        return result

    # ---- scanner job queue -------------------------------------------------------------------

    @app.get("/jobs")
    def list_jobs(response: Response, range: Optional[str] = Query(None), sort: Optional[str] = Query(None),
                  filter: Optional[str] = Query(None), db: Session = Depends(get_db_session),
                  user: UserData = Depends(get_current_user)):
        params = parse_list_params(range, sort, filter)
        items, total = jobs_service.list_jobs(db, params)
        response.headers["Content-Range"] = content_range("jobs", params.offset, len(items), total)
        return items

    @app.get("/jobs/stats")
    def get_job_stats(db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """``{kind: {status: count}}``."""
        return jobs_service.job_counts(db)

    @app.get("/jobs/health")
    def get_job_health(request: Request, response: Response, live: bool = Query(False),
                       db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """Queue health (read-only): per kind pending / retrying / running / failed, done and failed in the last
        hour and 24 hours, the oldest pending (due) and longest running job, scheduled jobs (due later), typical run /
        wait time and ETA; busy workers; service LLM throughput and ETA (UI "Pipeline health"). From the
        ``job_health`` snapshot while fresh (``computed_at``, ``snapshot``, ETag / 304); ``live=true`` computes."""
        return stats_service.serve(db, "job_health", lambda: jobs_service.job_health(db), live=live,
                                   request=request, response=response)

    @app.get("/jobs/errors")
    def get_job_errors(hours: int = Query(24), db: Session = Depends(get_db_session),
                       user: UserData = Depends(get_current_user)):
        """Failed jobs of the last ``hours`` grouped by kind and error text (ids / hashes normalised), most frequent
        first (UI "Pipeline health", Failures)."""
        return jobs_service.job_errors(db, hours)

    @app.get("/jobs/{job_id}")
    def get_job(job_id: int, db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        return jobs_service.get_job(db, job_id)

    @app.post("/jobs/{job_id}/retry")
    def retry_job(job_id: int, db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """A failed job pending again (attempts 0, due now; the error kept in ``payload.previous_error``); 409 otherwise."""
        result = jobs_service.retry_job(db, job_id)
        db.commit()
        return result

    @app.post("/jobs/{job_id}/cancel")
    def cancel_job(job_id: int, db: Session = Depends(get_db_session), user: UserData = Depends(get_current_user)):
        """A pending job becomes failed ('cancelled by <user>'); 409 otherwise."""
        result = jobs_service.cancel_job(db, job_id, user.username)
        db.commit()
        return result

    # ---- MCP ---------------------------------------------------------------------------------

    app.router.routes.append(Route("/mcp", endpoint=mcp_endpoint, methods=["GET", "POST", "DELETE"]))

    return app


app = create_app()
