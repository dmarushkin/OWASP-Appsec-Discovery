"""react-admin (ra-data-simple-rest) list parameters (P3-2) and paging at scale.

``?range=[0,24]&sort=["id","ASC"]&filter={"status":"pending_review"}``. Sort columns are
whitelisted by the caller, the page size is capped at ``MAX_LIMIT``, and the caller always
sets ``Content-Range: <resource> <start>-<end>/<total>``.

At millions of rows an exact ``count(*)`` per page and a deep ``OFFSET`` cost seconds, so (scale, contract 5):

* **totals are estimated** unless the caller asks for ``exact`` (filter key or query parameter ``exact=true``):
  ``estimated_total`` counts the filtered rows up to ``COUNT_CAP`` (an exact figure below the cap) and above it
  takes the planner's estimate of the same query (``EXPLAIN``); ``total_is_estimate`` says which it is. REST
  lists carry it in ``X-Total-Estimate: true|false`` next to a valid ``Content-Range``; MCP results in
  ``total_is_estimate``.
* **keyset paging**: ``after=<cursor>`` (filter key / query parameter / MCP argument) continues after the last
  row of the previous page in the current sort order; the response names the next cursor (``X-Next-Cursor``
  header, MCP ``next_cursor``), None when the page was the last one. ``offset`` keeps working (react-admin).
  A cursor encodes the sort key values of the last row (``encode_cursor`` / ``decode_cursor``), opaque to
  clients and bound to the sort order it was made with.
"""

import base64
import json
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import text

from services.errors import Invalid

MAX_LIMIT = 100
DEFAULT_LIMIT = 25
# exact counts up to here; above it the planner's estimate is returned (``total_is_estimate``)
COUNT_CAP = 10_000
CURSOR_MAX = 2000

# keys of ``filter`` that steer the paging, not the rows
PAGING_KEYS = ("after", "exact")


@dataclass
class ListParams:
    offset: int = 0
    limit: int = DEFAULT_LIMIT
    sort: Optional[str] = None
    descending: bool = False
    filters: Dict[str, Any] = field(default_factory=dict)
    after: Optional[str] = None         # keyset cursor: the page after this one
    exact: bool = False                 # an exact total instead of an estimate


@dataclass
class Page:
    """What a list service returns: the rows, the total (exact or estimated) and the cursor of the next page."""
    items: list
    total: int
    total_is_estimate: bool = False
    next_cursor: Optional[str] = None

    def __iter__(self):             # ``items, total = list_x(...)`` keeps working for older callers
        yield self.items
        yield self.total


def _json(raw: Optional[str], what: str):
    if raw is None or raw == "":
        return None
    try:
        return json.loads(raw)
    except ValueError:
        raise Invalid(f"{what} is not valid JSON") from None


def truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


def parse_list_params(range_: Optional[str], sort: Optional[str], filter_: Optional[str],
                      after: Optional[str] = None, exact: Optional[bool] = None) -> ListParams:
    params = ListParams()

    rng = _json(range_, "range")
    if rng is not None:
        if not (isinstance(rng, list) and len(rng) == 2 and all(isinstance(v, int) and v >= 0 for v in rng)
                and rng[1] >= rng[0]):
            raise Invalid("range must be [start, end] with 0 <= start <= end")
        params.offset = rng[0]
        params.limit = min(rng[1] - rng[0] + 1, MAX_LIMIT)

    srt = _json(sort, "sort")
    if srt is not None:
        if not (isinstance(srt, list) and len(srt) == 2 and isinstance(srt[0], str)
                and str(srt[1]).upper() in ("ASC", "DESC")):
            raise Invalid('sort must be ["field", "ASC"|"DESC"]')
        params.sort = srt[0]
        params.descending = str(srt[1]).upper() == "DESC"

    flt = _json(filter_, "filter")
    if flt is not None:
        if not isinstance(flt, dict):
            raise Invalid("filter must be a JSON object")
        params.filters = {k: v for k, v in flt.items() if v is not None and v != ""}
    # the paging keys may travel inside ``filter`` (react-admin) or as query parameters
    cursor = params.filters.pop("after", None)
    if "exact" in params.filters:
        params.exact = truthy(params.filters.pop("exact"))
    if after not in (None, ""):
        cursor = after
    if exact is not None:
        params.exact = bool(exact)
    if cursor not in (None, ""):
        params.after = str(cursor)
        params.offset = 0           # a cursor replaces the offset
    return params


def content_range(resource: str, offset: int, count: int, total: int) -> str:
    end = offset + count - 1 if count else offset
    return f"{resource} {offset}-{end}/{max(total, offset + count)}"


def set_page_headers(response, resource: str, params: ListParams, page: Page) -> None:
    """``Content-Range`` (valid for react-admin, the total an estimate when ``X-Total-Estimate`` is true) and
    ``X-Next-Cursor`` of a REST list response."""
    response.headers["Content-Range"] = content_range(resource, params.offset, len(page.items), page.total)
    response.headers["X-Total-Estimate"] = "true" if page.total_is_estimate else "false"
    if page.next_cursor:
        response.headers["X-Next-Cursor"] = page.next_cursor
    response.headers["Access-Control-Expose-Headers"] = "Content-Range, X-Total-Estimate, X-Next-Cursor"


# ---- totals ---------------------------------------------------------------------------------------

def estimated_total(session, from_where_sql: str, binds: Dict[str, Any], *, exact: bool = False,
                    cap: Optional[int] = None) -> Tuple[int, bool]:
    """``(total, is_estimate)`` of ``SELECT ... FROM <from_where_sql>``: exact when asked or when the rows fit
    under ``cap`` (counted with ``LIMIT cap + 1``, so a big set costs the cap, not the table), else the planner's
    row estimate of the same query (never below the cap)."""
    cap = COUNT_CAP if cap is None else cap
    if exact:
        return int(session.execute(text(f"SELECT count(*) FROM {from_where_sql}"), binds).scalar() or 0), False
    capped = session.execute(text(f"SELECT count(*) FROM (SELECT 1 FROM {from_where_sql} LIMIT :cap_plus) c"),
                             {**binds, "cap_plus": cap + 1}).scalar() or 0
    if capped <= cap:
        return int(capped), False
    estimate = planner_estimate(session, f"SELECT 1 FROM {from_where_sql}", binds)
    return max(int(estimate or 0), cap), True


def planner_estimate(session, sql: str, binds: Dict[str, Any]) -> Optional[int]:
    """The planner's row estimate of ``sql`` (``EXPLAIN (FORMAT JSON)``), None when unavailable."""
    try:
        row = session.execute(text(f"EXPLAIN (FORMAT JSON) {sql}"), binds).scalar()
    except Exception:           # a dialect without EXPLAIN JSON, a plan error: no estimate, not a failure
        return None
    plan = row[0] if isinstance(row, list) else row
    if isinstance(plan, str):
        try:
            plan = json.loads(plan)[0]
        except (ValueError, IndexError, TypeError):
            return None
    try:
        return int(plan["Plan"]["Plan Rows"])
    except (KeyError, TypeError, ValueError):
        return None


# ---- keyset cursors -------------------------------------------------------------------------------

def _tagged(value) -> list:
    if value is None:
        return [None, "null"]
    if isinstance(value, bool):
        return [value, "bool"]
    if isinstance(value, int):
        return [value, "int"]
    if isinstance(value, (float, Decimal)):
        return [float(value), "float"]
    if isinstance(value, uuid.UUID):
        return [str(value), "uuid"]
    if isinstance(value, datetime):
        return [value.isoformat(), "ts"]
    if isinstance(value, date):
        return [value.isoformat(), "date"]
    return [str(value), "text"]


_CASTS = {"int": "bigint", "float": "double precision", "uuid": "uuid", "ts": "timestamptz", "date": "date",
          "bool": "boolean", "text": "text"}


def encode_cursor(sort: str, values: Sequence[Any]) -> str:
    """An opaque cursor of the sort key values of the last row of a page, bound to ``sort``."""
    raw = json.dumps({"s": sort, "v": [_tagged(v) for v in values]}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(cursor: str, sort: str, n_values: int) -> List[Tuple[Any, str]]:
    """The ``(value, type)`` pairs of a cursor made with ``encode_cursor`` for the same sort order; ``Invalid``
    otherwise (a cursor is only valid with the sort it was made with)."""
    if not cursor or len(cursor) > CURSOR_MAX:
        raise Invalid("invalid cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        values = [(v, t) for v, t in data["v"]]
        if data["s"] != sort:
            raise Invalid(f"the cursor was made with sort {data['s']!r}, not {sort!r}")
        if len(values) != n_values or any(t not in _CASTS and t != "null" for _, t in values):
            raise Invalid("invalid cursor")
        return values
    except Invalid:
        raise
    except Exception:
        raise Invalid("invalid cursor") from None


def keyset_condition(columns: Sequence[Tuple[str, bool]], values: List[Tuple[Any, str]], binds: Dict[str, Any],
                     prefix: str = "ks") -> str:
    """The SQL condition "rows after the cursor" for ``ORDER BY c0 [DESC] NULLS LAST, c1 [DESC] NULLS LAST, ...``
    (``columns``: ``(expression, descending)``; every key sorts NULLS LAST, as the list services order). The
    bind values are added to ``binds`` (``prefix0``, ``prefix1``, ...)."""
    if len(columns) != len(values):
        raise Invalid("invalid cursor")
    clauses = []
    for i, ((expr, desc), (value, kind)) in enumerate(zip(columns, values)):
        equal_before = " AND ".join(_equal(columns[j][0], values[j], binds, f"{prefix}{j}") for j in range(i))
        if kind == "null":
            # the row was in the NULL tail of this key: only rows that are NULL here too can follow
            strict = f"{expr} IS NULL"
            if i == len(columns) - 1:
                continue        # a NULL last key cannot order anything after it
            clauses.append("(" + (equal_before + " AND " if equal_before else "") + strict + " AND (" +
                           _tail(columns, values, binds, prefix, i + 1) + "))")
            break
        name = f"{prefix}{i}"
        binds[name] = value
        cast = f"CAST(:{name} AS {_CASTS[kind]})"
        op = "<" if desc else ">"
        # NULLS LAST: a non-NULL key is followed by greater (ASC) / smaller (DESC) values and then the NULLs
        strict = f"({expr} {op} {cast} OR {expr} IS NULL)"
        clauses.append("(" + (equal_before + " AND " if equal_before else "") + strict + ")")
    return "(" + " OR ".join(clauses) + ")" if clauses else "false"


def _equal(expr: str, tagged: Tuple[Any, str], binds: Dict[str, Any], name: str) -> str:
    value, kind = tagged
    if kind == "null":
        return f"{expr} IS NULL"
    binds[name] = value
    return f"{expr} = CAST(:{name} AS {_CASTS[kind]})"


def _tail(columns, values, binds, prefix, start) -> str:
    return keyset_condition(list(columns[start:]), list(values[start:]), binds, prefix=f"{prefix}t{start}_")


def parse_timestamp(value, name: str = "timestamp") -> str:
    """An ISO 8601 date / timestamp (``2026-05-01``, ``2026-05-01T10:00:00Z``) for a
    ``CAST(:x AS timestamptz)`` bind; anything else is ``Invalid`` (not a 500 from Postgres)."""
    from services.errors import Invalid

    if isinstance(value, (datetime, date)):
        return value.isoformat()
    try:
        return datetime.fromisoformat(str(value).strip()).isoformat()
    except ValueError:
        raise Invalid(f"{name} must be an ISO 8601 date or timestamp, got {str(value)[:50]!r}") from None


def as_ints(values, name: str = "id") -> list:
    """Integers of a filter value (one or a list); anything else is ``Invalid``."""
    from services.errors import Invalid

    try:
        out = []
        for v in as_list(values):
            if isinstance(v, bool) or (isinstance(v, float) and not v.is_integer()):
                raise ValueError(v)
            out.append(int(v))
        return out
    except (TypeError, ValueError):
        raise Invalid(f"{name} must be an integer or a list of integers") from None


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def as_list(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def group_condition(column: str, prefix: str, binds: Dict[str, Any], name: str = "group") -> str:
    """``group=<prefix>`` (contract 7): a GitLab group is a prefix of ``full_path`` - the project at that path or
    any project below it (``grp/payments`` matches ``grp/payments/ledger``, not ``grp/payments-old``)."""
    prefix = str(prefix).strip().strip("/")
    if not prefix:
        raise Invalid("group must be a non-empty path prefix")
    binds[name] = prefix
    binds[f"{name}_like"] = escape_like(prefix) + "/%"
    return f"({column} = :{name} OR {column} LIKE :{name}_like ESCAPE '\\')"
