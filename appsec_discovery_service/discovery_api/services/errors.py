"""Errors of the API services; REST maps them to HTTP statuses, MCP to tool errors."""


class ServiceError(Exception):
    status_code = 400


class NotFound(ServiceError):
    status_code = 404


class Conflict(ServiceError):
    status_code = 409


class Invalid(ServiceError):
    status_code = 422


class Forbidden(ServiceError):
    status_code = 403


class TooLarge(ServiceError):
    status_code = 413


class TooManyRequests(ServiceError):
    """A budget is used up (prompt trials: LLM_TRIAL_DAILY_CALLS model calls per day)."""
    status_code = 429
