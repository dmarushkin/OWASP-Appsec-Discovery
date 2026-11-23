"""discovery_scanner entry point (P2-4).

The old multiprocessing Manager dicts / queue (update_projects, update_branches_mrs,
pull_code, scan_all, llm_score, clean_cache loops) are replaced by the Postgres job queue
(``jobs`` table, ``discovery_common.jobs``): ``supervisor.Supervisor`` runs the scheduler
(GitLab polling, cleanup) and supervises the worker processes, which run the handlers of
``services.job_handlers``.
"""

import sys

from pydantic import ValidationError

from config import format_settings_error, get_settings
from logger import get_logger

logger = get_logger(__name__)


def main() -> int:

    try:
        settings = get_settings()
    except ValidationError as e:
        logger.error(f"Invalid scanner configuration (check env variables):\n{format_settings_error(e)}")
        return 2

    from services.db_service import init_db
    from supervisor import Scheduler, Supervisor

    # The schema is migrated by the one-shot discovery_migrate service (Alembic); here we
    # only wait for the database and check that it is migrated.
    init_db()

    Supervisor(settings, scheduler=Scheduler(settings)).run()
    return 0


if __name__ == "__main__":

    logger.info("Starting application...")

    sys.exit(main())
