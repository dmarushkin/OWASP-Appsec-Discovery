"""``python -m discovery_common.migrate [revision]`` - wait for the database, then run
``alembic upgrade`` (default ``head``). Used by the one-shot ``discovery_migrate`` compose
service; the scanner and the API start only after it completed successfully.

A database created by the old ``create_all`` startup has no ``alembic_version`` table:
the idempotent baseline revision adopts it (see ``0001_baseline``).
"""

import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

from discovery_common import db
from discovery_common.log import get_logger

logger = get_logger(__name__)

ALEMBIC_INI = Path(__file__).resolve().parent / "alembic.ini"


def alembic_config() -> Config:
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_INI.parent / "migrations"))
    return config


def upgrade(url: str = None, revision: str = "head", wait_timeout: float = 120.0) -> None:
    if url:
        db.configure(url)
    db.wait_for_db(timeout=wait_timeout)
    config = alembic_config()
    with db.get_engine().begin() as connection:
        config.attributes["connection"] = connection
        before = db.schema_revision(connection)
        logger.info(f"Database schema revision: {before or 'none (legacy or empty database)'}; upgrading to {revision}")
        command.upgrade(config, revision)
    logger.info(f"Database schema is at {db.schema_revision()}")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    upgrade(revision=argv[0] if argv else "head")
    return 0


if __name__ == "__main__":
    sys.exit(main())
