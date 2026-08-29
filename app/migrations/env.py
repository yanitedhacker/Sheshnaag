from __future__ import annotations

import logging
from logging.config import fileConfig

from alembic import context
from alembic.script import ScriptDirectory
from sqlalchemy import engine_from_config, inspect, pool

from app.core.config import settings
from app.core.database import Base
from app.migrations.bootstrap import create_current_schema_snapshot
import app.models  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata
logger = logging.getLogger("alembic.env")


def _is_upgrade_to_head() -> bool:
    options = getattr(config, "cmd_opts", None)
    command = getattr(options, "cmd", None)
    command_name = (
        getattr(command[0], "__name__", "")
        if isinstance(command, tuple) and command
        else ""
    )
    return command_name == "upgrade" and getattr(options, "revision", None) in {
        "head",
        "heads",
    }


def get_url() -> str:
    return settings.database_url


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        upgrade_to_head = _is_upgrade_to_head()
        existing_application_tables: set[str] | None = None
        if upgrade_to_head:
            existing_application_tables = {
                name
                for name in inspect(connection).get_table_names()
                if name != "alembic_version"
            }
            # SQLAlchemy 2 starts a transaction for reflection. End that
            # read-only transaction before Alembic owns migration commits.
            connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        bootstrapped_empty_database = False
        with context.begin_transaction():
            if existing_application_tables == set() and upgrade_to_head:
                logger.info(
                    "Empty database detected; creating the current schema "
                    "snapshot and stamping Alembic head."
                )
                script = ScriptDirectory.from_config(config)
                heads = script.get_heads()
                if len(heads) != 1:
                    raise RuntimeError(
                        f"fresh_database_requires_single_alembic_head:{heads}"
                    )
                create_current_schema_snapshot(connection, target_metadata)
                context.get_context().stamp(script, heads[0])
                bootstrapped_empty_database = True
            else:
                context.run_migrations()
        if bootstrapped_empty_database:
            # SQLite treats DDL as non-transactional, but the version-row
            # INSERT is transactional. Commit both parts before the
            # connection closes so the schema and its Alembic head agree.
            connection.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
