#!/usr/bin/env python3

"""
Migration: Add reasoning_effort field to llm_providers table

Adds reasoning effort configuration to enable extended thinking/reasoning
for supported LLM providers (Anthropic, OpenAI o1/o3, etc.).
"""

import sqlite3

from src.ida_compat import log


def migrate_add_reasoning_effort(db_path: str):
    """
    Add reasoning_effort column to llm_providers table.

    Column stores reasoning effort level: 'none', 'low', 'medium', 'high'
    Default is 'none' for backward compatibility.

    Migration is idempotent - safe to run multiple times.

    Args:
        db_path: Path to settings database
    """
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        # Check if column already exists
        cursor.execute("PRAGMA table_info(llm_providers)")
        columns = [col[1] for col in cursor.fetchall()]

        if 'reasoning_effort' not in columns:
            # Add the reasoning_effort column with default 'none'
            cursor.execute('''
                ALTER TABLE llm_providers
                ADD COLUMN reasoning_effort TEXT DEFAULT 'none'
            ''')

            conn.commit()
            log.log_info("Added reasoning_effort column to llm_providers table")

            # Count providers that will be affected
            cursor.execute('SELECT COUNT(*) FROM llm_providers')
            provider_count = cursor.fetchone()[0]

            if provider_count > 0:
                log.log_info(f"Existing {provider_count} provider(s) will default to reasoning_effort='none'")
        else:
            log.log_debug("reasoning_effort column already exists, skipping migration")

    except Exception as e:
        conn.rollback()
        log.log_error(f"Migration add_reasoning_effort failed: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    # Test migration
    import os
    from src.ida_compat import get_user_data_dir

    db_path = os.path.join(get_user_data_dir(), 'settings.db')

    if os.path.exists(db_path):
        migrate_add_reasoning_effort(db_path)
    else:
        log.log_error(f"Settings database not found at: {db_path}")
