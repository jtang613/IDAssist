#!/usr/bin/env python3

"""
Migration: Add LiteLLM-specific configuration fields to llm_providers table
"""

import sqlite3

from src.ida_compat import log


def migrate_add_litellm_configs(db_path: str):
    """
    Add LiteLLM-specific configuration fields to llm_providers table.

    New fields:
    - model_family: Detected model family (anthropic, amazon, meta, etc.)
    - is_bedrock: Boolean flag for Bedrock models
    - litellm_params: JSON field for LiteLLM-specific parameters
    """
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        # Check if columns exist
        cursor.execute("PRAGMA table_info(llm_providers)")
        columns = [col[1] for col in cursor.fetchall()]

        changes_made = False

        if 'model_family' not in columns:
            cursor.execute('''
                ALTER TABLE llm_providers
                ADD COLUMN model_family TEXT DEFAULT 'unknown'
            ''')
            log.log_info("Added model_family column to llm_providers")
            changes_made = True

        if 'is_bedrock' not in columns:
            cursor.execute('''
                ALTER TABLE llm_providers
                ADD COLUMN is_bedrock BOOLEAN DEFAULT 0
            ''')
            log.log_info("Added is_bedrock column to llm_providers")
            changes_made = True

        if 'litellm_params' not in columns:
            cursor.execute('''
                ALTER TABLE llm_providers
                ADD COLUMN litellm_params TEXT DEFAULT '{}'
            ''')
            log.log_info("Added litellm_params column to llm_providers")
            changes_made = True

        if changes_made:
            conn.commit()
            log.log_info("LiteLLM configuration migration completed successfully")
        else:
            log.log_info("LiteLLM columns already exist, skipping migration")

    except Exception as e:
        conn.rollback()
        log.log_error(f"LiteLLM migration failed: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    # Test migration
    import os
    from src.ida_compat import get_user_data_dir

    db_path = os.path.join(get_user_data_dir(), 'settings.db')
    if os.path.exists(db_path):
        migrate_add_litellm_configs(db_path)
    else:
        log.log_error("Settings database not found")
