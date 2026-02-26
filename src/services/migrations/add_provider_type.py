#!/usr/bin/env python3

"""
Migration: Add provider_type field to llm_providers table
"""

import sqlite3
from typing import Dict, Any
from ..models.provider_types import ProviderType

from src.ida_compat import log

def migrate_add_provider_type(db_path: str):
    """
    Add provider_type column to llm_providers table and populate with detected types
    """
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        # Check if column already exists
        cursor.execute("PRAGMA table_info(llm_providers)")
        columns = [col[1] for col in cursor.fetchall()]

        if 'provider_type' not in columns:
            # Add the provider_type column
            cursor.execute('''
                ALTER TABLE llm_providers
                ADD COLUMN provider_type TEXT DEFAULT 'openai_platform'
            ''')

            # Update existing providers with detected types
            cursor.execute('SELECT id, name, url FROM llm_providers')
            providers = cursor.fetchall()

            for provider_id, name, url in providers:
                detected_type = _detect_provider_type(name, url)
                cursor.execute('''
                    UPDATE llm_providers
                    SET provider_type = ?
                    WHERE id = ?
                ''', (detected_type.value, provider_id))

            conn.commit()
            log.log_info(f"Added provider_type column and updated {len(providers)} existing providers")
        else:
            log.log_info("provider_type column already exists, skipping migration")

    except Exception as e:
        conn.rollback()
        log.log_error(f"Migration failed: {e}")
        raise
    finally:
        conn.close()


def _detect_provider_type(name: str, url: str) -> ProviderType:
    """
    Detect provider type from name and URL for migration purposes
    """
    name_lower = name.lower() if name else ''
    url_lower = url.lower() if url else ''

    if 'openai.com' in url_lower or 'openai' in name_lower:
        return ProviderType.OPENAI_PLATFORM
    elif 'anthropic.com' in url_lower or 'claude' in name_lower or 'anthropic' in name_lower:
        return ProviderType.ANTHROPIC_PLATFORM
    elif ':11434' in url_lower or 'ollama' in name_lower or 'ollama' in url_lower:
        return ProviderType.OLLAMA
    elif 'openwebui' in name_lower or 'open-webui' in name_lower:
        return ProviderType.OPENWEBUI
    elif 'lmstudio' in name_lower or ':1234' in url_lower:
        return ProviderType.LMSTUDIO
    else:
        # Default to OpenAI for unknown providers
        return ProviderType.OPENAI_PLATFORM


if __name__ == "__main__":
    # Test migration
    import os
    from src.ida_compat import get_user_data_dir

    db_path = os.path.join(get_user_data_dir(), 'settings.db')
    if os.path.exists(db_path):
        migrate_add_provider_type(db_path)
    else:
        log.log_error("Settings database not found")
