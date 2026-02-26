#!/usr/bin/env python3

import sqlite3
import threading
import os
from typing import List, Optional
from datetime import datetime
from .models.rlhf_models import RLHFFeedbackEntry

from src.ida_compat import log, get_user_data_dir


class RLHFService:
    """
    Service for handling RLHF (Reinforcement Learning from Human Feedback) data.
    Manages feedback storage and retrieval from SQLite database.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern for thread-safe service instance"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._db_path = None
        self._db_lock = threading.Lock()
        self._initialized = True

        # Initialize database
        self._ensure_database_exists()

    def _get_database_path(self) -> str:
        """Get database path - follows same pattern as AnalysisDBService"""
        if not self._db_path:
            try:
                idassist_dir = get_user_data_dir()

                # Use same database as AnalysisDBService for consistency
                self._db_path = os.path.join(idassist_dir, 'analysis.db')

            except Exception as e:
                log.log_error(f"Failed to determine RLHF database path: {e}")
                # Fallback to current directory
                self._db_path = 'idassist_rlhf.db'

        return self._db_path

    def _ensure_database_exists(self):
        """Ensure database exists and create feedback table if needed"""
        conn = None
        try:
            with self._db_lock:
                conn = sqlite3.connect(self._get_database_path())
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS feedback (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        model_name TEXT NOT NULL,
                        prompt TEXT NOT NULL,
                        system TEXT NOT NULL,
                        response TEXT NOT NULL,
                        feedback INTEGER NOT NULL,
                        timestamp TEXT NOT NULL,
                        metadata TEXT
                    )
                ''')
                conn.commit()
                log.log_info("RLHF feedback table initialized")
        except Exception as e:
            log.log_error(f"Failed to initialize RLHF database: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def store_feedback(self, feedback_entry: RLHFFeedbackEntry) -> bool:
        """
        Store feedback entry in database

        Args:
            feedback_entry: RLHFFeedbackEntry instance to store

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Set timestamp if not provided
            if not feedback_entry.timestamp:
                feedback_entry.timestamp = datetime.now().isoformat()

            with self._db_lock:
                with sqlite3.connect(self._get_database_path()) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO feedback (model_name, prompt, system, response, feedback, timestamp, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        feedback_entry.model_name,
                        feedback_entry.prompt,
                        feedback_entry.system,
                        feedback_entry.response,
                        1 if feedback_entry.feedback else 0,
                        feedback_entry.timestamp,
                        feedback_entry.metadata
                    ))

                    feedback_entry.id = cursor.lastrowid
                    conn.commit()

                    log.log_info(f"Stored RLHF feedback: {feedback_entry.id} ({feedback_entry.model_name})")
                    return True

        except Exception as e:
            log.log_error(f"Failed to store RLHF feedback: {e}")
            return False

    def get_feedback_entries(self, limit: Optional[int] = None, model_name: Optional[str] = None) -> List[RLHFFeedbackEntry]:
        """
        Retrieve feedback entries from database

        Args:
            limit: Maximum number of entries to return
            model_name: Filter by specific model name

        Returns:
            List of RLHFFeedbackEntry instances
        """
        try:
            with self._db_lock:
                with sqlite3.connect(self._get_database_path()) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    query = "SELECT * FROM feedback"
                    params = []

                    if model_name:
                        query += " WHERE model_name = ?"
                        params.append(model_name)

                    query += " ORDER BY timestamp DESC"

                    if limit:
                        query += " LIMIT ?"
                        params.append(limit)

                    cursor.execute(query, params)
                    rows = cursor.fetchall()

                    return [RLHFFeedbackEntry.from_dict(dict(row)) for row in rows]

        except Exception as e:
            log.log_error(f"Failed to retrieve RLHF feedback entries: {e}")
            return []

    def get_feedback_stats(self) -> dict:
        """
        Get basic statistics about stored feedback

        Returns:
            dict: Statistics including total entries, upvotes, downvotes
        """
        try:
            with self._db_lock:
                with sqlite3.connect(self._get_database_path()) as conn:
                    cursor = conn.cursor()

                    # Get total count
                    cursor.execute("SELECT COUNT(*) FROM feedback")
                    total = cursor.fetchone()[0]

                    # Get upvotes count
                    cursor.execute("SELECT COUNT(*) FROM feedback WHERE feedback = 1")
                    upvotes = cursor.fetchone()[0]

                    # Get downvotes count
                    cursor.execute("SELECT COUNT(*) FROM feedback WHERE feedback = 0")
                    downvotes = cursor.fetchone()[0]

                    # Get unique models
                    cursor.execute("SELECT COUNT(DISTINCT model_name) FROM feedback")
                    unique_models = cursor.fetchone()[0]

                    return {
                        'total_entries': total,
                        'upvotes': upvotes,
                        'downvotes': downvotes,
                        'unique_models': unique_models
                    }

        except Exception as e:
            log.log_error(f"Failed to get RLHF feedback stats: {e}")
            return {
                'total_entries': 0,
                'upvotes': 0,
                'downvotes': 0,
                'unique_models': 0
            }


# Global service instance
rlhf_service = RLHFService()
