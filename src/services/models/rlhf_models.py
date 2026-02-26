#!/usr/bin/env python3

from typing import Optional
from dataclasses import dataclass
import json


@dataclass
class RLHFFeedbackEntry:
    """Data model for RLHF feedback entries"""
    model_name: str
    prompt: str
    system: str
    response: str
    feedback: bool  # True for upvote, False for downvote
    timestamp: str
    metadata: str  # JSON string containing binary metadata
    id: Optional[int] = None  # Database primary key

    def to_dict(self) -> dict:
        """Convert to dictionary for database operations"""
        return {
            'id': self.id,
            'model_name': self.model_name,
            'prompt': self.prompt,
            'system': self.system,
            'response': self.response,
            'feedback': 1 if self.feedback else 0,
            'timestamp': self.timestamp,
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'RLHFFeedbackEntry':
        """Create instance from database row dictionary"""
        return cls(
            id=data.get('id'),
            model_name=data['model_name'],
            prompt=data['prompt'],
            system=data['system'],
            response=data['response'],
            feedback=bool(data['feedback']),
            timestamp=data['timestamp'],
            metadata=data['metadata']
        )

    def get_metadata_dict(self) -> dict:
        """Parse metadata JSON string to dictionary"""
        try:
            return json.loads(self.metadata)
        except (json.JSONDecodeError, TypeError):
            return {}

    @staticmethod
    def create_metadata_json(filename: str, size: int, sha256: str) -> str:
        """Create metadata JSON string from binary info"""
        return json.dumps({
            'filename': filename,
            'size': size,
            'sha256': sha256
        })
