#!/usr/bin/env python3

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional


class UpdateType(Enum):
    INCREMENTAL = auto()
    FULL_REPLACE = auto()


@dataclass(frozen=True)
class RenderUpdate:
    update_type: UpdateType
    committed_html: Optional[str]
    pending_html: Optional[str]
    full_html: Optional[str]

    @classmethod
    def incremental(cls, committed_html: str, pending_html: str) -> "RenderUpdate":
        return cls(
            update_type=UpdateType.INCREMENTAL,
            committed_html=committed_html,
            pending_html=pending_html,
            full_html=None,
        )

    @classmethod
    def full_replace(cls, full_html: str) -> "RenderUpdate":
        return cls(
            update_type=UpdateType.FULL_REPLACE,
            committed_html=None,
            pending_html=None,
            full_html=full_html,
        )
