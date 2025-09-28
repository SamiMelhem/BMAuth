"""
Background tasks module for authentication system maintenance.

This module provides background task scheduling and execution for
database maintenance, cleanup, and optimization tasks.
"""

from .scheduler import (
    BackgroundTaskScheduler,
    start_background_tasks,
    stop_background_tasks,
)

__all__ = [
    "BackgroundTaskScheduler",
    "start_background_tasks",
    "stop_background_tasks",
]