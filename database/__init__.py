"""
Database optimization and partitioning module.

This module provides automatic database partitioning, indexing optimization,
and performance management for scalable authentication systems.
"""

from .partitioning import (
    DatabasePartitionManager,
    DatabaseOptimizer,
    PartitionInterval,
    run_database_maintenance,
    initialize_database_optimization,
)

__all__ = [
    "DatabasePartitionManager",
    "DatabaseOptimizer",
    "PartitionInterval",
    "run_database_maintenance",
    "initialize_database_optimization",
]