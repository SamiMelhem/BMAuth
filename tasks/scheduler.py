"""
Background task scheduler for database maintenance and optimization.

This module provides automated scheduling of database maintenance tasks,
cleanup operations, and performance optimization routines.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass

from app.config.scaling import get_scaling_config
from app.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


@dataclass
class ScheduledTask:
    """Represents a scheduled background task."""
    name: str
    func: Callable
    interval_seconds: int
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    enabled: bool = True
    running: bool = False

    def __post_init__(self):
        """Calculate next run time after initialization."""
        if self.next_run is None:
            self.next_run = datetime.now() + timedelta(seconds=self.interval_seconds)

    def should_run(self) -> bool:
        """Check if task should run now."""
        return (
            self.enabled
            and not self.running
            and self.next_run is not None
            and datetime.now() >= self.next_run
        )

    def mark_completed(self):
        """Mark task as completed and schedule next run."""
        self.last_run = datetime.now()
        self.next_run = self.last_run + timedelta(seconds=self.interval_seconds)
        self.running = False

    def mark_started(self):
        """Mark task as started."""
        self.running = True


class BackgroundTaskScheduler:
    """Manages background task scheduling and execution."""

    def __init__(self):
        """Initialize task scheduler."""
        self.tasks: Dict[str, ScheduledTask] = {}
        self.running = False
        self.config = get_scaling_config()
        self._setup_default_tasks()

    def _setup_default_tasks(self):
        """Set up default maintenance tasks based on configuration."""
        # Database maintenance task
        self.add_task(
            name="database_maintenance",
            func=self._run_database_maintenance,
            interval_seconds=self.config.session_cleanup_interval
        )

        # Session cleanup task
        self.add_task(
            name="session_cleanup",
            func=self._run_session_cleanup,
            interval_seconds=max(300, self.config.session_cleanup_interval // 4)  # More frequent
        )

        # Future partition creation task (daily)
        if self.config.enable_partitioning:
            self.add_task(
                name="partition_maintenance",
                func=self._run_partition_maintenance,
                interval_seconds=86400  # Daily
            )

        # Risk score cleanup task
        self.add_task(
            name="risk_score_cleanup",
            func=self._run_risk_score_cleanup,
            interval_seconds=3600  # Hourly
        )

        # Statistics update task
        self.add_task(
            name="statistics_update",
            func=self._run_statistics_update,
            interval_seconds=1800  # Every 30 minutes
        )

    def add_task(self, name: str, func: Callable, interval_seconds: int, enabled: bool = True):
        """Add a new scheduled task."""
        task = ScheduledTask(
            name=name,
            func=func,
            interval_seconds=interval_seconds,
            enabled=enabled
        )
        self.tasks[name] = task
        logger.info(f"Added background task: {name} (interval: {interval_seconds}s)")

    def remove_task(self, name: str):
        """Remove a scheduled task."""
        if name in self.tasks:
            del self.tasks[name]
            logger.info(f"Removed background task: {name}")

    def enable_task(self, name: str):
        """Enable a scheduled task."""
        if name in self.tasks:
            self.tasks[name].enabled = True
            logger.info(f"Enabled background task: {name}")

    def disable_task(self, name: str):
        """Disable a scheduled task."""
        if name in self.tasks:
            self.tasks[name].enabled = False
            logger.info(f"Disabled background task: {name}")

    async def start(self):
        """Start the task scheduler."""
        if self.running:
            logger.warning("Task scheduler is already running")
            return

        self.running = True
        logger.info("Starting background task scheduler")

        while self.running:
            try:
                # Check and run tasks that are due
                for task in list(self.tasks.values()):
                    if task.should_run():
                        await self._execute_task(task)

                # Sleep for a short interval before checking again
                await asyncio.sleep(10)  # Check every 10 seconds

            except asyncio.CancelledError:
                logger.info("Task scheduler cancelled")
                break
            except Exception as e:
                logger.error(f"Error in task scheduler: {e}")
                await asyncio.sleep(30)  # Wait longer after errors

        logger.info("Background task scheduler stopped")

    def stop(self):
        """Stop the task scheduler."""
        self.running = False
        logger.info("Stopping background task scheduler")

    async def _execute_task(self, task: ScheduledTask):
        """Execute a single task."""
        logger.debug(f"Executing background task: {task.name}")
        task.mark_started()

        try:
            await task.func()
            task.mark_completed()
            logger.debug(f"Task completed successfully: {task.name}")
        except Exception as e:
            logger.error(f"Task failed: {task.name} - {e}")
            task.mark_completed()  # Still mark as completed to avoid getting stuck

    async def _run_database_maintenance(self):
        """Run database maintenance tasks."""
        try:
            from app.database.partitioning import run_database_maintenance

            async with AsyncSessionLocal() as session:
                await run_database_maintenance(session)
        except Exception as e:
            logger.error(f"Database maintenance failed: {e}")

    async def _run_session_cleanup(self):
        """Clean up expired sessions and tokens."""
        try:
            async with AsyncSessionLocal() as session:
                # Clean up expired WebAuthn challenges
                from sqlalchemy import text
                await session.execute(
                    text("DELETE FROM webauthn_challenges WHERE expires_at < NOW()")
                )

                # Clean up expired sessions if using session table
                if self.config.enable_partitioning:
                    await session.execute(
                        text("DELETE FROM user_sessions_partitioned WHERE expires_at < NOW() - INTERVAL '1 day'")
                    )

                await session.commit()
                logger.debug("Session cleanup completed")
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")

    async def _run_partition_maintenance(self):
        """Run partition maintenance tasks."""
        try:
            from app.database.partitioning import DatabasePartitionManager

            async with AsyncSessionLocal() as session:
                manager = DatabasePartitionManager(session)
                await manager.create_future_partitions()
                await manager.cleanup_old_partitions()
                logger.debug("Partition maintenance completed")
        except Exception as e:
            logger.error(f"Partition maintenance failed: {e}")

    async def _run_risk_score_cleanup(self):
        """Clean up and recalculate risk scores."""
        try:
            async with AsyncSessionLocal() as session:
                # Reset risk scores for old events
                from sqlalchemy import text
                await session.execute(
                    text("""
                    UPDATE webauthn_credentials
                    SET risk_score = GREATEST(0, risk_score - 1)
                    WHERE updated_at < NOW() - INTERVAL '7 days'
                    AND risk_score > 0
                    """)
                )
                await session.commit()
                logger.debug("Risk score cleanup completed")
        except Exception as e:
            logger.error(f"Risk score cleanup failed: {e}")

    async def _run_statistics_update(self):
        """Update database statistics for query optimization."""
        try:
            async with AsyncSessionLocal() as session:
                from sqlalchemy import text
                # Update table statistics (PostgreSQL specific)
                await session.execute(text("ANALYZE"))
                await session.commit()
                logger.debug("Statistics update completed")
        except Exception as e:
            logger.debug(f"Statistics update failed (may not be PostgreSQL): {e}")

    def get_task_status(self) -> Dict[str, Any]:
        """Get status of all scheduled tasks."""
        status = {
            "scheduler_running": self.running,
            "total_tasks": len(self.tasks),
            "enabled_tasks": sum(1 for task in self.tasks.values() if task.enabled),
            "tasks": {}
        }

        for name, task in self.tasks.items():
            status["tasks"][name] = {
                "enabled": task.enabled,
                "running": task.running,
                "interval_seconds": task.interval_seconds,
                "last_run": task.last_run.isoformat() if task.last_run else None,
                "next_run": task.next_run.isoformat() if task.next_run else None,
                "next_run_in_seconds": (
                    int((task.next_run - datetime.now()).total_seconds())
                    if task.next_run else None
                )
            }

        return status


# Global task scheduler instance
_task_scheduler: Optional[BackgroundTaskScheduler] = None
_scheduler_task: Optional[asyncio.Task] = None


async def start_background_tasks():
    """Start the global background task scheduler."""
    global _task_scheduler, _scheduler_task

    if _task_scheduler is not None and _task_scheduler.running:
        logger.warning("Background tasks are already running")
        return

    _task_scheduler = BackgroundTaskScheduler()

    # Start the scheduler in a background task
    _scheduler_task = asyncio.create_task(_task_scheduler.start())
    logger.info("Background tasks started")


async def stop_background_tasks():
    """Stop the global background task scheduler."""
    global _task_scheduler, _scheduler_task

    if _task_scheduler is not None:
        _task_scheduler.stop()

    if _scheduler_task is not None:
        _scheduler_task.cancel()
        try:
            await _scheduler_task
        except asyncio.CancelledError:
            pass
        _scheduler_task = None

    _task_scheduler = None
    logger.info("Background tasks stopped")


def get_task_scheduler() -> Optional[BackgroundTaskScheduler]:
    """Get the global task scheduler instance."""
    return _task_scheduler


# Convenience functions for manual task execution
async def run_maintenance_now():
    """Manually trigger database maintenance."""
    try:
        from app.database.partitioning import run_database_maintenance

        async with AsyncSessionLocal() as session:
            results = await run_database_maintenance(session)
            logger.info(f"Manual maintenance completed: {results}")
            return results
    except Exception as e:
        logger.error(f"Manual maintenance failed: {e}")
        raise


async def run_cleanup_now():
    """Manually trigger cleanup tasks."""
    try:
        async with AsyncSessionLocal() as session:
            from sqlalchemy import text

            # Clean up expired challenges
            result1 = await session.execute(
                text("DELETE FROM webauthn_challenges WHERE expires_at < NOW()")
            )

            # Clean up old sessions if partitioned table exists
            try:
                result2 = await session.execute(
                    text("DELETE FROM user_sessions_partitioned WHERE expires_at < NOW() - INTERVAL '1 day'")
                )
            except Exception:
                result2 = None

            await session.commit()

            results = {
                "challenges_cleaned": result1.rowcount if result1 else 0,
                "sessions_cleaned": result2.rowcount if result2 else 0
            }

            logger.info(f"Manual cleanup completed: {results}")
            return results
    except Exception as e:
        logger.error(f"Manual cleanup failed: {e}")
        raise