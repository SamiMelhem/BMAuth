"""
Database partitioning and optimization system for scalable authentication.

This module provides automatic database partitioning, indexing optimization,
and query performance enhancements that scale to millions of users.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum

from sqlalchemy import text, inspect, Index
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from app.config.scaling import get_scaling_config, ScaleLevel

logger = logging.getLogger(__name__)


class PartitionInterval(Enum):
    """Supported partition intervals."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    YEARLY = "yearly"


class DatabasePartitionManager:
    """Manages automatic database partitioning for scalable performance."""

    def __init__(self, db_session: AsyncSession):
        """Initialize partition manager with database session."""
        self.db = db_session
        self.config = get_scaling_config()

    async def setup_partitioning(self) -> None:
        """Set up initial partitioning based on configuration."""
        if not self.config.enable_partitioning:
            logger.info("Partitioning disabled by configuration")
            return

        logger.info("Setting up database partitioning...")

        # Create partitioned tables for high-volume data
        await self._create_partitioned_auth_events_table()
        await self._create_partitioned_security_logs_table()
        await self._create_partitioned_sessions_table()

        # Create initial partitions
        await self._create_initial_partitions()

        # Set up automatic partition creation
        await self._setup_automatic_partition_creation()

        logger.info("Database partitioning setup completed")

    async def _create_partitioned_auth_events_table(self) -> None:
        """Create partitioned authentication events table."""
        partition_sql = """
        -- Create partitioned authentication events table
        DO $$
        BEGIN
            -- Check if table exists and is already partitioned
            IF NOT EXISTS (
                SELECT 1 FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = 'auth_events_partitioned'
                AND n.nspname = 'public'
            ) THEN
                -- Create the parent partitioned table
                CREATE TABLE auth_events_partitioned (
                    id SERIAL,
                    user_id VARCHAR(36) NOT NULL,
                    event_type VARCHAR(50) NOT NULL,
                    ip_address INET,
                    user_agent TEXT,
                    success BOOLEAN NOT NULL DEFAULT false,
                    failure_reason TEXT,
                    risk_score INTEGER DEFAULT 0,
                    device_fingerprint TEXT,
                    location_country VARCHAR(3),
                    location_city VARCHAR(100),
                    metadata JSONB,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id, created_at)
                ) PARTITION BY RANGE (created_at);

                -- Create indexes on the partitioned table
                CREATE INDEX idx_auth_events_part_user_time ON auth_events_partitioned (user_id, created_at DESC);
                CREATE INDEX idx_auth_events_part_type_time ON auth_events_partitioned (event_type, created_at DESC);
                CREATE INDEX idx_auth_events_part_ip_time ON auth_events_partitioned (ip_address, created_at DESC);
                CREATE INDEX idx_auth_events_part_risk ON auth_events_partitioned (risk_score, created_at DESC);
                CREATE INDEX idx_auth_events_part_success ON auth_events_partitioned (success, created_at DESC);

                -- GIN index for metadata JSONB queries
                CREATE INDEX idx_auth_events_part_metadata ON auth_events_partitioned USING GIN (metadata);
            END IF;
        END $$;
        """

        try:
            await self.db.execute(text(partition_sql))
            await self.db.commit()
            logger.info("Created partitioned auth_events table")
        except Exception as e:
            logger.warning(f"Could not create partitioned auth_events table (may not be PostgreSQL): {e}")
            await self.db.rollback()

    async def _create_partitioned_security_logs_table(self) -> None:
        """Create partitioned security logs table."""
        partition_sql = """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = 'security_logs_partitioned'
                AND n.nspname = 'public'
            ) THEN
                CREATE TABLE security_logs_partitioned (
                    id SERIAL,
                    event_type VARCHAR(50) NOT NULL,
                    description TEXT NOT NULL,
                    user_id VARCHAR(36),
                    ip_address INET,
                    user_agent TEXT,
                    risk_level VARCHAR(20) DEFAULT 'low',
                    metadata JSONB,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id, created_at)
                ) PARTITION BY RANGE (created_at);

                -- Create indexes
                CREATE INDEX idx_security_logs_part_user_time ON security_logs_partitioned (user_id, created_at DESC);
                CREATE INDEX idx_security_logs_part_type_time ON security_logs_partitioned (event_type, created_at DESC);
                CREATE INDEX idx_security_logs_part_risk ON security_logs_partitioned (risk_level, created_at DESC);
                CREATE INDEX idx_security_logs_part_ip ON security_logs_partitioned (ip_address, created_at DESC);
                CREATE INDEX idx_security_logs_part_metadata ON security_logs_partitioned USING GIN (metadata);
            END IF;
        END $$;
        """

        try:
            await self.db.execute(text(partition_sql))
            await self.db.commit()
            logger.info("Created partitioned security_logs table")
        except Exception as e:
            logger.warning(f"Could not create partitioned security_logs table: {e}")
            await self.db.rollback()

    async def _create_partitioned_sessions_table(self) -> None:
        """Create partitioned sessions table for high-volume session tracking."""
        partition_sql = """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = 'user_sessions_partitioned'
                AND n.nspname = 'public'
            ) THEN
                CREATE TABLE user_sessions_partitioned (
                    id VARCHAR(64) NOT NULL,
                    user_id VARCHAR(36) NOT NULL,
                    device_fingerprint TEXT,
                    ip_address INET,
                    user_agent TEXT,
                    is_active BOOLEAN DEFAULT true,
                    risk_score INTEGER DEFAULT 0,
                    last_activity TIMESTAMP WITH TIME ZONE NOT NULL,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id, created_at)
                ) PARTITION BY RANGE (created_at);

                -- Create indexes
                CREATE INDEX idx_sessions_part_user ON user_sessions_partitioned (user_id, created_at DESC);
                CREATE INDEX idx_sessions_part_active ON user_sessions_partitioned (is_active, expires_at);
                CREATE INDEX idx_sessions_part_device ON user_sessions_partitioned (device_fingerprint, created_at DESC);
                CREATE INDEX idx_sessions_part_ip ON user_sessions_partitioned (ip_address, created_at DESC);
            END IF;
        END $$;
        """

        try:
            await self.db.execute(text(partition_sql))
            await self.db.commit()
            logger.info("Created partitioned user_sessions table")
        except Exception as e:
            logger.warning(f"Could not create partitioned sessions table: {e}")
            await self.db.rollback()

    async def _create_initial_partitions(self) -> None:
        """Create initial partitions for current and future periods."""
        interval = PartitionInterval(self.config.partition_interval)

        # Create partitions for the past 3 months, current period, and next 3 periods
        partitions_to_create = self._get_partition_periods(interval, months_back=3, periods_forward=3)

        for table_name in ['auth_events_partitioned', 'security_logs_partitioned', 'user_sessions_partitioned']:
            for period_start, period_end, partition_name in partitions_to_create:
                await self._create_partition(table_name, partition_name, period_start, period_end)

    def _get_partition_periods(self, interval: PartitionInterval, months_back: int = 3, periods_forward: int = 3) -> List[tuple]:
        """Generate partition periods based on interval."""
        periods = []
        now = datetime.now()

        if interval == PartitionInterval.MONTHLY:
            # Start from N months back
            start_date = now.replace(day=1) - timedelta(days=months_back * 31)
            start_date = start_date.replace(day=1)

            for i in range(months_back + periods_forward + 1):
                period_start = start_date.replace(day=1)
                # Calculate next month
                if period_start.month == 12:
                    period_end = period_start.replace(year=period_start.year + 1, month=1)
                else:
                    period_end = period_start.replace(month=period_start.month + 1)

                partition_name = f"{period_start.year}_{period_start.month:02d}"
                periods.append((period_start, period_end, partition_name))

                start_date = period_end

        elif interval == PartitionInterval.WEEKLY:
            # Start from N weeks back
            start_date = now - timedelta(weeks=months_back * 4)
            start_date = start_date - timedelta(days=start_date.weekday())  # Start of week

            for i in range((months_back * 4) + (periods_forward) + 1):
                period_start = start_date
                period_end = start_date + timedelta(days=7)

                # Format: year_week_number
                year, week, _ = period_start.isocalendar()
                partition_name = f"{year}_w{week:02d}"
                periods.append((period_start, period_end, partition_name))

                start_date = period_end

        elif interval == PartitionInterval.DAILY:
            # Start from N days back
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=months_back * 30)

            for i in range((months_back * 30) + periods_forward + 1):
                period_start = start_date
                period_end = start_date + timedelta(days=1)

                partition_name = f"{period_start.year}_{period_start.month:02d}_{period_start.day:02d}"
                periods.append((period_start, period_end, partition_name))

                start_date = period_end

        return periods

    async def _create_partition(self, table_name: str, partition_name: str, start_date: datetime, end_date: datetime) -> None:
        """Create a single partition for a table."""
        partition_table_name = f"{table_name}_{partition_name}"

        create_partition_sql = f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = '{partition_table_name}'
                AND n.nspname = 'public'
            ) THEN
                CREATE TABLE {partition_table_name} PARTITION OF {table_name}
                FOR VALUES FROM ('{start_date.isoformat()}') TO ('{end_date.isoformat()}');
            END IF;
        END $$;
        """

        try:
            await self.db.execute(text(create_partition_sql))
            await self.db.commit()
            logger.debug(f"Created partition {partition_table_name} for period {start_date} to {end_date}")
        except Exception as e:
            logger.warning(f"Could not create partition {partition_table_name}: {e}")
            await self.db.rollback()

    async def _setup_automatic_partition_creation(self) -> None:
        """Set up automatic creation of future partitions."""
        # Create a stored procedure for automatic partition creation
        procedure_sql = """
        CREATE OR REPLACE FUNCTION create_future_partitions()
        RETURNS void AS $$
        DECLARE
            table_name TEXT;
            partition_interval TEXT;
            next_partition_date DATE;
            partition_name TEXT;
            partition_start_date TEXT;
            partition_end_date TEXT;
        BEGIN
            -- Get partition interval from configuration (this would be passed as parameter in real implementation)
            partition_interval := 'monthly'; -- Default, should be configurable

            FOR table_name IN
                SELECT t.table_name
                FROM information_schema.tables t
                WHERE t.table_name LIKE '%_partitioned'
                AND t.table_schema = 'public'
            LOOP
                -- Calculate next partition needed
                IF partition_interval = 'monthly' THEN
                    next_partition_date := date_trunc('month', CURRENT_DATE) + interval '2 months';
                    partition_name := to_char(next_partition_date, 'YYYY_MM');
                    partition_start_date := to_char(next_partition_date, 'YYYY-MM-DD');
                    partition_end_date := to_char(next_partition_date + interval '1 month', 'YYYY-MM-DD');
                ELSIF partition_interval = 'weekly' THEN
                    next_partition_date := date_trunc('week', CURRENT_DATE) + interval '2 weeks';
                    partition_name := to_char(next_partition_date, 'YYYY_"w"WW');
                    partition_start_date := to_char(next_partition_date, 'YYYY-MM-DD');
                    partition_end_date := to_char(next_partition_date + interval '1 week', 'YYYY-MM-DD');
                ELSIF partition_interval = 'daily' THEN
                    next_partition_date := CURRENT_DATE + interval '2 days';
                    partition_name := to_char(next_partition_date, 'YYYY_MM_DD');
                    partition_start_date := to_char(next_partition_date, 'YYYY-MM-DD');
                    partition_end_date := to_char(next_partition_date + interval '1 day', 'YYYY-MM-DD');
                END IF;

                -- Create partition if it doesn't exist
                EXECUTE format('
                    CREATE TABLE IF NOT EXISTS %I_%s PARTITION OF %I
                    FOR VALUES FROM (%L) TO (%L)',
                    table_name, partition_name, table_name,
                    partition_start_date, partition_end_date
                );

                RAISE NOTICE 'Created partition %_%', table_name, partition_name;
            END LOOP;
        END;
        $$ LANGUAGE plpgsql;
        """

        try:
            await self.db.execute(text(procedure_sql))
            await self.db.commit()
            logger.info("Created automatic partition creation procedure")
        except Exception as e:
            logger.warning(f"Could not create partition procedure: {e}")
            await self.db.rollback()

    async def create_future_partitions(self) -> None:
        """Manually trigger creation of future partitions."""
        try:
            await self.db.execute(text("SELECT create_future_partitions()"))
            await self.db.commit()
            logger.info("Created future partitions")
        except Exception as e:
            logger.error(f"Failed to create future partitions: {e}")
            await self.db.rollback()

    async def cleanup_old_partitions(self, retention_days: int = None) -> None:
        """Clean up old partitions based on retention policy."""
        if retention_days is None:
            retention_days = self.config.event_retention_days

        cutoff_date = datetime.now() - timedelta(days=retention_days)

        # Get list of partitions older than cutoff date
        old_partitions_sql = """
        SELECT schemaname, tablename
        FROM pg_tables
        WHERE tablename LIKE '%_partitioned_%'
        AND schemaname = 'public'
        """

        try:
            result = await self.db.execute(text(old_partitions_sql))
            partitions = result.fetchall()

            for schema, table_name in partitions:
                # Extract date from partition name and check if it's old enough
                if await self._should_drop_partition(table_name, cutoff_date):
                    await self._drop_partition(table_name)

            await self.db.commit()
            logger.info(f"Cleaned up old partitions older than {retention_days} days")
        except Exception as e:
            logger.error(f"Failed to cleanup old partitions: {e}")
            await self.db.rollback()

    async def _should_drop_partition(self, table_name: str, cutoff_date: datetime) -> bool:
        """Check if a partition should be dropped based on its date."""
        # Extract date from table name (format: tablename_YYYY_MM or similar)
        parts = table_name.split('_')
        if len(parts) < 3:
            return False

        try:
            # Try to parse various date formats
            if len(parts) >= 4 and parts[-2].isdigit() and parts[-1].isdigit():
                # Format: table_YYYY_MM_DD
                year, month, day = int(parts[-3]), int(parts[-2]), int(parts[-1])
                partition_date = datetime(year, month, day)
            elif len(parts) >= 3 and parts[-2].isdigit() and parts[-1].isdigit():
                # Format: table_YYYY_MM
                year, month = int(parts[-2]), int(parts[-1])
                partition_date = datetime(year, month, 1)
            elif parts[-1].startswith('w') and parts[-1][1:].isdigit():
                # Format: table_YYYY_wWW
                year = int(parts[-2])
                week = int(parts[-1][1:])
                # Calculate date from year and week
                partition_date = datetime.strptime(f'{year}-W{week:02d}-1', '%Y-W%W-%w')
            else:
                return False

            return partition_date < cutoff_date
        except (ValueError, IndexError):
            return False

    async def _drop_partition(self, table_name: str) -> None:
        """Drop a specific partition."""
        drop_sql = f"DROP TABLE IF EXISTS {table_name}"
        try:
            await self.db.execute(text(drop_sql))
            logger.info(f"Dropped old partition: {table_name}")
        except Exception as e:
            logger.error(f"Failed to drop partition {table_name}: {e}")
            raise

    async def optimize_indexes(self) -> None:
        """Optimize database indexes for better query performance."""
        # Analyze table statistics
        await self._analyze_tables()

        # Create additional indexes based on usage patterns
        await self._create_performance_indexes()

        # Update table statistics
        await self._update_statistics()

    async def _analyze_tables(self) -> None:
        """Analyze tables to update query planner statistics."""
        tables_to_analyze = [
            'users', 'webauthn_credentials', 'security_logs',
            'auth_events_partitioned', 'security_logs_partitioned', 'user_sessions_partitioned'
        ]

        for table in tables_to_analyze:
            try:
                await self.db.execute(text(f"ANALYZE {table}"))
                logger.debug(f"Analyzed table: {table}")
            except Exception as e:
                logger.warning(f"Could not analyze table {table}: {e}")

        await self.db.commit()

    async def _create_performance_indexes(self) -> None:
        """Create additional indexes for common query patterns."""
        performance_indexes = [
            # Composite indexes for common queries
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_active_email ON users (is_active, email) WHERE is_active = true",
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_username_active ON users (username, is_active) WHERE is_active = true",

            # WebAuthn credential indexes
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_webauthn_user_active ON webauthn_credentials (user_id, is_active) WHERE is_active = true",
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_webauthn_risk_score ON webauthn_credentials (risk_score, updated_at)",

            # Partial indexes for better performance
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_locked ON users (locked_until) WHERE locked_until IS NOT NULL",
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_failed_attempts ON users (failed_login_attempts) WHERE failed_login_attempts > 0",
        ]

        for index_sql in performance_indexes:
            try:
                await self.db.execute(text(index_sql))
                logger.debug(f"Created performance index")
            except Exception as e:
                logger.warning(f"Could not create performance index: {e}")

        await self.db.commit()

    async def _update_statistics(self) -> None:
        """Update database statistics for query optimization."""
        try:
            # Update general statistics
            await self.db.execute(text("ANALYZE"))

            # Vacuum analyze for better performance (PostgreSQL specific)
            await self.db.execute(text("VACUUM ANALYZE"))

            await self.db.commit()
            logger.info("Updated database statistics")
        except Exception as e:
            logger.warning(f"Could not update statistics: {e}")
            await self.db.rollback()

    async def get_partition_info(self) -> Dict[str, Any]:
        """Get information about current partitions."""
        info_sql = """
        SELECT
            schemaname,
            tablename,
            pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
            pg_stat_get_tuples_returned(c.oid) as rows_read,
            pg_stat_get_tuples_inserted(c.oid) as rows_inserted
        FROM pg_tables pt
        JOIN pg_class c ON c.relname = pt.tablename
        WHERE tablename LIKE '%_partitioned%'
        AND schemaname = 'public'
        ORDER BY tablename
        """

        try:
            result = await self.db.execute(text(info_sql))
            partitions = []
            for row in result.fetchall():
                partitions.append({
                    "schema": row[0],
                    "table": row[1],
                    "size": row[2],
                    "rows_read": row[3] or 0,
                    "rows_inserted": row[4] or 0
                })

            return {
                "partitions": partitions,
                "total_partitions": len(partitions),
                "partitioning_enabled": self.config.enable_partitioning,
                "partition_interval": self.config.partition_interval
            }
        except Exception as e:
            logger.error(f"Failed to get partition info: {e}")
            return {"error": str(e), "partitions": []}


class DatabaseOptimizer:
    """Provides database optimization and maintenance functionality."""

    def __init__(self, db_session: AsyncSession):
        """Initialize database optimizer."""
        self.db = db_session
        self.config = get_scaling_config()

    async def run_maintenance(self) -> Dict[str, Any]:
        """Run complete database maintenance routine."""
        results = {}

        # Partition management
        partition_manager = DatabasePartitionManager(self.db)

        try:
            if self.config.enable_partitioning:
                await partition_manager.create_future_partitions()
                await partition_manager.cleanup_old_partitions()
                results["partitioning"] = "success"
            else:
                results["partitioning"] = "disabled"
        except Exception as e:
            results["partitioning"] = f"error: {e}"

        # Index optimization
        try:
            await partition_manager.optimize_indexes()
            results["index_optimization"] = "success"
        except Exception as e:
            results["index_optimization"] = f"error: {e}"

        # Cleanup old data
        try:
            await self._cleanup_expired_sessions()
            await self._cleanup_old_challenges()
            results["data_cleanup"] = "success"
        except Exception as e:
            results["data_cleanup"] = f"error: {e}"

        return results

    async def _cleanup_expired_sessions(self) -> None:
        """Clean up expired sessions."""
        cleanup_sql = """
        DELETE FROM user_sessions_partitioned
        WHERE expires_at < NOW() - INTERVAL '1 day'
        """

        try:
            result = await self.db.execute(text(cleanup_sql))
            await self.db.commit()
            logger.info(f"Cleaned up expired sessions")
        except Exception as e:
            logger.warning(f"Could not cleanup expired sessions: {e}")
            await self.db.rollback()

    async def _cleanup_old_challenges(self) -> None:
        """Clean up old WebAuthn challenges."""
        cleanup_sql = """
        DELETE FROM webauthn_challenges
        WHERE expires_at < NOW() - INTERVAL '1 hour'
        """

        try:
            result = await self.db.execute(text(cleanup_sql))
            await self.db.commit()
            logger.info(f"Cleaned up old challenges")
        except Exception as e:
            logger.warning(f"Could not cleanup old challenges: {e}")
            await self.db.rollback()

    async def get_database_stats(self) -> Dict[str, Any]:
        """Get comprehensive database statistics."""
        stats = {}

        # Table sizes
        size_sql = """
        SELECT
            relname as table_name,
            pg_size_pretty(pg_total_relation_size(relid)) as size,
            pg_stat_get_tuples_returned(relid) as rows_read,
            pg_stat_get_tuples_inserted(relid) as rows_inserted
        FROM pg_stat_user_tables
        WHERE schemaname = 'public'
        ORDER BY pg_total_relation_size(relid) DESC
        """

        try:
            result = await self.db.execute(text(size_sql))
            tables = []
            for row in result.fetchall():
                tables.append({
                    "name": row[0],
                    "size": row[1],
                    "rows_read": row[2] or 0,
                    "rows_inserted": row[3] or 0
                })
            stats["tables"] = tables
        except Exception as e:
            stats["tables"] = f"error: {e}"

        # Index usage
        index_sql = """
        SELECT
            indexrelname as index_name,
            relname as table_name,
            idx_scan as times_used,
            pg_size_pretty(pg_relation_size(indexrelid)) as size
        FROM pg_stat_user_indexes
        WHERE schemaname = 'public'
        ORDER BY idx_scan DESC
        """

        try:
            result = await self.db.execute(text(index_sql))
            indexes = []
            for row in result.fetchall():
                indexes.append({
                    "name": row[0],
                    "table": row[1],
                    "times_used": row[2] or 0,
                    "size": row[3]
                })
            stats["indexes"] = indexes
        except Exception as e:
            stats["indexes"] = f"error: {e}"

        return stats


# Background task for automatic maintenance
async def run_database_maintenance(db_session: AsyncSession) -> None:
    """Background task for database maintenance."""
    try:
        optimizer = DatabaseOptimizer(db_session)
        results = await optimizer.run_maintenance()
        logger.info(f"Database maintenance completed: {results}")
    except Exception as e:
        logger.error(f"Database maintenance failed: {e}")


# Initialization function
async def initialize_database_optimization(db_session: AsyncSession) -> None:
    """Initialize database optimization and partitioning."""
    try:
        partition_manager = DatabasePartitionManager(db_session)
        await partition_manager.setup_partitioning()

        optimizer = DatabaseOptimizer(db_session)
        await optimizer.run_maintenance()

        logger.info("Database optimization initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database optimization: {e}")
        raise