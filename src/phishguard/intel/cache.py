"""Persistent SQLite cache for threat intelligence results using SQLAlchemy 2.x."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import (
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from phishguard.core.config import get_settings
from phishguard.intel.base import Indicator, IntelResult, compute_indicator_hash
from phishguard.intel.constants import (
    MAX_RAW_SUMMARY_BYTES,
    MAX_THREAT_TYPES_CACHED,
    NEGATIVE_CACHE_TTL_HOURS,
)

logger = structlog.get_logger(__name__)


class Base(DeclarativeBase):
    """Declarative base for threat intelligence cache models."""


class IntelCacheRecord(Base):
    """Persistent cache record for an indicator query outcome.

    Per Amendment 1: Stores NO plaintext indicator values; records indicator_hash only.
    Stores capped summary and threat types without raw responses.
    """

    __tablename__ = "intel_cache"
    __table_args__ = (
        UniqueConstraint("provider", "indicator_hash", name="uq_provider_indicator_hash"),
        Index("ix_intel_cache_lookup", "provider", "indicator_hash"),
        Index("ix_intel_cache_expires", "expires_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    indicator_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False)
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    threat_types: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    raw_summary: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}"
    )  # JSON-encoded summary
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IntelCache:
    """Thread-safe SQLite cache manager accessed via asyncio.to_thread."""

    def __init__(self, db_url: str | None = None) -> None:
        """Initialize SQLite database engine and sessionmaker.

        Args:
            db_url: SQLAlchemy connection string. Defaults to PHISHGUARD_DB_URL.
        """
        cfg = get_settings()
        self.db_url = db_url or cfg.PHISHGUARD_DB_URL
        self._ttl_hours = cfg.INTEL_CACHE_TTL_HOURS

        # Ensure parent directory exists for file-based sqlite
        if self.db_url.startswith("sqlite:///") and ":memory:" not in self.db_url:
            db_path = Path(self.db_url.replace("sqlite:///", ""))
            db_path.parent.mkdir(parents=True, exist_ok=True)

        engine_kwargs: dict[str, Any] = {
            "connect_args": {"check_same_thread": False} if "sqlite" in self.db_url else {},
            "pool_pre_ping": True,
        }
        if ":memory:" in self.db_url:
            engine_kwargs["poolclass"] = StaticPool

        self.engine = create_engine(self.db_url, **engine_kwargs)

        # Enable WAL mode for SQLite
        if "sqlite" in self.db_url and ":memory:" not in self.db_url:
            try:
                with self.engine.connect() as conn:
                    conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
                    conn.exec_driver_sql("PRAGMA synchronous=NORMAL;")
            except Exception as exc:
                logger.warning("intel_cache_wal_init_failed", error=str(exc))

        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)

    def _get_sync(self, provider: str, indicator_hash: str) -> IntelResult | None:
        """Synchronous lookup in SQLite cache."""
        try:
            with self.SessionLocal() as session:
                stmt = select(IntelCacheRecord).where(
                    IntelCacheRecord.provider == provider,
                    IntelCacheRecord.indicator_hash == indicator_hash,
                )
                record = session.scalars(stmt).first()
                if not record:
                    return None

                # Check expiration
                now = datetime.now(UTC)
                expires_at = record.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=UTC)
                if expires_at <= now:
                    return None

                # Reconstruct capped threat types and summary
                threats = [t for t in record.threat_types.split(",") if t]
                try:
                    summary = json.loads(record.raw_summary)
                except Exception:
                    summary = {}

                return IntelResult(
                    provider=record.provider,
                    indicator=Indicator(
                        type=record.indicator_type,  # type: ignore[arg-type]
                        value="[CACHED]",  # Plaintext value was not stored
                    ),
                    verdict=record.verdict,  # type: ignore[arg-type]
                    score=record.score,
                    threat_types=threats,
                    raw=summary,
                    duration_ms=0,
                )
        except Exception as exc:
            logger.warning("intel_cache_read_failed", provider=provider, error=str(exc))
            return None

    def _set_sync(self, result: IntelResult, original_value: str) -> None:
        """Synchronous insert or update in SQLite cache."""
        try:
            now = datetime.now(UTC)
            # Differential TTL: clean / unknown results expire faster
            if result.verdict in ("malicious", "suspicious"):
                ttl_delta = timedelta(hours=self._ttl_hours)
            else:
                ttl_delta = timedelta(hours=NEGATIVE_CACHE_TTL_HOURS)

            expires_at = now + ttl_delta
            ind_hash = compute_indicator_hash(
                Indicator(type=result.indicator.type, value=original_value)
            )

            # Cap threat types and summary payload (Amendment 1)
            capped_threats = ",".join(result.threat_types[:MAX_THREAT_TYPES_CACHED])
            capped_raw: dict[str, Any] = {
                k: v[:100] if isinstance(v, str) else v
                for k, v in list(result.raw.items())[:5]
                if k not in ("api_key", "key", "token")
            }
            summary_json = json.dumps(capped_raw)[:MAX_RAW_SUMMARY_BYTES]

            with self.SessionLocal() as session:
                stmt = select(IntelCacheRecord).where(
                    IntelCacheRecord.provider == result.provider,
                    IntelCacheRecord.indicator_hash == ind_hash,
                )
                existing = session.scalars(stmt).first()
                if existing:
                    existing.verdict = result.verdict
                    existing.score = result.score
                    existing.threat_types = capped_threats
                    existing.raw_summary = summary_json
                    existing.expires_at = expires_at
                else:
                    record = IntelCacheRecord(
                        provider=result.provider,
                        indicator_hash=ind_hash,
                        indicator_type=result.indicator.type,
                        verdict=result.verdict,
                        score=result.score,
                        threat_types=capped_threats,
                        raw_summary=summary_json,
                        created_at=now,
                        expires_at=expires_at,
                    )
                    session.add(record)
                session.commit()
        except Exception as exc:
            logger.warning("intel_cache_write_failed", provider=result.provider, error=str(exc))

    async def get(self, provider: str, indicator: Indicator) -> IntelResult | None:
        """Asynchronously query cache using asyncio.to_thread (Amendment 10).

        Args:
            provider: Provider name.
            indicator: Indicator to check.

        Returns:
            Cached IntelResult if found and not expired; None otherwise.
        """
        ind_hash = compute_indicator_hash(indicator)
        return await asyncio.to_thread(self._get_sync, provider, ind_hash)

    async def set(self, result: IntelResult, original_value: str) -> None:
        """Asynchronously store result in cache using asyncio.to_thread (Amendment 10).

        Args:
            result: IntelResult to persist.
            original_value: The original indicator string before stripping.
        """
        await asyncio.to_thread(self._set_sync, result, original_value)
