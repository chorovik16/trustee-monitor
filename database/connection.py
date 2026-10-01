import logging
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from trustee_monitor.config import DATABASE_URL, BASE_DIR
from trustee_monitor.database.models import Base

logger = logging.getLogger(__name__)

SQLITE_FALLBACK_URL = f"sqlite+aiosqlite:///{BASE_DIR / 'trustee_antifish.db'}"

_engine = None
_session_maker = None
_using_fallback = False

def get_engine():
    global _engine, _session_maker, _using_fallback
    if _engine is None:
        target_url = DATABASE_URL
        try:
            if "postgresql" in target_url:
                _engine = create_async_engine(
                    target_url,
                    echo=False,
                    pool_pre_ping=True,
                    connect_args={"timeout": 3.0}
                )
            else:
                _engine = create_async_engine(target_url, echo=False)
            _session_maker = async_sessionmaker(bind=_engine, class_=AsyncSession, expire_on_commit=False)
        except Exception as e:
            logger.warning(f"Failed to create engine with {target_url}: {e}. Using SQLite fallback.")
            _engine = create_async_engine(SQLITE_FALLBACK_URL, echo=False)
            _session_maker = async_sessionmaker(bind=_engine, class_=AsyncSession, expire_on_commit=False)
            _using_fallback = True
    return _engine

async def init_db():
    """Initializes tables in database, prioritizing PostgreSQL with graceful fallback to SQLite for offline/dev testing."""
    global _engine, _session_maker, _using_fallback
    eng = get_engine()
    try:
        async with eng.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        db_type = "PostgreSQL" if not _using_fallback and "postgresql" in DATABASE_URL else "SQLite (Fallback/Dev)"
        logger.info(f"Database ({db_type}) initialized successfully. All tables created.")
        return True
    except Exception as e:
        if "postgresql" in DATABASE_URL and not _using_fallback:
            logger.warning(f"Could not connect to PostgreSQL on localhost: {e}. Switching to local SQLite fallback ({SQLITE_FALLBACK_URL})...")
            _using_fallback = True
            _engine = create_async_engine(SQLITE_FALLBACK_URL, echo=False)
            _session_maker = async_sessionmaker(bind=_engine, class_=AsyncSession, expire_on_commit=False)
            async with _engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Local SQLite fallback database initialized successfully.")
            return True
        else:
            logger.error(f"Database initialization failed: {e}")
            raise e

@asynccontextmanager
async def get_db_session():
    """Async session context manager."""
    global _session_maker
    if _session_maker is None:
        get_engine()
    session = _session_maker()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()
