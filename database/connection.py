import logging
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from trustee_monitor.config import DATABASE_URL
from trustee_monitor.database.models import Base
logger = logging.getLogger(__name__)
_engine = None
_session_maker = None

def get_engine():
    global _engine, _session_maker
    if _engine is None:
        _engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True, pool_size=20, max_overflow=10)
        _session_maker = async_sessionmaker(bind=_engine, class_=AsyncSession, expire_on_commit=False)
    return _engine

async def init_db():
    eng = get_engine()
    try:
        async with eng.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info('Database (PostgreSQL) initialized successfully. All tables created.')
        return True
    except Exception as e:
        logger.error(f'PostgreSQL initialization failed: {e}')
        raise e

@asynccontextmanager
async def get_db_session():
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
