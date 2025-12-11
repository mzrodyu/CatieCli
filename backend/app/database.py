from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import StaticPool
from app.config import settings
import os

# 确保数据目录存在
os.makedirs("data", exist_ok=True)

# SQLite优化配置：WAL模式、更长超时、连接池
engine = create_async_engine(
    settings.database_url, 
    echo=False,
    connect_args={
        "timeout": 60,  # 60秒超时
        "check_same_thread": False
    },
    poolclass=StaticPool,  # 使用静态连接池避免连接问题
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

async def get_db():
    async with async_session() as session:
        yield session

async def init_db():
    async with engine.begin() as conn:
        # 启用WAL模式提升并发性能
        from sqlalchemy import text
        await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.execute(text("PRAGMA synchronous=NORMAL"))
        await conn.execute(text("PRAGMA busy_timeout=60000"))  # 60秒
        
        await conn.run_sync(Base.metadata.create_all)
        
        # 数据库迁移：添加新列（如果不存在）
        from sqlalchemy import text
        migrations = [
            "ALTER TABLE usage_logs ADD COLUMN credential_id INTEGER REFERENCES credentials(id)",
        ]
        for sql in migrations:
            try:
                await conn.execute(text(sql))
                print(f"[DB Migration] ✅ {sql[:50]}...")
            except Exception as e:
                if "duplicate column" not in str(e).lower() and "already exists" not in str(e).lower():
                    pass  # 列已存在，忽略
