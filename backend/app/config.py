from pydantic_settings import BaseSettings
from typing import Optional
import os
import shutil

# 自动创建 .env 文件（如果不存在）
_env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
_env_example_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env.example')
if not os.path.exists(_env_path) and os.path.exists(_env_example_path):
    shutil.copy(_env_example_path, _env_path)
    print("✅ 已自动创建 .env 配置文件")


class Settings(BaseSettings):
    # 数据库
    database_url: str = "sqlite+aiosqlite:///./data/gemini_proxy.db"
    
    # JWT
    secret_key: str = "your-super-secret-key-change-this"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24 * 7  # 7天
    
    # 管理员
    admin_username: str = "admin"
    admin_password: str = "admin123"
    
    # 服务
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Gemini
    gemini_api_base: str = "https://generativelanguage.googleapis.com"
    
    # 用户配额
    default_daily_quota: int = 100
    
    # 凭证奖励：每上传一个凭证增加的额度
    credential_reward_quota: int = 1000
    
    # 速率限制 (RPM - requests per minute)
    base_rpm: int = 5  # 未上传凭证的用户
    contributor_rpm: int = 10  # 上传凭证的用户
    
    # 错误重试
    error_retry_count: int = 3  # 报错时切换凭证重试次数
    
    # 注册
    allow_registration: bool = True
    discord_only_registration: bool = False  # 仅允许通过 Discord Bot 注册
    discord_oauth_only: bool = False  # 仅允许通过 Discord OAuth 登录注册
    
    # 凭证池模式: 
    # "private" - 只能用自己的凭证
    # "tier3_shared" - 3.0凭证共享池（有3.0凭证的用户可用公共3.0池）
    # "full_shared" - 大锅饭模式（捐赠凭证即可用所有公共池）
    credential_pool_mode: str = "full_shared"
    
    # 公告
    announcement_enabled: bool = False
    announcement_title: str = ""
    announcement_content: str = ""
    announcement_read_seconds: int = 5  # 阅读多少秒才能关闭
    
    # Google OAuth (Gemini CLI 官方配置)
    google_client_id: str = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
    google_client_secret: str = "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"
    
    # OpenAI API 反代 (可选)
    openai_api_key: str = ""  # 如果填写，则支持真正的 OpenAI API 反代
    openai_api_base: str = "https://api.openai.com"
    
    # Discord OAuth (可选，用于 Discord 登录/注册)
    discord_client_id: str = ""
    discord_client_secret: str = ""
    discord_redirect_uri: str = ""  # 例如: https://你的域名/api/auth/discord/callback
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()


# 可持久化的配置项
PERSISTENT_CONFIG_KEYS = [
    "allow_registration",
    "discord_only_registration",
    "discord_oauth_only", 
    "default_daily_quota",
    "credential_reward_quota",
    "base_rpm",
    "contributor_rpm",
    "credential_pool_mode",
    "error_retry_count",
    "announcement_enabled",
    "announcement_title",
    "announcement_content",
    "announcement_read_seconds",
]


async def load_config_from_db():
    """从数据库加载配置"""
    from app.database import async_session
    from app.models.user import SystemConfig
    from sqlalchemy import select
    
    async with async_session() as db:
        result = await db.execute(select(SystemConfig))
        configs = result.scalars().all()
        
        for config in configs:
            if hasattr(settings, config.key):
                value = config.value
                # 类型转换
                attr_type = type(getattr(settings, config.key))
                if attr_type == bool:
                    value = value.lower() in ('true', '1', 'yes')
                elif attr_type == int:
                    value = int(value)
                setattr(settings, config.key, value)
                print(f"[Config] 从数据库加载: {config.key} = {value}")


async def save_config_to_db(key: str, value):
    """保存单个配置到数据库"""
    from app.database import async_session
    from app.models.user import SystemConfig
    from sqlalchemy import select
    
    async with async_session() as db:
        result = await db.execute(select(SystemConfig).where(SystemConfig.key == key))
        config = result.scalar_one_or_none()
        
        if config:
            config.value = str(value)
        else:
            config = SystemConfig(key=key, value=str(value))
            db.add(config)
        
        await db.commit()
