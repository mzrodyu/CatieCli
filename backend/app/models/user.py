from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from datetime import datetime
import secrets
from app.database import Base


class User(Base):
    """用户表"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    discord_id = Column(String(50), unique=True, index=True, nullable=True)  # Discord 用户 ID
    discord_name = Column(String(100), nullable=True)  # Discord 用户名
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    daily_quota = Column(Integer, default=100)  # 每日请求配额
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # 关系
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    usage_logs = relationship("UsageLog", back_populates="user", cascade="all, delete-orphan")
    credentials = relationship("Credential", back_populates="owner")


class APIKey(Base):
    """用户API密钥表"""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    key = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(100), default="default")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    
    # 关系
    user = relationship("User", back_populates="api_keys")
    
    @staticmethod
    def generate_key():
        """生成API密钥: cat-xxxxxxxx"""
        return f"cat-{secrets.token_hex(24)}"


class UsageLog(Base):
    """使用记录表"""
    __tablename__ = "usage_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), nullable=True)
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True, index=True)
    model = Column(String(100), nullable=True)
    endpoint = Column(String(200), nullable=True)
    tokens_input = Column(Integer, default=0)
    tokens_output = Column(Integer, default=0)
    status_code = Column(Integer, nullable=True)
    latency_ms = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # 关系
    user = relationship("User", back_populates="usage_logs")
    credential = relationship("Credential")


class Credential(Base):
    """Gemini凭证池"""
    __tablename__ = "credentials"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # 所属用户
    name = Column(String(100), nullable=False)
    api_key = Column(Text, nullable=False)  # Gemini API Key 或 OAuth access_token
    refresh_token = Column(Text, nullable=True)  # OAuth refresh_token
    project_id = Column(String(200), nullable=True)  # Google Cloud Project ID
    credential_type = Column(String(20), default="api_key")  # api_key 或 oauth
    model_tier = Column(String(10), default="2.5")  # 模型等级: "3" 或 "2.5"
    email = Column(String(100), nullable=True)  # OAuth 关联的邮箱
    is_public = Column(Boolean, default=False)  # 是否捐赠到公共池
    is_active = Column(Boolean, default=True)
    total_requests = Column(Integer, default=0)
    failed_requests = Column(Integer, default=0)
    last_used_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # 关系
    owner = relationship("User", back_populates="credentials")


class SystemConfig(Base):
    """系统配置表（持久化存储）"""
    __tablename__ = "system_config"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
