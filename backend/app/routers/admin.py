from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update, delete
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date, timedelta

from app.database import get_db
from app.models.user import User, APIKey, UsageLog, Credential
from app.services.auth import get_current_admin, get_password_hash
from app.services.credential_pool import CredentialPool
from app.services.websocket import notify_user_update, notify_credential_update

router = APIRouter(prefix="/api/admin", tags=["管理后台"])


# ===== 用户管理 =====
class UserUpdate(BaseModel):
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None
    daily_quota: Optional[int] = None
    quota_flash: Optional[int] = None
    quota_25pro: Optional[int] = None
    quota_30pro: Optional[int] = None


@router.get("/users")
async def list_users(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """获取所有用户（优化版：批量查询）"""
    from app.config import settings
    
    # 1. 获取所有用户
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    
    if not users:
        return {"users": [], "total": 0}
    
    user_ids = [u.id for u in users]
    today = date.today()
    
    # 2. 批量查询今日使用量
    usage_result = await db.execute(
        select(UsageLog.user_id, func.count(UsageLog.id))
        .where(UsageLog.user_id.in_(user_ids))
        .where(func.date(UsageLog.created_at) == today)
        .group_by(UsageLog.user_id)
    )
    usage_map = {row[0]: row[1] for row in usage_result.fetchall()}
    
    # 3. 批量查询凭证数量
    cred_result = await db.execute(
        select(Credential.user_id, func.count(Credential.id))
        .where(Credential.user_id.in_(user_ids))
        .where(Credential.is_active == True)
        .group_by(Credential.user_id)
    )
    cred_map = {row[0]: row[1] for row in cred_result.fetchall()}
    
    # 3.5 批量查询3.0凭证数量
    from sqlalchemy import case
    cred_30_result = await db.execute(
        select(Credential.user_id, func.count(Credential.id))
        .where(Credential.user_id.in_(user_ids))
        .where(Credential.is_active == True)
        .where(Credential.model_tier == "3")
        .group_by(Credential.user_id)
    )
    cred_30_map = {row[0]: row[1] for row in cred_30_result.fetchall()}
    
    # 4. 构建用户列表
    user_list = []
    for u in users:
        today_usage = usage_map.get(u.id, 0)
        credential_count = cred_map.get(u.id, 0)
        cred_30_count = cred_30_map.get(u.id, 0)
        
        # 计算真实配额
        if u.quota_flash and u.quota_flash > 0:
            quota_flash = u.quota_flash
        elif credential_count > 0:
            quota_flash = credential_count * settings.quota_flash
        else:
            quota_flash = settings.no_cred_quota_flash
        
        if u.quota_25pro and u.quota_25pro > 0:
            quota_25pro = u.quota_25pro
        elif credential_count > 0:
            quota_25pro = credential_count * settings.quota_25pro
        else:
            quota_25pro = settings.no_cred_quota_25pro
        
        if u.quota_30pro and u.quota_30pro > 0:
            quota_30pro = u.quota_30pro
        elif cred_30_count > 0:
            quota_30pro = cred_30_count * settings.quota_30pro
        elif credential_count > 0:
            quota_30pro = settings.cred25_quota_30pro
        else:
            quota_30pro = settings.no_cred_quota_30pro
        
        total_quota = quota_flash + quota_25pro + quota_30pro
        
        user_list.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_active": u.is_active,
            "is_admin": u.is_admin,
            "daily_quota": total_quota,
            "quota_flash": quota_flash,
            "quota_25pro": quota_25pro,
            "quota_30pro": quota_30pro,
            "today_usage": today_usage,
            "credential_count": credential_count,
            "discord_id": u.discord_id,
            "discord_name": u.discord_name,
            "created_at": u.created_at
        })
    
    return {"users": user_list, "total": len(user_list)}


@router.put("/users/{user_id}")
async def update_user(
    user_id: int,
    data: UserUpdate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """更新用户"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    if data.is_active is not None:
        user.is_active = data.is_active
    if data.is_admin is not None:
        user.is_admin = data.is_admin
    if data.daily_quota is not None:
        user.daily_quota = data.daily_quota
    if data.quota_flash is not None:
        user.quota_flash = data.quota_flash
    if data.quota_25pro is not None:
        user.quota_25pro = data.quota_25pro
    if data.quota_30pro is not None:
        user.quota_30pro = data.quota_30pro
    
    await db.commit()
    await notify_user_update()
    return {"message": "更新成功"}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """删除用户"""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="不能删除自己")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    await db.delete(user)
    await db.commit()
    await notify_user_update()
    return {"message": "删除成功"}


# ===== 凭证管理 =====
class CredentialCreate(BaseModel):
    name: str
    api_key: str


class CredentialUpdate(BaseModel):
    name: Optional[str] = None
    api_key: Optional[str] = None
    is_active: Optional[bool] = None


@router.get("/credentials")
async def list_credentials(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """获取所有凭证"""
    credentials = await CredentialPool.get_all_credentials(db)
    return {
        "credentials": [
            {
                "id": c.id,
                "name": c.name,
                "email": c.email,
                "api_key": c.api_key[:20] + "..." if c.api_key and len(c.api_key) > 20 else (c.api_key or ""),
                "model_tier": c.model_tier,
                "is_active": c.is_active,
                "total_requests": c.total_requests or 0,
                "failed_requests": c.failed_requests or 0,
                "last_used_at": (c.last_used_at.isoformat() + "Z") if c.last_used_at else None,
                "last_error": c.last_error,
                "created_at": (c.created_at.isoformat() + "Z") if c.created_at else None
            }
            for c in credentials
        ],
        "total": len(credentials)
    }


@router.post("/credentials")
async def add_credential(
    data: CredentialCreate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """添加凭证"""
    credential = await CredentialPool.add_credential(db, data.name, data.api_key)
    await notify_credential_update()
    return {"message": "添加成功", "id": credential.id}


@router.put("/credentials/{credential_id}")
async def update_credential(
    credential_id: int,
    data: CredentialUpdate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """更新凭证"""
    result = await db.execute(select(Credential).where(Credential.id == credential_id))
    credential = result.scalar_one_or_none()
    if not credential:
        raise HTTPException(status_code=404, detail="凭证不存在")
    
    if data.name is not None:
        credential.name = data.name
    if data.api_key is not None:
        credential.api_key = data.api_key
    if data.is_active is not None:
        credential.is_active = data.is_active
    
    await db.commit()
    await notify_credential_update()
    return {"message": "更新成功"}


@router.delete("/credentials/{credential_id}")
async def delete_credential(
    credential_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """删除凭证"""
    result = await db.execute(select(Credential).where(Credential.id == credential_id))
    credential = result.scalar_one_or_none()
    if not credential:
        raise HTTPException(status_code=404, detail="凭证不存在")
    
    await db.delete(credential)
    await db.commit()
    await notify_credential_update()
    return {"message": "删除成功"}


@router.get("/credentials/{credential_id}/detail")
async def get_credential_detail(
    credential_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """查看凭证详情（解密后返回，用于debug）"""
    from app.services.crypto import decrypt_credential
    
    result = await db.execute(
        select(Credential, User.username)
        .outerjoin(User, Credential.user_id == User.id)
        .where(Credential.id == credential_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="凭证不存在")
    
    c = row[0]
    username = row[1]
    
    return {
        "id": c.id,
        "email": c.email,
        "name": c.name,
        "username": username,
        "credential_type": c.credential_type,
        "refresh_token": decrypt_credential(c.refresh_token) if c.refresh_token else None,
        "access_token": decrypt_credential(c.api_key) if c.api_key else None,
        "client_id": decrypt_credential(c.client_id) if c.client_id else None,
        "client_secret": decrypt_credential(c.client_secret) if c.client_secret else None,
        "project_id": c.project_id,
        "model_tier": c.model_tier,
        "account_type": c.account_type,
        "is_active": c.is_active,
        "is_public": c.is_public,
        "total_requests": c.total_requests,
        "failed_requests": c.failed_requests,
        "last_used_at": c.last_used_at.isoformat() + "Z" if c.last_used_at else None,
        "last_error": c.last_error,
        "created_at": c.created_at.isoformat() + "Z" if c.created_at else None
    }


@router.get("/credentials/export")
async def export_all_credentials(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """导出所有凭证（包含 refresh_token，解密后导出）"""
    from app.services.crypto import decrypt_credential
    
    try:
        # 关联查询用户名
        result = await db.execute(
            select(Credential, User.username)
            .outerjoin(User, Credential.user_id == User.id)
            .order_by(Credential.created_at.desc())
        )
        rows = result.all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")
    
    export_data = []
    for row in rows:
        try:
            c = row[0]  # Credential
            username = row[1]  # username (可能为 None)
            
            # 安全获取属性，避免 AttributeError
            cred_data = {
                "id": getattr(c, 'id', None),
                "email": getattr(c, 'email', None),
                "name": getattr(c, 'name', None),
                "username": username,
                "project_id": getattr(c, 'project_id', None),
                "model_tier": getattr(c, 'model_tier', None),
                "is_active": getattr(c, 'is_active', None),
                "is_public": getattr(c, 'is_public', None),
                "user_id": getattr(c, 'user_id', None),
                "created_at": c.created_at.isoformat() if getattr(c, 'created_at', None) else None
            }
            
            # 解密敏感字段
            try:
                cred_data["refresh_token"] = decrypt_credential(c.refresh_token) if getattr(c, 'refresh_token', None) else None
                cred_data["access_token"] = decrypt_credential(c.api_key) if getattr(c, 'api_key', None) else None
                cred_data["client_id"] = decrypt_credential(c.client_id) if getattr(c, 'client_id', None) else None
                cred_data["client_secret"] = decrypt_credential(c.client_secret) if getattr(c, 'client_secret', None) else None
            except Exception as decrypt_err:
                cred_data["decrypt_error"] = str(decrypt_err)[:100]
            
            export_data.append(cred_data)
        except Exception as e:
            # 单条凭证处理失败不影响其他
            export_data.append({
                "error": f"处理失败: {str(e)[:100]}",
                "row_index": rows.index(row)
            })
    
    return export_data


@router.get("/credentials/duplicates")
async def check_duplicate_credentials(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """检测重复凭证（相同邮箱或相同refresh_token）"""
    from app.services.crypto import decrypt_credential
    from collections import defaultdict
    
    # 获取所有凭证
    result = await db.execute(
        select(Credential, User.username)
        .outerjoin(User, Credential.user_id == User.id)
        .order_by(Credential.created_at.asc())
    )
    rows = result.all()
    
    # 按邮箱分组
    email_groups = defaultdict(list)
    # 按 refresh_token 分组
    token_groups = defaultdict(list)
    
    for row in rows:
        c = row[0]
        username = row[1]
        
        cred_info = {
            "id": c.id,
            "email": c.email,
            "name": c.name,
            "username": username or "系统",
            "user_id": c.user_id,
            "is_active": c.is_active,
            "is_public": c.is_public,
            "model_tier": c.model_tier,
            "total_requests": c.total_requests,
            "created_at": c.created_at.isoformat() if c.created_at else None
        }
        
        # 按邮箱分组
        if c.email:
            email_groups[c.email].append(cred_info)
        
        # 按 refresh_token 分组（解密后比较）
        if c.refresh_token:
            try:
                token = decrypt_credential(c.refresh_token)
                # 只取前50字符作为key，避免太长
                token_key = token[:50] if token else None
                if token_key:
                    token_groups[token_key].append(cred_info)
            except:
                pass
    
    # 找出重复的
    duplicate_emails = {k: v for k, v in email_groups.items() if len(v) > 1}
    duplicate_tokens = {k: v for k, v in token_groups.items() if len(v) > 1}
    
    # 合并结果，去重
    all_duplicate_ids = set()
    duplicates = []
    
    for email, creds in duplicate_emails.items():
        for cred in creds:
            if cred["id"] not in all_duplicate_ids:
                all_duplicate_ids.add(cred["id"])
        duplicates.append({
            "type": "email",
            "key": email,
            "credentials": creds
        })
    
    for token_key, creds in duplicate_tokens.items():
        # 检查是否已经被邮箱重复覆盖
        ids = [c["id"] for c in creds]
        if not all(id in all_duplicate_ids for id in ids):
            for cred in creds:
                all_duplicate_ids.add(cred["id"])
            duplicates.append({
                "type": "token",
                "key": f"{token_key[:20]}...",
                "credentials": creds
            })
    
    return {
        "total_credentials": len(rows),
        "duplicate_count": len(all_duplicate_ids),
        "duplicates": duplicates
    }


# ===== 统计 =====
@router.get("/stats")
async def get_stats(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """获取系统统计"""
    # 用户数
    user_count = (await db.execute(select(func.count(User.id)))).scalar() or 0
    
    # 凭证数
    credential_count = (await db.execute(select(func.count(Credential.id)))).scalar() or 0
    active_credential_count = (await db.execute(
        select(func.count(Credential.id)).where(Credential.is_active == True)
    )).scalar() or 0
    
    # 今日请求数
    today = date.today()
    today_requests = (await db.execute(
        select(func.count(UsageLog.id)).where(func.date(UsageLog.created_at) == today)
    )).scalar() or 0
    
    # 总请求数
    total_requests = (await db.execute(select(func.count(UsageLog.id)))).scalar() or 0
    
    # 最近7天请求趋势
    daily_stats = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        count = (await db.execute(
            select(func.count(UsageLog.id)).where(func.date(UsageLog.created_at) == day)
        )).scalar() or 0
        daily_stats.append({"date": day.isoformat(), "count": count})
    
    return {
        "user_count": user_count,
        "credential_count": credential_count,
        "active_credential_count": active_credential_count,
        "today_requests": today_requests,
        "total_requests": total_requests,
        "daily_stats": daily_stats
    }


@router.get("/logs")
async def get_logs(
    limit: int = 100,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """获取使用日志"""
    result = await db.execute(
        select(UsageLog, User.username)
        .join(User, UsageLog.user_id == User.id)
        .order_by(UsageLog.created_at.desc())
        .limit(limit)
    )
    logs = result.all()
    
    return {
        "logs": [
            {
                "id": log.UsageLog.id,
                "username": log.username,
                "model": log.UsageLog.model,
                "endpoint": log.UsageLog.endpoint,
                "status_code": log.UsageLog.status_code,
                "latency_ms": log.UsageLog.latency_ms,
                "created_at": log.UsageLog.created_at.isoformat() + "Z"  # 标记为 UTC 时间
            }
            for log in logs
        ]
    }


# ===== 配额设置 =====
class QuotaUpdate(BaseModel):
    quota: int


@router.post("/settings/default-quota")
async def set_default_quota(
    data: QuotaUpdate,
    admin: User = Depends(get_current_admin)
):
    """设置新用户默认配额"""
    from app.config import settings
    settings.default_daily_quota = data.quota
    return {"message": "默认配额已更新", "quota": data.quota}


@router.post("/settings/batch-quota")
async def batch_update_quota(
    data: QuotaUpdate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """批量更新所有用户配额"""
    await db.execute(
        update(User).values(daily_quota=data.quota)
    )
    await db.commit()
    await notify_user_update()
    return {"message": f"已将所有用户配额设为 {data.quota}"}
