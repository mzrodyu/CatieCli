"""
管理功能路由 - 凭证管理、配置、统计等
"""
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update
import sqlalchemy
from typing import List, Optional
from datetime import datetime, timedelta
import json
import io
import zipfile

from app.database import get_db
from app.models.user import User, Credential, UsageLog
from app.services.auth import get_current_user, get_current_admin
from app.services.crypto import encrypt_credential, decrypt_credential
from app.config import settings

router = APIRouter(prefix="/api/manage", tags=["管理功能"])


# ===== 凭证管理增强 =====

@router.get("/credentials/status")
async def get_credentials_status(
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """获取所有凭证的详细状态"""
    result = await db.execute(
        select(Credential).order_by(Credential.created_at.desc())
    )
    credentials = result.scalars().all()
    
    return {
        "total": len(credentials),
        "active": sum(1 for c in credentials if c.is_active),
        "public": sum(1 for c in credentials if c.is_public),
        "tier_3_count": sum(1 for c in credentials if c.model_tier == "3"),
        "credentials": [
            {
                "id": c.id,
                "name": c.name,
                "email": c.email,
                "project_id": c.project_id,
                "credential_type": c.credential_type,
                "model_tier": c.model_tier or "2.5",
                "is_active": c.is_active,
                "is_public": c.is_public,
                "total_requests": c.total_requests,
                "failed_requests": c.failed_requests,
                "last_used_at": (c.last_used_at.isoformat() + "Z") if c.last_used_at else None,
                "last_error": c.last_error,
                "created_at": (c.created_at.isoformat() + "Z") if c.created_at else None,
            }
            for c in credentials
        ]
    }


@router.post("/credentials/batch-action")
async def batch_credential_action(
    action: str = Form(...),  # enable, disable, delete
    credential_ids: str = Form(...),  # 逗号分隔的ID
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """批量操作凭证"""
    ids = [int(x.strip()) for x in credential_ids.split(",") if x.strip()]
    
    if not ids:
        raise HTTPException(status_code=400, detail="未选择凭证")
    
    if action == "enable":
        await db.execute(
            update(Credential).where(Credential.id.in_(ids)).values(is_active=True)
        )
    elif action == "disable":
        await db.execute(
            update(Credential).where(Credential.id.in_(ids)).values(is_active=False)
        )
    elif action == "delete":
        result = await db.execute(select(Credential).where(Credential.id.in_(ids)))
        for cred in result.scalars().all():
            await db.delete(cred)
    else:
        raise HTTPException(status_code=400, detail="无效的操作")
    
    await db.commit()
    return {"message": f"已对 {len(ids)} 个凭证执行 {action} 操作"}


@router.delete("/credentials/inactive")
async def delete_inactive_credentials(
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """一键删除所有无效凭证"""
    result = await db.execute(
        select(Credential).where(Credential.is_active == False)
    )
    inactive_creds = result.scalars().all()
    
    if not inactive_creds:
        return {"message": "没有无效凭证", "deleted_count": 0}
    
    deleted_count = len(inactive_creds)
    for cred in inactive_creds:
        await db.delete(cred)
    
    await db.commit()
    return {"message": f"已删除 {deleted_count} 个无效凭证", "deleted_count": deleted_count}


@router.get("/credentials/export")
async def export_credentials(
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """导出所有凭证为 ZIP 文件"""
    result = await db.execute(select(Credential))
    credentials = result.scalars().all()
    
    # 创建内存中的 ZIP 文件
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for cred in credentials:
            cred_data = {
                "client_id": "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com",
                "client_secret": "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",
                "refresh_token": decrypt_credential(cred.refresh_token) if cred.refresh_token else "",
                "token": decrypt_credential(cred.api_key) if cred.api_key else "",
                "project_id": cred.project_id or "",
                "email": cred.email or "",
            }
            filename = f"{cred.email or cred.id}.json"
            zf.writestr(filename, json.dumps(cred_data, indent=2))
    
    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=credentials.zip"}
    )


@router.post("/credentials/{credential_id}/toggle")
async def toggle_credential(
    credential_id: int,
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """切换凭证启用/禁用状态"""
    result = await db.execute(select(Credential).where(Credential.id == credential_id))
    cred = result.scalar_one_or_none()
    
    if not cred:
        raise HTTPException(status_code=404, detail="凭证不存在")
    
    cred.is_active = not cred.is_active
    await db.commit()
    
    return {"message": f"凭证已{'启用' if cred.is_active else '禁用'}", "is_active": cred.is_active}


@router.post("/credentials/{credential_id}/donate")
async def toggle_donate(
    credential_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """切换凭证捐赠状态"""
    result = await db.execute(
        select(Credential).where(Credential.id == credential_id, Credential.user_id == user.id)
    )
    cred = result.scalar_one_or_none()
    
    if not cred:
        raise HTTPException(status_code=404, detail="凭证不存在或无权限")
    
    cred.is_public = not cred.is_public
    await db.commit()
    
    return {"message": f"凭证已{'捐赠' if cred.is_public else '取消捐赠'}", "is_public": cred.is_public}


@router.post("/credentials/{credential_id}/tier")
async def set_credential_tier(
    credential_id: int,
    tier: str = Form(...),  # "3" 或 "2.5"
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """设置凭证模型等级（管理员）"""
    if tier not in ["3", "2.5"]:
        raise HTTPException(status_code=400, detail="等级只能是 '3' 或 '2.5'")
    
    result = await db.execute(select(Credential).where(Credential.id == credential_id))
    cred = result.scalar_one_or_none()
    
    if not cred:
        raise HTTPException(status_code=404, detail="凭证不存在")
    
    cred.model_tier = tier
    await db.commit()
    
    return {"message": f"凭证等级已设为 {tier}", "model_tier": tier}


@router.post("/credentials/{credential_id}/verify")
async def verify_credential(
    credential_id: int,
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """验证凭证有效性和模型等级"""
    import httpx
    from app.services.credential_pool import CredentialPool
    from app.services.crypto import decrypt_credential
    
    result = await db.execute(select(Credential).where(Credential.id == credential_id))
    cred = result.scalar_one_or_none()
    
    if not cred:
        raise HTTPException(status_code=404, detail="凭证不存在")
    
    # 获取 access token
    access_token = await CredentialPool.get_access_token(cred, db)
    if not access_token:
        cred.is_active = False
        cred.last_error = "无法获取 access token"
        await db.commit()
        return {
            "is_valid": False,
            "model_tier": cred.model_tier,
            "error": "无法获取 access token",
            "supports_3": False
        }
    
    # 测试 Gemini 2.5
    is_valid = False
    supports_3 = False
    error_msg = None
    
    async with httpx.AsyncClient(timeout=15) as client:
        # 使用 cloudcode-pa 端点测试（与 gcli2api 一致）
        try:
            test_url = "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            
            # 先测试 3.0（优先）
            test_payload_3 = {
                "model": "gemini-2.5-pro",
                "project": cred.project_id or "",
                "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
            }
            resp3 = await client.post(test_url, headers=headers, json=test_payload_3)
            if resp3.status_code == 200:
                is_valid = True
                supports_3 = True
            elif resp3.status_code == 429:
                is_valid = True
                supports_3 = True
                error_msg = "配额已用尽 (429)"
            else:
                # 3.0 失败，再测试 2.5
                test_payload_25 = {
                    "model": "gemini-2.5-flash",
                    "project": cred.project_id or "",
                    "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
                }
                resp25 = await client.post(test_url, headers=headers, json=test_payload_25)
                if resp25.status_code == 200:
                    is_valid = True
                    supports_3 = False
                elif resp25.status_code == 429:
                    is_valid = True
                    supports_3 = False
                    error_msg = "配额已用尽 (429)"
                elif resp25.status_code in [401, 403]:
                    error_msg = f"认证失败 ({resp25.status_code})"
                else:
                    error_msg = f"API 返回 {resp25.status_code}"
        except Exception as e:
            error_msg = f"请求异常: {str(e)[:30]}"
    
    # 更新凭证状态
    cred.is_active = is_valid
    cred.model_tier = "3" if supports_3 else "2.5"
    if error_msg:
        cred.last_error = error_msg
    await db.commit()
    
    return {
        "is_valid": is_valid,
        "model_tier": cred.model_tier,
        "supports_3": supports_3,
        "error": error_msg
    }


@router.post("/credentials/verify-all")
async def verify_all_credentials(
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """一键检测所有凭证（包括账号类型检测）"""
    import httpx
    from app.services.credential_pool import CredentialPool
    
    result = await db.execute(select(Credential))
    creds = result.scalars().all()
    
    results = {"total": len(creds), "valid": 0, "invalid": 0, "tier3": 0, "pro": 0, "details": []}
    
    for cred in creds:
        try:
            access_token = await CredentialPool.get_access_token(cred, db)
            if not access_token:
                cred.is_active = False
                db.add(cred)
                results["invalid"] += 1
                results["details"].append({"id": cred.id, "email": cred.email, "status": "invalid", "reason": "无法获取 token"})
                continue
            
            is_valid = False
            supports_3 = False
            account_type = "unknown"
            
            async with httpx.AsyncClient(timeout=15) as client:
                test_url = "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
                headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
                
                # 先测试 2.5 验证凭证有效性
                test_payload_25 = {
                    "model": "gemini-2.5-flash",
                    "project": cred.project_id or "",
                    "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
                }
                resp = await client.post(test_url, headers=headers, json=test_payload_25)
                if resp.status_code == 200 or resp.status_code == 429:
                    is_valid = True
                    
                    # 凭证有效，再测试是否支持 3.0 模型
                    test_payload_3 = {
                        "model": "gemini-3-pro-preview",
                        "project": cred.project_id or "",
                        "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
                    }
                    resp_3 = await client.post(test_url, headers=headers, json=test_payload_3)
                    if resp_3.status_code == 200 or resp_3.status_code == 429:
                        supports_3 = True
                        print(f"[检测] {cred.email} 支持 3.0 模型", flush=True)
                    else:
                        supports_3 = False
                        print(f"[检测] {cred.email} 不支持 3.0 模型 (status={resp_3.status_code})", flush=True)
            
            # 检测账号类型（Pro/Free）
            if is_valid and cred.project_id:
                try:
                    type_result = await CredentialPool.detect_account_type(access_token, cred.project_id)
                    account_type = type_result.get("account_type", "unknown")
                    print(f"[检测] {cred.email}: account_type={account_type}, result={type_result}", flush=True)
                except Exception as e:
                    print(f"[检测] {cred.email} 检测账号类型失败: {e}", flush=True)
            
            cred.is_active = is_valid
            # 根据实际模型检测结果设置 tier（Pro 是账号类型，不代表支持 3.0）
            cred.model_tier = "3" if supports_3 else "2.5"
            # 暂时存储在 last_error 字段（后续可以添加专用字段）
            if account_type != "unknown":
                cred.last_error = f"account_type:{account_type}"
            
            # 确保变更被追踪并立即写入
            print(f"[检测] 设置 {cred.email} model_tier={cred.model_tier}, account_type={account_type}, supports_3={supports_3}", flush=True)
            await db.merge(cred)
            await db.flush()
            
            if is_valid:
                results["valid"] += 1
                if supports_3:
                    results["tier3"] += 1
                if account_type == "pro":
                    results["pro"] += 1
                reason = "配额用尽(429)" if resp.status_code == 429 else None
                results["details"].append({
                    "id": cred.id, 
                    "email": cred.email, 
                    "status": "valid", 
                    "tier": cred.model_tier,
                    "account_type": account_type,
                    "note": reason
                })
            else:
                results["invalid"] += 1
                results["details"].append({"id": cred.id, "email": cred.email, "status": "invalid", "reason": f"API 返回 {resp.status_code}"})
        except Exception as e:
            cred.is_active = False
            db.add(cred)
            results["invalid"] += 1
            results["details"].append({"id": cred.id, "email": cred.email, "status": "error", "reason": str(e)[:50]})
    
    await db.commit()
    return results


# Google Gemini CLI 配额参考（每日请求数限制）
# Pro 订阅账号: CLI 总额度 1500，2.5/3.0 共用 250
# 普通账号: 总额度 1000，2.5/3.0 共用 200
QUOTA_LIMITS = {
    "pro": {"total": 1500, "premium": 250},   # Pro 账号
    "free": {"total": 1000, "premium": 200},  # 普通账号
}

# 高级模型（2.5-pro, 3.0 系列）共享 premium 配额
PREMIUM_MODELS = ["gemini-2.5-pro", "gemini-3-pro", "gemini-3-pro-preview", "gemini-3-pro-high", "gemini-3-pro-low", "gemini-3-pro-image"]


@router.get("/credentials/{credential_id}/quota")
async def get_credential_quota(
    credential_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取单个凭证的配额使用情况"""
    # 检查凭证权限
    cred = await db.get(Credential, credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="凭证不存在")
    if cred.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="无权查看此凭证")
    
    # 获取今天的开始时间（北京时间 15:00 = UTC 07:00 重置）
    now = datetime.utcnow()
    today_7am = now.replace(hour=7, minute=0, second=0, microsecond=0)
    # 如果当前时间还没到 UTC 07:00，则从昨天 07:00 开始
    today_start = today_7am if now >= today_7am else today_7am - timedelta(days=1)
    
    # 判断账号类型（从 last_error 字段解析，格式: account_type:pro）
    is_pro = False
    if cred.last_error and "account_type:pro" in cred.last_error:
        is_pro = True
    quota_config = QUOTA_LIMITS["pro"] if is_pro else QUOTA_LIMITS["free"]
    
    # 查询今天该凭证按模型的使用次数
    result = await db.execute(
        select(UsageLog.model, func.count(UsageLog.id).label("count"))
        .where(UsageLog.credential_id == credential_id)
        .where(UsageLog.created_at >= today_start)
        .where(UsageLog.status_code == 200)  # 只统计成功的请求
        .group_by(UsageLog.model)
    )
    usage_by_model = result.all()
    
    # 统计各模型使用情况
    quota_info = []
    total_used = 0
    premium_used = 0
    
    for model, count in usage_by_model:
        if not model:
            continue
        total_used += count
        
        # 获取基础模型名（去掉后缀）
        base_model = model
        for suffix in ["-maxthinking", "-nothinking", "-search"]:
            if base_model.endswith(suffix):
                base_model = base_model.replace(suffix, "")
                break
        
        # 判断是否为高级模型
        is_premium = any(pm in base_model for pm in PREMIUM_MODELS)
        if is_premium:
            premium_used += count
        
        quota_info.append({
            "model": model,
            "used": count,
            "is_premium": is_premium
        })
    
    # 按使用量排序
    quota_info.sort(key=lambda x: -x["used"])
    
    # 计算 Flash 使用量（非高级模型）
    flash_used = total_used - premium_used
    
    # 计算高级模型配额（2.5-pro + 3.0 共享）
    premium_limit = quota_config["premium"]
    premium_remaining = max(0, premium_limit - premium_used)
    premium_percentage = min(100, (premium_remaining / premium_limit) * 100) if premium_limit > 0 else 0
    
    # 计算 Flash 配额（总配额 - 高级配额 = Flash 专用）
    flash_limit = quota_config["total"] - quota_config["premium"]  # 750 或 1300
    flash_remaining = max(0, flash_limit - flash_used)
    flash_percentage = min(100, (flash_remaining / flash_limit) * 100) if flash_limit > 0 else 0
    
    # 总配额
    total_limit = quota_config["total"]
    total_remaining = max(0, total_limit - total_used)
    total_percentage = min(100, (total_remaining / total_limit) * 100) if total_limit > 0 else 0
    
    # 获取下次重置时间（北京时间 15:00 = UTC 07:00）
    next_reset = today_start + timedelta(days=1)
    
    return {
        "credential_id": credential_id,
        "credential_name": cred.name,
        "email": cred.email,
        "account_type": "pro" if is_pro else "free",
        "reset_time": next_reset.isoformat() + "Z",
        "flash": {
            "used": flash_used,
            "limit": flash_limit,
            "remaining": flash_remaining,
            "percentage": round(flash_percentage, 1),
            "note": "2.5-flash 专用"
        },
        "premium": {
            "used": premium_used,
            "limit": premium_limit,
            "remaining": premium_remaining,
            "percentage": round(premium_percentage, 1),
            "note": "2.5-pro 和 3.0 共用"
        },
        "models": quota_info
    }


# ===== 使用统计 =====

@router.get("/stats/overview")
async def get_stats_overview(
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """获取统计概览"""
    now = datetime.utcnow()
    today = now.date()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)
    
    # 今日请求数
    today_result = await db.execute(
        select(func.count(UsageLog.id)).where(func.date(UsageLog.created_at) == today)
    )
    today_requests = today_result.scalar() or 0
    
    # 本周请求数
    week_result = await db.execute(
        select(func.count(UsageLog.id)).where(UsageLog.created_at >= week_ago)
    )
    week_requests = week_result.scalar() or 0
    
    # 本月请求数
    month_result = await db.execute(
        select(func.count(UsageLog.id)).where(UsageLog.created_at >= month_ago)
    )
    month_requests = month_result.scalar() or 0
    
    # 总请求数
    total_result = await db.execute(select(func.count(UsageLog.id)))
    total_requests = total_result.scalar() or 0
    
    # 活跃用户数
    active_users_result = await db.execute(
        select(func.count(func.distinct(UsageLog.user_id))).where(UsageLog.created_at >= week_ago)
    )
    active_users = active_users_result.scalar() or 0
    
    # 凭证统计
    cred_result = await db.execute(select(func.count(Credential.id)))
    total_credentials = cred_result.scalar() or 0
    
    active_cred_result = await db.execute(
        select(func.count(Credential.id)).where(Credential.is_active == True)
    )
    active_credentials = active_cred_result.scalar() or 0
    
    return {
        "requests": {
            "today": today_requests,
            "week": week_requests,
            "month": month_requests,
            "total": total_requests,
        },
        "users": {
            "active_this_week": active_users,
        },
        "credentials": {
            "total": total_credentials,
            "active": active_credentials,
        }
    }


@router.get("/stats/by-model")
async def get_stats_by_model(
    days: int = 7,
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """按模型统计使用量"""
    since = datetime.utcnow() - timedelta(days=days)
    
    result = await db.execute(
        select(UsageLog.model, func.count(UsageLog.id).label("count"))
        .where(UsageLog.created_at >= since)
        .group_by(UsageLog.model)
        .order_by(func.count(UsageLog.id).desc())
    )
    
    return {
        "period_days": days,
        "models": [{"model": row[0] or "unknown", "count": row[1]} for row in result.all()]
    }


@router.get("/stats/by-user")
async def get_stats_by_user(
    days: int = 7,
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """按用户统计使用量"""
    since = datetime.utcnow() - timedelta(days=days)
    
    result = await db.execute(
        select(User.username, func.count(UsageLog.id).label("count"))
        .join(User, UsageLog.user_id == User.id)
        .where(UsageLog.created_at >= since)
        .group_by(User.username)
        .order_by(func.count(UsageLog.id).desc())
        .limit(20)
    )
    
    return {
        "period_days": days,
        "users": [{"username": row[0], "count": row[1]} for row in result.all()]
    }


@router.get("/stats/daily")
async def get_daily_stats(
    days: int = 30,
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """获取每日统计数据（用于图表）"""
    since = datetime.utcnow() - timedelta(days=days)
    
    result = await db.execute(
        select(
            func.date(UsageLog.created_at).label("date"),
            func.count(UsageLog.id).label("count")
        )
        .where(UsageLog.created_at >= since)
        .group_by(func.date(UsageLog.created_at))
        .order_by(func.date(UsageLog.created_at))
    )
    
    return {
        "period_days": days,
        "daily": [{"date": str(row[0]), "count": row[1]} for row in result.all()]
    }


# ===== 配置管理 =====

@router.get("/config")
async def get_config(user: User = Depends(get_current_admin)):
    """获取当前配置"""
    from app.config import settings
    return {
        "allow_registration": settings.allow_registration,
        "discord_only_registration": settings.discord_only_registration,
        "discord_oauth_only": settings.discord_oauth_only,
        "default_daily_quota": settings.default_daily_quota,
        "no_credential_quota": settings.no_credential_quota,
        "credential_reward_quota": settings.credential_reward_quota,
        "base_rpm": settings.base_rpm,
        "contributor_rpm": settings.contributor_rpm,
        "error_retry_count": settings.error_retry_count,
        "admin_username": settings.admin_username,
        "credential_pool_mode": settings.credential_pool_mode,
        "force_donate": settings.force_donate,
        "announcement_enabled": settings.announcement_enabled,
        "announcement_title": settings.announcement_title,
        "announcement_content": settings.announcement_content,
        "announcement_read_seconds": settings.announcement_read_seconds,
    }


@router.get("/announcement")
async def get_announcement():
    """获取公告（公开接口）"""
    from app.config import settings
    if not settings.announcement_enabled:
        return {"enabled": False}
    return {
        "enabled": True,
        "title": settings.announcement_title,
        "content": settings.announcement_content,
        "read_seconds": settings.announcement_read_seconds,
    }


@router.post("/config")
async def update_config(
    allow_registration: Optional[bool] = Form(None),
    discord_only_registration: Optional[bool] = Form(None),
    discord_oauth_only: Optional[bool] = Form(None),
    default_daily_quota: Optional[int] = Form(None),
    no_credential_quota: Optional[int] = Form(None),
    credential_reward_quota: Optional[int] = Form(None),
    base_rpm: Optional[int] = Form(None),
    contributor_rpm: Optional[int] = Form(None),
    error_retry_count: Optional[int] = Form(None),
    credential_pool_mode: Optional[str] = Form(None),
    force_donate: Optional[bool] = Form(None),
    announcement_enabled: Optional[bool] = Form(None),
    announcement_title: Optional[str] = Form(None),
    announcement_content: Optional[str] = Form(None),
    announcement_read_seconds: Optional[int] = Form(None),
    user: User = Depends(get_current_admin)
):
    """更新配置（持久化保存到数据库）"""
    from app.config import settings, save_config_to_db
    
    updated = {}
    if allow_registration is not None:
        settings.allow_registration = allow_registration
        await save_config_to_db("allow_registration", allow_registration)
        updated["allow_registration"] = allow_registration
    if discord_only_registration is not None:
        settings.discord_only_registration = discord_only_registration
        await save_config_to_db("discord_only_registration", discord_only_registration)
        updated["discord_only_registration"] = discord_only_registration
    if discord_oauth_only is not None:
        settings.discord_oauth_only = discord_oauth_only
        await save_config_to_db("discord_oauth_only", discord_oauth_only)
        updated["discord_oauth_only"] = discord_oauth_only
    if default_daily_quota is not None:
        settings.default_daily_quota = default_daily_quota
        await save_config_to_db("default_daily_quota", default_daily_quota)
        updated["default_daily_quota"] = default_daily_quota
    if no_credential_quota is not None:
        settings.no_credential_quota = no_credential_quota
        await save_config_to_db("no_credential_quota", no_credential_quota)
        updated["no_credential_quota"] = no_credential_quota
    if credential_reward_quota is not None:
        settings.credential_reward_quota = credential_reward_quota
        await save_config_to_db("credential_reward_quota", credential_reward_quota)
        updated["credential_reward_quota"] = credential_reward_quota
    if base_rpm is not None:
        settings.base_rpm = base_rpm
        await save_config_to_db("base_rpm", base_rpm)
        updated["base_rpm"] = base_rpm
    if contributor_rpm is not None:
        settings.contributor_rpm = contributor_rpm
        await save_config_to_db("contributor_rpm", contributor_rpm)
        updated["contributor_rpm"] = contributor_rpm
    if credential_pool_mode is not None:
        if credential_pool_mode in ["private", "tier3_shared", "full_shared"]:
            settings.credential_pool_mode = credential_pool_mode
            await save_config_to_db("credential_pool_mode", credential_pool_mode)
            updated["credential_pool_mode"] = credential_pool_mode
        else:
            raise HTTPException(status_code=400, detail="无效的凭证池模式")
    if error_retry_count is not None:
        settings.error_retry_count = error_retry_count
        await save_config_to_db("error_retry_count", error_retry_count)
        updated["error_retry_count"] = error_retry_count
    if force_donate is not None:
        settings.force_donate = force_donate
        await save_config_to_db("force_donate", force_donate)
        updated["force_donate"] = force_donate
    
    # 公告配置
    if announcement_enabled is not None:
        settings.announcement_enabled = announcement_enabled
        await save_config_to_db("announcement_enabled", announcement_enabled)
        updated["announcement_enabled"] = announcement_enabled
    if announcement_title is not None:
        settings.announcement_title = announcement_title
        await save_config_to_db("announcement_title", announcement_title)
        updated["announcement_title"] = announcement_title
    if announcement_content is not None:
        settings.announcement_content = announcement_content
        await save_config_to_db("announcement_content", announcement_content)
        updated["announcement_content"] = announcement_content
    if announcement_read_seconds is not None:
        settings.announcement_read_seconds = announcement_read_seconds
        await save_config_to_db("announcement_read_seconds", announcement_read_seconds)
        updated["announcement_read_seconds"] = announcement_read_seconds
    
    return {"message": "配置已保存", "updated": updated}


# ===== 全站统计（按模型分类）=====

@router.get("/stats/global")
async def get_global_stats(
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """获取全站统计（按模型分类）"""
    now = datetime.utcnow()
    today = now.date()
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(days=1)
    
    # 按模型分类统计（今日）
    model_stats_result = await db.execute(
        select(UsageLog.model, func.count(UsageLog.id).label("count"))
        .where(func.date(UsageLog.created_at) == today)
        .group_by(UsageLog.model)
        .order_by(func.count(UsageLog.id).desc())
    )
    model_stats = [{"model": row[0] or "unknown", "count": row[1]} for row in model_stats_result.all()]
    
    # 分类汇总
    flash_count = sum(s["count"] for s in model_stats if "flash" in s["model"].lower())
    pro_count = sum(s["count"] for s in model_stats if "pro" in s["model"].lower() and "3" not in s["model"])
    tier3_count = sum(s["count"] for s in model_stats if "3" in s["model"])
    
    # 最近1小时请求数
    hour_result = await db.execute(
        select(func.count(UsageLog.id)).where(UsageLog.created_at >= hour_ago)
    )
    hour_requests = hour_result.scalar() or 0
    
    # 今日总请求数
    today_result = await db.execute(
        select(func.count(UsageLog.id)).where(func.date(UsageLog.created_at) == today)
    )
    today_requests = today_result.scalar() or 0
    
    # 凭证统计
    total_creds = await db.execute(select(func.count(Credential.id)))
    active_creds = await db.execute(
        select(func.count(Credential.id)).where(Credential.is_active == True)
    )
    public_creds = await db.execute(
        select(func.count(Credential.id)).where(Credential.is_public == True)
    )
    
    tier3_cred_result = await db.execute(
        select(func.count(Credential.id))
        .where(Credential.model_tier == "3")
        .where(Credential.is_active == True)
    )
    tier3_creds = tier3_cred_result.scalar() or 0
    
    # 活跃用户数（最近24小时）
    active_users_result = await db.execute(
        select(func.count(func.distinct(UsageLog.user_id)))
        .where(UsageLog.created_at >= day_ago)
    )
    active_users = active_users_result.scalar() or 0
    
    return {
        "requests": {
            "last_hour": hour_requests,
            "today": today_requests,
            "by_category": {
                "flash": flash_count,
                "pro_2.5": pro_count,
                "tier_3": tier3_count,
            }
        },
        "credentials": {
            "total": total_creds.scalar() or 0,
            "active": active_creds.scalar() or 0,
            "public": public_creds.scalar() or 0,
            "tier_3": tier3_creds,
        },
        "users": {
            "active_24h": active_users,
        },
        "models": model_stats[:10],  # Top 10 模型
        "pool_mode": settings.credential_pool_mode,
    }
