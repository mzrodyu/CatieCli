from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date

from app.database import get_db
from app.models.user import User, APIKey, UsageLog
from app.services.auth import (
    get_password_hash, authenticate_user, create_access_token,
    get_current_user
)
from app.config import settings

router = APIRouter(prefix="/api/auth", tags=["认证"])


class UserRegister(BaseModel):
    username: str
    password: str
    email: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class APIKeyCreate(BaseModel):
    name: str = "default"


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key: str
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime]


@router.post("/register", response_model=TokenResponse)
async def register(data: UserRegister, db: AsyncSession = Depends(get_db)):
    """用户注册"""
    if not settings.allow_registration:
        raise HTTPException(status_code=403, detail="注册已关闭")
    if settings.discord_only_registration:
        raise HTTPException(status_code=403, detail="仅允许通过 Discord Bot 注册")
    if settings.discord_oauth_only:
        raise HTTPException(status_code=403, detail="仅允许通过 Discord 登录注册，请点击 Discord 登录按钮")
    
    # 检查用户名是否存在
    result = await db.execute(select(User).where(User.username == data.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="用户名已存在")
    
    # 创建用户
    user = User(
        username=data.username,
        email=data.email,
        hashed_password=get_password_hash(data.password),
        daily_quota=settings.default_daily_quota
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    # 自动创建一个API Key
    api_key = APIKey(user_id=user.id, key=APIKey.generate_key(), name="default")
    db.add(api_key)
    await db.commit()
    
    # 生成token
    token = create_access_token(data={"sub": user.username})
    
    return TokenResponse(
        access_token=token,
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
            "daily_quota": user.daily_quota
        }
    )


@router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, db: AsyncSession = Depends(get_db)):
    """用户登录"""
    user = await authenticate_user(db, data.username, data.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="账户已被禁用")
    
    token = create_access_token(data={"sub": user.username})
    
    return TokenResponse(
        access_token=token,
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
            "daily_quota": user.daily_quota
        }
    )


@router.get("/me")
async def get_me(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """获取当前用户信息"""
    # 获取今日使用量
    today = date.today()
    result = await db.execute(
        select(func.count(UsageLog.id))
        .where(UsageLog.user_id == user.id)
        .where(func.date(UsageLog.created_at) == today)
    )
    today_usage = result.scalar() or 0
    
    # 获取用户凭证数量
    cred_result = await db.execute(
        select(func.count(Credential.id))
        .where(Credential.user_id == user.id)
        .where(Credential.is_active == True)
    )
    credential_count = cred_result.scalar() or 0
    
    # 统计公开凭证数量
    public_result = await db.execute(
        select(func.count(Credential.id))
        .where(Credential.user_id == user.id)
        .where(Credential.is_public == True)
        .where(Credential.is_active == True)
    )
    public_credential_count = public_result.scalar() or 0
    
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        "daily_quota": user.daily_quota,
        "today_usage": today_usage,
        "credential_count": credential_count,
        "public_credential_count": public_credential_count,
        "has_public_credentials": public_credential_count > 0,
        "created_at": user.created_at
    }


@router.get("/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """获取用户的API Keys"""
    result = await db.execute(
        select(APIKey).where(APIKey.user_id == user.id).order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()
    return [
        APIKeyResponse(
            id=k.id,
            name=k.name,
            key=k.key,
            is_active=k.is_active,
            created_at=k.created_at,
            last_used_at=k.last_used_at
        )
        for k in keys
    ]


@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    data: APIKeyCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """创建新的API Key"""
    # 限制每个用户最多5个key
    result = await db.execute(
        select(func.count(APIKey.id)).where(APIKey.user_id == user.id)
    )
    count = result.scalar() or 0
    if count >= 5:
        raise HTTPException(status_code=400, detail="最多只能创建5个API Key")
    
    api_key = APIKey(user_id=user.id, key=APIKey.generate_key(), name=data.name)
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    
    return APIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key=api_key.key,
        is_active=api_key.is_active,
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at
    )


@router.delete("/api-keys/{key_id}")
async def delete_api_key(
    key_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """删除API Key"""
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user.id)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key不存在")
    
    await db.delete(api_key)
    await db.commit()
    return {"message": "删除成功"}


@router.post("/api-keys/{key_id}/regenerate", response_model=APIKeyResponse)
async def regenerate_api_key(
    key_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """重新生成API Key"""
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user.id)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key不存在")
    
    # 生成新的 key
    api_key.key = APIKey.generate_key()
    await db.commit()
    await db.refresh(api_key)
    
    return APIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key=api_key.key,
        is_active=api_key.is_active,
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at
    )


# ===== 用户凭证管理 =====
from app.models.user import Credential
from fastapi import UploadFile, File, Form
from typing import List
import json

@router.post("/credentials/upload")
async def upload_credentials(
    files: List[UploadFile] = File(...),
    is_public: bool = Form(default=False),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """上传 JSON 凭证文件（支持多文件）"""
    from app.services.crypto import encrypt_credential
    from app.config import settings
    
    # 强制捐赠模式
    if settings.force_donate:
        is_public = True
    
    if not files:
        raise HTTPException(status_code=400, detail="请选择要上传的文件")
    
    results = []
    success_count = 0
    
    for file in files:
        if not file.filename.endswith('.json'):
            results.append({"filename": file.filename, "status": "error", "message": "只支持 JSON 文件"})
            continue
        
        try:
            content = await file.read()
            cred_data = json.loads(content.decode('utf-8'))
            
            # 验证必要字段
            required_fields = ["refresh_token"]
            missing = [f for f in required_fields if f not in cred_data]
            if missing:
                results.append({"filename": file.filename, "status": "error", "message": f"缺少字段: {', '.join(missing)}"})
                continue
            
            # 创建凭证（加密存储）
            email = cred_data.get("email") or file.filename
            project_id = cred_data.get("project_id", "")
            refresh_token = cred_data.get("refresh_token")
            
            # 去重检查：根据 email 或 refresh_token 判断是否已存在（全局）
            existing = await db.execute(
                select(Credential).where(Credential.email == email)
            )
            if existing.scalar_one_or_none():
                results.append({"filename": file.filename, "status": "skip", "message": f"凭证已存在: {email}"})
                continue
            
            # 也检查 refresh_token 是否重复
            from app.services.crypto import encrypt_credential as enc
            existing_token = await db.execute(
                select(Credential).where(Credential.refresh_token == enc(refresh_token))
            )
            if existing_token.scalar_one_or_none():
                results.append({"filename": file.filename, "status": "skip", "message": f"凭证token已存在: {email}"})
                continue
            
            # 自动验证凭证有效性
            is_valid = False
            model_tier = "2.5"
            verify_msg = ""
            
            try:
                import httpx
                from app.services.credential_pool import CredentialPool
                
                # 创建临时凭证对象用于获取 token
                temp_cred = Credential(
                    api_key=encrypt_credential(cred_data.get("token") or cred_data.get("access_token", "")),
                    refresh_token=encrypt_credential(cred_data.get("refresh_token")),
                    credential_type="oauth"
                )
                
                access_token = await CredentialPool.get_access_token(temp_cred, db)
                if access_token:
                    async with httpx.AsyncClient(timeout=15) as client:
                        # 使用 cloudcode-pa 端点测试（与 gcli2api 一致）
                        test_url = "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
                        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
                        
                        # 先测试 2.5 判断凭证是否有效
                        test_payload_25 = {
                            "model": "gemini-2.5-flash",
                            "project": project_id,
                            "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
                        }
                        resp = await client.post(test_url, headers=headers, json=test_payload_25)
                        
                        if resp.status_code == 200 or resp.status_code == 429:
                            is_valid = True
                            model_tier = "2.5"
                            
                            # 凭证有效，再测试 3.0
                            test_payload_3 = {
                                "model": "gemini-3-pro-preview",
                                "project": project_id,
                                "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
                            }
                            resp3 = await client.post(test_url, headers=headers, json=test_payload_3)
                            
                            if resp3.status_code == 200 or resp3.status_code == 429:
                                model_tier = "3"
                                verify_msg = f"✅ 有效 (等级: 3)"
                            else:
                                verify_msg = f"✅ 有效 (等级: 2.5)"
                        else:
                            verify_msg = f"❌ 无效 ({resp.status_code})"
                else:
                    verify_msg = "❌ 无法获取 token"
            except Exception as e:
                verify_msg = f"⚠️ 验证失败: {str(e)[:30]}"
            
            # 如果要捐赠但凭证无效，不允许
            actual_public = is_public and is_valid
            
            credential = Credential(
                user_id=user.id,
                name=f"Upload - {email}",
                api_key=encrypt_credential(cred_data.get("token") or cred_data.get("access_token", "")),
                refresh_token=encrypt_credential(cred_data.get("refresh_token")),
                project_id=project_id,
                credential_type="oauth",
                email=email,
                is_public=actual_public,
                is_active=is_valid,
                model_tier=model_tier
            )
            db.add(credential)
            
            status_msg = f"上传成功 {verify_msg}"
            if is_public and not is_valid:
                status_msg += " (无效凭证不会捐赠)"
            results.append({"filename": file.filename, "status": "success" if is_valid else "warning", "message": status_msg})
            success_count += 1
            
        except json.JSONDecodeError:
            results.append({"filename": file.filename, "status": "error", "message": "JSON 格式错误"})
        except Exception as e:
            results.append({"filename": file.filename, "status": "error", "message": str(e)})
    
    await db.commit()
    return {"uploaded_count": success_count, "total_count": len(files), "results": results}


@router.get("/credentials")
async def list_my_credentials(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """获取我的凭证列表"""
    result = await db.execute(
        select(Credential).where(Credential.user_id == user.id).order_by(Credential.created_at.desc())
    )
    creds = result.scalars().all()
    
    def parse_account_type(last_error):
        """从 last_error 解析账号类型"""
        if last_error and last_error.startswith("account_type:"):
            return last_error.replace("account_type:", "")
        return "unknown"
    
    return [
        {
            "id": c.id,
            "name": c.name,
            "email": c.email,
            "is_public": c.is_public,
            "is_active": c.is_active,
            "model_tier": c.model_tier or "2.5",
            "account_type": parse_account_type(c.last_error),
            "total_requests": c.total_requests or 0,
            "last_used_at": (c.last_used_at.isoformat() + "Z") if c.last_used_at else None,
            "created_at": (c.created_at.isoformat() + "Z") if c.created_at else None
        }
        for c in creds
    ]


@router.patch("/credentials/{cred_id}")
async def update_my_credential(
    cred_id: int,
    is_public: bool = None,
    is_active: bool = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """更新我的凭证（公开/启用状态）"""
    result = await db.execute(
        select(Credential).where(Credential.id == cred_id, Credential.user_id == user.id)
    )
    cred = result.scalar_one_or_none()
    if not cred:
        raise HTTPException(status_code=404, detail="凭证不存在")
    
    if is_public is not None:
        # 捐赠时必须凭证有效且无错误记录
        if is_public:
            if not cred.is_active:
                raise HTTPException(status_code=400, detail="无效凭证不能捐赠，请先检测")
            # 检查是否有认证错误（403等）
            if cred.last_error and ('403' in cred.last_error or '401' in cred.last_error or '认证' in cred.last_error or '无效' in cred.last_error):
                raise HTTPException(status_code=400, detail="凭证存在认证错误，不能捐赠")
            # 捐赠奖励配额（只有从私有变公开才奖励）
            if not cred.is_public:
                user.daily_quota += settings.credential_reward_quota
                print(f"[凭证捐赠] 用户 {user.username} 获得 {settings.credential_reward_quota} 额度奖励", flush=True)
        else:
            # 取消捐赠扣除配额
            if cred.is_public:
                user.daily_quota = max(settings.default_daily_quota, user.daily_quota - settings.credential_reward_quota)
                print(f"[取消捐赠] 用户 {user.username} 扣除 {settings.credential_reward_quota} 额度", flush=True)
        cred.is_public = is_public
    if is_active is not None:
        # 手动启用时清除错误（但不清除403错误记录）
        cred.is_active = is_active
    
    await db.commit()
    return {"message": "更新成功", "is_public": cred.is_public, "is_active": cred.is_active}


@router.delete("/credentials/{cred_id}")
async def delete_my_credential(
    cred_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """删除我的凭证"""
    result = await db.execute(
        select(Credential).where(Credential.id == cred_id, Credential.user_id == user.id)
    )
    cred = result.scalar_one_or_none()
    if not cred:
        raise HTTPException(status_code=404, detail="凭证不存在")
    
    # 如果是公开凭证，删除时扣除配额
    if cred.is_public:
        user.daily_quota = max(settings.default_daily_quota, user.daily_quota - settings.credential_reward_quota)
        print(f"[删除凭证] 用户 {user.username} 扣除 {settings.credential_reward_quota} 额度", flush=True)
    
    await db.delete(cred)
    await db.commit()
    return {"message": "删除成功"}


@router.get("/credentials/{cred_id}/export")
async def export_my_credential(
    cred_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """导出我的凭证为 JSON 格式"""
    from app.services.crypto import decrypt_credential
    
    result = await db.execute(
        select(Credential).where(Credential.id == cred_id, Credential.user_id == user.id)
    )
    cred = result.scalar_one_or_none()
    if not cred:
        raise HTTPException(status_code=404, detail="凭证不存在")
    
    # 构建 gcli 兼容的 JSON 格式
    cred_data = {
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret,
        "refresh_token": decrypt_credential(cred.refresh_token) if cred.refresh_token else "",
        "token": decrypt_credential(cred.api_key) if cred.api_key else "",
        "project_id": cred.project_id or "",
        "email": cred.email or "",
        "type": "authorized_user"
    }
    
    return cred_data


@router.post("/credentials/{cred_id}/verify")
async def verify_my_credential(
    cred_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """验证我的凭证有效性和模型等级"""
    import httpx
    from app.services.credential_pool import CredentialPool
    
    try:
        print(f"[凭证检测] 开始检测凭证 {cred_id}", flush=True)
        
        result = await db.execute(
            select(Credential).where(Credential.id == cred_id, Credential.user_id == user.id)
        )
        cred = result.scalar_one_or_none()
        if not cred:
            return {"is_valid": False, "model_tier": "2.5", "error": "凭证不存在", "supports_3": False}
        
        print(f"[凭证检测] 凭证 {cred.email} 开始获取 token", flush=True)
        
        # 获取 access token
        try:
            access_token = await CredentialPool.get_access_token(cred, db)
        except Exception as e:
            print(f"[凭证检测] 获取 token 异常: {e}", flush=True)
            cred.is_active = False
            cred.last_error = f"获取 token 异常: {str(e)[:50]}"
            await db.commit()
            return {
                "is_valid": False,
                "model_tier": cred.model_tier or "2.5",
                "error": f"获取 token 异常: {str(e)[:50]}",
                "supports_3": False
            }
        
        if not access_token:
            cred.is_active = False
            cred.last_error = "无法获取 access token"
            await db.commit()
            return {
                "is_valid": False,
                "model_tier": cred.model_tier or "2.5",
                "error": "无法获取 access token",
                "supports_3": False
            }
        
        print(f"[凭证检测] 获取到 token，开始测试", flush=True)
        
        # 先检测账号类型（无论 API 是否可用）
        account_type = "unknown"
        type_result = None
        if cred.project_id:
            try:
                type_result = await CredentialPool.detect_account_type(access_token, cred.project_id)
                account_type = type_result.get("account_type", "unknown")
                print(f"[凭证检测] 账号类型检测结果: {type_result}", flush=True)
            except Exception as e:
                print(f"[凭证检测] 检测账号类型失败: {e}", flush=True)
        
        # 测试 Gemini API
        is_valid = False
        supports_3 = False
        error_msg = None
        
        async with httpx.AsyncClient(timeout=15) as client:
            # 使用 cloudcode-pa 端点测试（与 gcli2api 一致）
            try:
                test_url = "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
                headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
                
                # 先测试 2.5 判断凭证是否有效
                test_payload_25 = {
                    "model": "gemini-2.5-flash",
                    "project": cred.project_id or "",
                    "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
                }
                resp = await client.post(test_url, headers=headers, json=test_payload_25)
                print(f"[凭证检测] gemini-2.5-flash 响应: {resp.status_code}", flush=True)
                
                if resp.status_code == 200 or resp.status_code == 429:
                    is_valid = True
                    # 429 是检测时触发的限速，不是真正用完配额，不记录错误
                    
                    # 凭证有效，再测试 3.0
                    test_payload_3 = {
                        "model": "gemini-3-pro-preview",
                        "project": cred.project_id or "",
                        "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
                    }
                    resp3 = await client.post(test_url, headers=headers, json=test_payload_3)
                    print(f"[凭证检测] gemini-3-pro-preview 响应: {resp3.status_code}", flush=True)
                    
                    if resp3.status_code == 200 or resp3.status_code == 429:
                        supports_3 = True
                    else:
                        supports_3 = False
                elif resp.status_code in [401, 403]:
                    error_msg = f"认证失败 ({resp.status_code})"
                else:
                    error_msg = f"API 返回 {resp.status_code}"
            except Exception as e:
                error_msg = f"请求异常: {str(e)[:30]}"
        
        # 更新凭证状态
        cred.is_active = is_valid
        cred.model_tier = "3" if supports_3 else "2.5"
        # 保存 account_type，error_msg 附加在后面
        if account_type != "unknown":
            cred.last_error = f"account_type:{account_type}"
            if error_msg:
                cred.last_error += f" | {error_msg}"
        elif error_msg:
            cred.last_error = error_msg
        await db.commit()
        
        # 获取存储空间信息
        storage_gb = type_result.get("storage_gb") if type_result else None
        
        print(f"[凭证检测] 完成: valid={is_valid}, tier={cred.model_tier}, type={account_type}, storage={storage_gb}GB", flush=True)
        
        return {
            "is_valid": is_valid,
            "model_tier": cred.model_tier,
            "supports_3": supports_3,
            "account_type": account_type,
            "storage_gb": storage_gb,
            "error": error_msg
        }
    except Exception as e:
        print(f"[凭证检测] 严重异常: {e}", flush=True)
        return {
            "is_valid": False,
            "model_tier": "2.5",
            "error": f"检测异常: {str(e)[:50]}",
            "supports_3": False
        }


# ===== Discord Bot API =====

class DiscordRegister(BaseModel):
    username: str
    password: str
    discord_id: str
    discord_name: str


@router.post("/register-discord")
async def register_from_discord(data: DiscordRegister, db: AsyncSession = Depends(get_db)):
    """Discord Bot 注册接口"""
    # 检查 Discord ID 是否已注册
    result = await db.execute(select(User).where(User.discord_id == data.discord_id))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="该 Discord 账号已注册")
    
    # 检查用户名是否存在
    result = await db.execute(select(User).where(User.username == data.username.lower()))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="用户名已存在")
    
    # 验证用户名格式
    if not data.username.isalnum() or len(data.username) < 3 or len(data.username) > 20:
        raise HTTPException(status_code=400, detail="用户名必须是3-20位字母数字")
    
    # 创建用户
    user = User(
        username=data.username.lower(),
        hashed_password=get_password_hash(data.password),
        discord_id=data.discord_id,
        discord_name=data.discord_name,
        daily_quota=settings.default_daily_quota
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    # 创建 API Key
    api_key = APIKey(user_id=user.id, key=APIKey.generate_key(), name="Discord")
    db.add(api_key)
    await db.commit()
    
    return {
        "message": "注册成功",
        "username": user.username,
        "api_key": api_key.key
    }


@router.get("/check-discord/{discord_id}")
async def check_discord_user(discord_id: str, db: AsyncSession = Depends(get_db)):
    """检查 Discord 用户是否已注册"""
    result = await db.execute(select(User).where(User.discord_id == discord_id))
    user = result.scalar_one_or_none()
    
    if user:
        # 获取 API Key
        key_result = await db.execute(select(APIKey).where(APIKey.user_id == user.id, APIKey.is_active == True))
        api_key = key_result.scalar_one_or_none()
        
        return {
            "exists": True,
            "username": user.username,
            "api_key": api_key.key if api_key else None
        }
    return {"exists": False}


@router.get("/discord-key/{discord_id}")
async def get_discord_user_key(discord_id: str, db: AsyncSession = Depends(get_db)):
    """获取 Discord 用户的 API Key"""
    result = await db.execute(select(User).where(User.discord_id == discord_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户未注册")
    
    # 获取 API Key
    key_result = await db.execute(select(APIKey).where(APIKey.user_id == user.id, APIKey.is_active == True))
    api_key = key_result.scalar_one_or_none()
    
    if not api_key:
        # 创建新 Key
        api_key = APIKey(user_id=user.id, key=APIKey.generate_key(), name="Discord")
        db.add(api_key)
        await db.commit()
    
    # 获取今日用量
    today = date.today()
    usage_result = await db.execute(
        select(func.count(UsageLog.id))
        .where(UsageLog.user_id == user.id)
        .where(func.date(UsageLog.created_at) == today)
    )
    today_usage = usage_result.scalar() or 0
    
    return {
        "username": user.username,
        "api_key": api_key.key,
        "daily_quota": user.daily_quota,
        "today_usage": today_usage
    }


@router.post("/discord-key/{discord_id}/regenerate")
async def regenerate_discord_user_key(discord_id: str, db: AsyncSession = Depends(get_db)):
    """重新生成 Discord 用户的 API Key"""
    result = await db.execute(select(User).where(User.discord_id == discord_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户未注册")
    
    # 获取现有 API Key
    key_result = await db.execute(select(APIKey).where(APIKey.user_id == user.id, APIKey.is_active == True))
    api_key = key_result.scalar_one_or_none()
    
    if api_key:
        # 重新生成
        api_key.key = APIKey.generate_key()
    else:
        # 创建新 Key
        api_key = APIKey(user_id=user.id, key=APIKey.generate_key(), name="Discord")
        db.add(api_key)
    
    await db.commit()
    
    return {
        "username": user.username,
        "api_key": api_key.key,
        "message": "API Key 已重新生成"
    }


@router.get("/discord-stats/{discord_id}")
async def get_discord_user_stats(discord_id: str, db: AsyncSession = Depends(get_db)):
    """获取 Discord 用户统计"""
    from app.models.user import Credential
    
    result = await db.execute(select(User).where(User.discord_id == discord_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户未注册")
    
    # 今日用量
    today = date.today()
    usage_result = await db.execute(
        select(func.count(UsageLog.id))
        .where(UsageLog.user_id == user.id)
        .where(func.date(UsageLog.created_at) == today)
    )
    today_usage = usage_result.scalar() or 0
    
    # 总请求数
    total_result = await db.execute(
        select(func.count(UsageLog.id)).where(UsageLog.user_id == user.id)
    )
    total_requests = total_result.scalar() or 0
    
    # 凭证数量
    cred_result = await db.execute(
        select(func.count(Credential.id)).where(Credential.user_id == user.id)
    )
    credentials_count = cred_result.scalar() or 0
    
    return {
        "username": user.username,
        "discord_id": user.discord_id,
        "discord_name": user.discord_name,
        "daily_quota": user.daily_quota,
        "today_usage": today_usage,
        "total_requests": total_requests,
        "credentials_count": credentials_count,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None
    }


# ===== Discord OAuth 登录/注册 =====

@router.get("/discord/login")
async def discord_login_url():
    """获取 Discord OAuth 登录 URL"""
    if not settings.discord_client_id or not settings.discord_redirect_uri:
        raise HTTPException(status_code=503, detail="Discord OAuth 未配置")
    
    import urllib.parse
    params = {
        "client_id": settings.discord_client_id,
        "redirect_uri": settings.discord_redirect_uri,
        "response_type": "code",
        "scope": "identify"
    }
    url = f"https://discord.com/api/oauth2/authorize?{urllib.parse.urlencode(params)}"
    return {"url": url}


@router.get("/discord/callback")
async def discord_callback(code: str, db: AsyncSession = Depends(get_db)):
    """Discord OAuth 回调处理"""
    import httpx
    
    if not settings.discord_client_id or not settings.discord_client_secret:
        raise HTTPException(status_code=503, detail="Discord OAuth 未配置")
    
    # 1. 用 code 换取 access_token
    token_url = "https://discord.com/api/oauth2/token"
    data = {
        "client_id": settings.discord_client_id,
        "client_secret": settings.discord_client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.discord_redirect_uri
    }
    
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(token_url, data=data)
        if token_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Discord 授权失败")
        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        
        # 2. 获取用户信息
        user_resp = await client.get(
            "https://discord.com/api/users/@me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if user_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="获取 Discord 用户信息失败")
        discord_user = user_resp.json()
    
    discord_id = discord_user["id"]
    discord_name = f"{discord_user['username']}"
    
    # 3. 查找或创建用户
    result = await db.execute(select(User).where(User.discord_id == discord_id))
    user = result.scalar_one_or_none()
    
    if not user:
        # 新用户注册
        if not settings.allow_registration:
            raise HTTPException(status_code=403, detail="注册已关闭")
        
        # 用 Discord ID 作为用户名
        username = f"discord_{discord_id}"
        
        # 检查用户名是否已存在
        existing = await db.execute(select(User).where(User.username == username))
        if existing.scalar_one_or_none():
            username = f"discord_{discord_id}_{int(datetime.utcnow().timestamp())}"
        
        user = User(
            username=username,
            hashed_password="",  # Discord 用户无密码
            discord_id=discord_id,
            discord_name=discord_name,
            daily_quota=settings.default_daily_quota,
            is_active=True
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    else:
        # 更新 Discord 名称
        if user.discord_name != discord_name:
            user.discord_name = discord_name
            await db.commit()
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="账户已被禁用")
    
    # 4. 生成 JWT token
    jwt_token = create_access_token(data={"sub": user.username})
    
    # 5. 返回 HTML 页面，通过 postMessage 传递 token 给前端
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>登录成功</title></head>
    <body>
    <script>
        window.opener.postMessage({{
            type: 'discord_login',
            token: '{jwt_token}',
            user: {{
                id: {user.id},
                username: '{user.username}',
                discord_id: '{user.discord_id}',
                discord_name: '{discord_name}',
                is_admin: {'true' if user.is_admin else 'false'}
            }}
        }}, '*');
        window.close();
    </script>
    <p>登录成功，正在跳转...</p>
    </body>
    </html>
    """
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html)


@router.get("/discord/config")
async def get_discord_config():
    """获取 Discord OAuth 配置状态"""
    return {
        "enabled": bool(settings.discord_client_id and settings.discord_client_secret),
        "client_id": settings.discord_client_id if settings.discord_client_id else None,
        "discord_oauth_only": settings.discord_oauth_only
    }
