from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional
import httpx
import secrets
import json
from urllib.parse import urlencode, quote

from app.database import get_db
from app.models.user import User, Credential
from app.services.auth import get_current_user, get_current_admin
from app.config import settings

router = APIRouter(prefix="/api/oauth", tags=["OAuth认证"])

# OAuth 配置
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# OAuth 所需的 scope
OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

# 存储 OAuth state (生产环境应使用 Redis)
oauth_states = {}


class OAuthConfig(BaseModel):
    client_id: str
    client_secret: str


class CallbackURLRequest(BaseModel):
    callback_url: str
    is_public: bool = False  # 是否捐赠到公共池


@router.get("/config")
async def get_oauth_config(admin: User = Depends(get_current_admin)):
    """获取 OAuth 配置状态"""
    return {
        "configured": bool(settings.google_client_id and settings.google_client_secret),
        "client_id": settings.google_client_id[:20] + "..." if settings.google_client_id else None
    }


@router.post("/config")
async def set_oauth_config(
    config: OAuthConfig,
    admin: User = Depends(get_current_admin)
):
    """设置 OAuth 配置 (仅运行时生效)"""
    settings.google_client_id = config.client_id
    settings.google_client_secret = config.client_secret
    return {"message": "配置已更新"}


@router.get("/auth-url")
async def get_auth_url(
    request: Request,
    get_all_projects: bool = False,
    user: User = Depends(get_current_user)
):
    """获取 OAuth 认证链接（需登录）"""
    return await _get_auth_url_impl(get_all_projects, user.id if user else None)


@router.get("/auth-url-public")
async def get_auth_url_public(get_all_projects: bool = False):
    """获取 OAuth 认证链接（公开，用于 Discord Bot）"""
    return await _get_auth_url_impl(get_all_projects, None)


async def _get_auth_url_impl(get_all_projects: bool, user_id: int = None):
    """获取 OAuth 认证链接实现"""
    if not settings.google_client_id:
        raise HTTPException(status_code=400, detail="未配置 OAuth Client ID")
    
    # 生成 state
    state = secrets.token_urlsafe(32)
    oauth_states[state] = {
        "user_id": user_id,
        "get_all_projects": get_all_projects
    }
    
    # Gemini CLI 官方 OAuth 固定使用 localhost:8080 作为回调
    redirect_uri = "http://localhost:8080"
    
    # 构建 OAuth URL
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(OAUTH_SCOPES),
        "response_type": "code",
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state
    }
    
    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    
    return {
        "auth_url": auth_url,
        "state": state,
        "redirect_uri": redirect_uri
    }


@router.get("/callback")
async def oauth_callback(
    code: str,
    state: str,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """OAuth 回调处理"""
    # 验证 state
    state_data = oauth_states.pop(state, None)
    if not state_data:
        return RedirectResponse(url="/dashboard?error=invalid_state")

    user_id = state_data.get("user_id")
    if not user_id:
        return RedirectResponse(url="/dashboard?error=no_user_associated")

    try:
        # 获取 access token
        redirect_uri = "http://localhost:8080"
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri
                }
            )
            token_data = token_response.json()

        if "error" in token_data:
            error_msg = token_data.get('error_description', 'token_error')
            return RedirectResponse(url=f"/dashboard?error={quote(error_msg)}")

        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        # 获取用户信息
        async with httpx.AsyncClient() as client:
            userinfo_response = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            userinfo = userinfo_response.json()
        email = userinfo.get("email", "unknown")

        # 获取项目ID并启用API
        project_id = ""
        try:
            async with httpx.AsyncClient() as client:
                projects_response = await client.get(
                    "https://cloudresourcemanager.googleapis.com/v1/projects",
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={"filter": "lifecycleState:ACTIVE"}
                )
                projects_data = projects_response.json()
                projects = projects_data.get("projects", [])
                if projects:
                    project_id = projects[0].get("projectId", "")
                    # 自动启用服务
                    for service in ["geminicloudassist.googleapis.com", "cloudaicompanion.googleapis.com"]:
                        await client.post(
                            f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services/{service}:enable",
                            headers={"Authorization": f"Bearer {access_token}"}
                        )
        except Exception as e:
            print(f"获取项目或启用服务失败: {e}", flush=True)

        # 加密并保存凭证
        from app.services.crypto import encrypt_credential
        credential = Credential(
            user_id=user_id,
            name=f"OAuth - {email}",
            api_key=encrypt_credential(access_token),
            refresh_token=encrypt_credential(refresh_token),
            project_id=project_id,
            credential_type="oauth",
            email=email,
            is_public=False # 默认为私有
        )
        
        # 验证凭证能力
        from app.services.credential_pool import CredentialPool
        db.add(credential)
        await db.flush()
        verify_result = await CredentialPool.verify_credential_capabilities(credential, db)

        credential.is_active = verify_result.get("is_valid", False)
        credential.model_tier = verify_result.get("model_tier", "2.5")
        
        await db.commit()

        if credential.is_active:
            return RedirectResponse(url=f"/dashboard?oauth=success&tier={credential.model_tier}")
        else:
            error_msg = verify_result.get("error", "凭证无效")
            return RedirectResponse(url=f"/dashboard?oauth=fail&error={quote(error_msg)}")

    except Exception as e:
        return RedirectResponse(url=f"/dashboard?oauth=error&msg={quote(str(e)[:50])}")


@router.post("/from-callback-url")
async def credential_from_callback_url(
    data: CallbackURLRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """从回调 URL 手动获取凭证 (适用于无法直接回调的场景)"""
    from urllib.parse import urlparse, parse_qs
    
    import sys
    print(f"收到回调URL: {data.callback_url}", flush=True)  # 调试
    
    try:
        parsed = urlparse(data.callback_url)
        params = parse_qs(parsed.query)
        
        code = params.get("code", [None])[0]
        print(f"解析到code: {code[:20] if code else 'None'}...", flush=True)  # 调试
        
        if not code:
            raise HTTPException(status_code=400, detail="URL 中未找到 code 参数")
        
        # 获取 access token (使用 Gemini CLI 官方 redirect_uri)
        redirect_uri = "http://localhost:8080"
        
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri
                }
            )
            token_data = token_response.json()
        
        print(f"Token response: {token_data}", flush=True)  # 调试日志
        
        if "error" in token_data:
            error_msg = token_data.get("error_description") or token_data.get("error", "获取 token 失败")
            raise HTTPException(status_code=400, detail=error_msg)
        
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        
        # 获取用户信息
        async with httpx.AsyncClient() as client:
            userinfo_response = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            userinfo = userinfo_response.json()
        
        email = userinfo.get("email", "unknown")
        
        # 获取用户的 Google Cloud 项目列表
        project_id = ""
        try:
            async with httpx.AsyncClient() as client:
                projects_response = await client.get(
                    "https://cloudresourcemanager.googleapis.com/v1/projects",
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={"filter": "lifecycleState:ACTIVE"}
                )
                projects_data = projects_response.json()
                projects = projects_data.get("projects", [])
                
                if projects:
                    # 选择第一个项目，或者找 default 项目
                    for p in projects:
                        if "default" in p.get("projectId", "").lower() or "default" in p.get("name", "").lower():
                            project_id = p.get("projectId")
                            break
                    if not project_id:
                        project_id = projects[0].get("projectId", "")
                    print(f"获取到 project_id: {project_id}", flush=True)
                    
                    # 自动启用必需的 API 服务
                    required_services = [
                        "geminicloudassist.googleapis.com",
                        "cloudaicompanion.googleapis.com",
                    ]
                    for service in required_services:
                        try:
                            enable_url = f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services/{service}:enable"
                            enable_response = await client.post(
                                enable_url,
                                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                                json={}
                            )
                            if enable_response.status_code in [200, 201]:
                                print(f"✅ 已启用服务: {service}", flush=True)
                            else:
                                print(f"⚠️ 启用服务 {service}: {enable_response.status_code}", flush=True)
                        except Exception as se:
                            print(f"启用服务 {service} 失败: {se}", flush=True)
        except Exception as e:
            print(f"获取项目列表失败: {e}", flush=True)
        
        # 保存凭证（关联当前用户，加密存储）
        from app.services.crypto import encrypt_credential
        credential = Credential(
            user_id=user.id,
            name=f"OAuth - {email}",
            api_key=encrypt_credential(access_token),
            refresh_token=encrypt_credential(refresh_token),
            project_id=project_id,  # 保存 project_id
            credential_type="oauth",
            email=email,
            is_public=data.is_public  # 是否捐赠到公共池
        )
        
        # 使用统一函数进行验证
        from app.services.credential_pool import CredentialPool
        db.add(credential)
        await db.flush() # 分配ID
        verify_result = await CredentialPool.verify_credential_capabilities(credential, db)
        
        is_valid = verify_result.get("is_valid", False)
        detected_tier = verify_result.get("model_tier", "2.5")
        
        # 根据验证结果更新状态
        credential.is_active = is_valid
        credential.model_tier = detected_tier
        if data.is_public and not is_valid:
            credential.is_public = False
        
        # 奖励用户额度（如果捐赠到公共池且凭证有效）
        reward_quota = 0
        if data.is_public and is_valid:
            reward_quota = settings.credential_reward_quota
            user.daily_quota += reward_quota
            print(f"[凭证奖励] 用户 {user.username} 获得 {reward_quota} 额度奖励", flush=True)
        
        await db.commit()
        
        # 如果捐赠，通知更新
        if data.is_public:
            from app.services.websocket import notify_credential_update
            await notify_credential_update()
        
        # 构建返回消息
        msg_parts = ["凭证获取成功"]
        if not is_valid:
            msg_parts.append("⚠️ 凭证验证失败，已禁用")
        else:
            msg_parts.append(f"✅ 等级: {detected_tier}")
            if detected_tier == "3":
                msg_parts.append("🎉 支持 Gemini 3！")
        if reward_quota:
            msg_parts.append(f"奖励 +{reward_quota} 额度")
        
        return {
            "message": "，".join(msg_parts), 
            "email": email,
            "is_public": data.is_public,
            "credential_id": credential.id,
            "reward_quota": reward_quota,
            "is_valid": is_valid,
            "model_tier": detected_tier
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"处理失败: {str(e)}")


class DiscordCallbackRequest(BaseModel):
    callback_url: str
    discord_id: str
    is_public: bool = True  # Discord 默认捐赠


@router.post("/from-callback-url-discord")
async def credential_from_callback_url_discord(
    data: DiscordCallbackRequest,
    db: AsyncSession = Depends(get_db)
):
    """从回调 URL 获取凭证 (Discord Bot 专用，通过 Discord ID 关联用户)"""
    from urllib.parse import urlparse, parse_qs
    from sqlalchemy import select
    
    # 查找 Discord 用户
    result = await db.execute(select(User).where(User.discord_id == data.discord_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="请先使用 /register 注册账号")
    
    try:
        parsed = urlparse(data.callback_url)
        params = parse_qs(parsed.query)
        
        code = params.get("code", [None])[0]
        if not code:
            raise HTTPException(status_code=400, detail="URL 中未找到 code 参数，请确保复制完整的回调 URL")
        
        # 获取 access token
        redirect_uri = "http://localhost:8080"
        
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri
                }
            )
            token_data = token_response.json()
        
        if "error" in token_data:
            error_msg = token_data.get("error_description") or token_data.get("error", "获取 token 失败")
            if "invalid_grant" in str(error_msg).lower():
                raise HTTPException(status_code=400, detail="授权码已过期或已使用，请重新获取授权链接")
            raise HTTPException(status_code=400, detail=error_msg)
        
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        
        # 获取用户信息
        async with httpx.AsyncClient() as client:
            userinfo_response = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            userinfo = userinfo_response.json()
        
        email = userinfo.get("email", "unknown")
        
        # 获取项目 ID
        project_id = ""
        try:
            async with httpx.AsyncClient() as client:
                projects_response = await client.get(
                    "https://cloudresourcemanager.googleapis.com/v1/projects",
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={"filter": "lifecycleState:ACTIVE"}
                )
                projects_data = projects_response.json()
                projects = projects_data.get("projects", [])
                
                if projects:
                    for p in projects:
                        if "default" in p.get("projectId", "").lower():
                            project_id = p.get("projectId")
                            break
                    if not project_id:
                        project_id = projects[0].get("projectId", "")
                    
                    # 启用必需服务
                    for service in ["geminicloudassist.googleapis.com", "cloudaicompanion.googleapis.com"]:
                        try:
                            await client.post(
                                f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services/{service}:enable",
                                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                                json={}
                            )
                        except:
                            pass
        except Exception as e:
            print(f"[Discord OAuth] 获取项目失败: {e}", flush=True)
        
        # 保存凭证
        from app.services.crypto import encrypt_credential
        credential = Credential(
            user_id=user.id,
            name=f"Discord - {email}",
            api_key=encrypt_credential(access_token),
            refresh_token=encrypt_credential(refresh_token),
            project_id=project_id,
            credential_type="oauth",
            email=email,
            is_public=data.is_public
        )
        
        # 使用统一函数进行验证
        from app.services.credential_pool import CredentialPool
        db.add(credential)
        await db.flush() # 分配ID
        verify_result = await CredentialPool.verify_credential_capabilities(credential, db)
        
        is_valid = verify_result.get("is_valid", False)
        detected_tier = verify_result.get("model_tier", "2.5")

        credential.is_active = is_valid
        credential.model_tier = detected_tier
        if data.is_public and not is_valid:
            credential.is_public = False
        
        # 奖励额度
        reward_quota = 0
        if data.is_public and is_valid:
            reward_quota = settings.credential_reward_quota
            user.daily_quota += reward_quota
        
        await db.commit()
        
        return {
            "success": True,
            "email": email,
            "is_valid": is_valid,
            "model_tier": detected_tier,
            "reward_quota": reward_quota,
            "message": f"凭证添加成功！等级: {detected_tier}" + (f" 🎉 奖励 +{reward_quota} 额度" if reward_quota else "")
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"处理失败: {str(e)}")
