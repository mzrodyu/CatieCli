from typing import Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, or_
from app.models.user import Credential
from app.services.crypto import decrypt_credential, encrypt_credential
from app.config import settings
import httpx


class CredentialPool:
    """Gemini凭证池管理"""
    
    @staticmethod
    def get_required_tier(model: str) -> str:
        """根据模型名确定需要的凭证等级"""
        model_lower = model.lower()
        # gemini-3-xxx 模型需要 3 等级凭证
        if "gemini-3-" in model_lower or "/gemini-3-" in model_lower:
            return "3"
        return "2.5"
    
    @staticmethod
    async def check_user_has_tier3_creds(db: AsyncSession, user_id: int) -> bool:
        """检查用户是否有 3.0 等级的凭证"""
        result = await db.execute(
            select(Credential)
            .where(Credential.user_id == user_id)
            .where(Credential.model_tier == "3")
            .where(Credential.is_active == True)
            .limit(1)
        )
        return result.scalar_one_or_none() is not None
    
    @staticmethod
    async def get_available_credential(
        db: AsyncSession, 
        user_id: int = None,
        user_has_public_creds: bool = False,
        model: str = None,
        exclude_ids: set = None
    ) -> Optional[Credential]:
        """
        获取一个可用的凭证 (根据模式 + 轮询策略 + 模型等级匹配)
        
        模式:
        - private: 只能用自己的凭证
        - tier3_shared: 有3.0凭证的用户可用公共3.0池
        - full_shared: 大锅饭模式（捐赠凭证即可用所有公共池）
        
        模型等级规则:
        - 3.0 模型只能用 3.0 等级的凭证
        - 2.5 模型可以用任何等级的凭证
        
        exclude_ids: 排除的凭证ID集合（用于重试时跳过已失败的凭证）
        """
        pool_mode = settings.credential_pool_mode
        query = select(Credential).where(Credential.is_active == True)
        
        # 排除已尝试过的凭证
        if exclude_ids:
            query = query.where(~Credential.id.in_(exclude_ids))
        
        # 根据模型确定需要的凭证等级
        required_tier = CredentialPool.get_required_tier(model) if model else "2.5"
        
        if required_tier == "3":
            # gemini-3 模型只能用 3 等级凭证
            query = query.where(Credential.model_tier == "3")
        # 2.5 模型可以用任何等级凭证（不添加额外筛选）
        
        # 根据模式决定凭证访问规则
        if pool_mode == "private":
            # 私有模式：只能用自己的凭证
            query = query.where(Credential.user_id == user_id)
        
        elif pool_mode == "tier3_shared":
            # 3.0共享模式
            if required_tier == "3":
                # 请求 3.0 模型：检查用户是否有 3.0 凭证
                user_has_tier3 = await CredentialPool.check_user_has_tier3_creds(db, user_id)
                if user_has_tier3:
                    # 有 3.0 凭证，可以用公共 3.0 池 + 自己的
                    query = query.where(
                        or_(
                            Credential.is_public == True,
                            Credential.user_id == user_id
                        )
                    )
                else:
                    # 没有 3.0 凭证，只能用自己的
                    query = query.where(Credential.user_id == user_id)
            else:
                # 请求 2.5 模型：无条件允许使用所有公共池 + 自己的
                query = query.where(
                    or_(
                        Credential.is_public == True,
                        Credential.user_id == user_id
                    )
                )
        
        else:  # full_shared (大锅饭模式)
            if user_has_public_creds:
                # 用户有贡献，可以用所有公共凭证 + 自己的私有凭证
                query = query.where(
                    or_(
                        Credential.is_public == True,
                        Credential.user_id == user_id
                    )
                )
            else:
                # 用户没有贡献，只能用自己的凭证
                query = query.where(Credential.user_id == user_id)
        
        result = await db.execute(
            query.order_by(Credential.last_used_at.asc().nullsfirst())
        )
        credentials = result.scalars().all()
        
        if not credentials:
            return None
        
        # 选择最久未使用的凭证
        credential = credentials[0]
        
        # 更新使用时间和计数
        credential.last_used_at = datetime.utcnow()
        credential.total_requests += 1
        await db.commit()
        
        return credential
    
    @staticmethod
    async def check_user_has_public_creds(db: AsyncSession, user_id: int) -> bool:
        """检查用户是否有公开的凭证（是否参与大锅饭）"""
        result = await db.execute(
            select(Credential)
            .where(Credential.user_id == user_id)
            .where(Credential.is_public == True)
            .where(Credential.is_active == True)
            .limit(1)
        )
        return result.scalar_one_or_none() is not None
    
    @staticmethod
    async def refresh_access_token(credential: Credential) -> Optional[str]:
        """
        使用 refresh_token 刷新 access_token
        返回新的 access_token，失败返回 None
        """
        refresh_token = decrypt_credential(credential.refresh_token)
        if not refresh_token:
            print(f"[Token刷新] refresh_token 解密失败", flush=True)
            return None
        
        print(f"[Token刷新] 开始刷新 token, refresh_token 前20字符: {refresh_token[:20]}...", flush=True)
        
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "client_id": settings.google_client_id,
                        "client_secret": settings.google_client_secret,
                        "refresh_token": refresh_token,
                        "grant_type": "refresh_token"
                    }
                )
                data = response.json()
                print(f"[Token刷新] 响应状态: {response.status_code}", flush=True)
                
                if "access_token" in data:
                    print(f"[Token刷新] 刷新成功!", flush=True)
                    return data["access_token"]
                print(f"[Token刷新] 刷新失败: {data.get('error', 'unknown')}", flush=True)
                return None
        except Exception as e:
            print(f"[Token刷新] 异常: {e}", flush=True)
            return None
    
    @staticmethod
    async def get_access_token(credential: Credential, db: AsyncSession) -> Optional[str]:
        """
        获取可用的 access_token
        优先使用缓存的，过期则刷新
        """
        # OAuth 凭证需要刷新
        if credential.credential_type == "oauth" and credential.refresh_token:
            # 尝试刷新 token
            new_token = await CredentialPool.refresh_access_token(credential)
            if new_token:
                # 更新数据库中的 access_token
                credential.api_key = encrypt_credential(new_token)
                await db.commit()
                return new_token
            return None
        
        # 普通 API Key 直接返回
        return decrypt_credential(credential.api_key)
    
    @staticmethod
    async def mark_credential_error(db: AsyncSession, credential_id: int, error: str):
        """标记凭证错误"""
        await db.execute(
            update(Credential)
            .where(Credential.id == credential_id)
            .values(
                failed_requests=Credential.failed_requests + 1,
                last_error=error
            )
        )
        await db.commit()
    
    @staticmethod
    async def disable_credential(db: AsyncSession, credential_id: int):
        """禁用凭证"""
        await db.execute(
            update(Credential)
            .where(Credential.id == credential_id)
            .values(is_active=False)
        )
        await db.commit()
    
    @staticmethod
    async def handle_credential_failure(db: AsyncSession, credential_id: int, error: str):
        """
        处理凭证失败：
        1. 标记错误
        2. 如果是认证错误 (401/403)，禁用凭证
        3. 降级用户额度（如果之前有奖励）
        """
        from app.models.user import User
        
        # 标记错误
        await CredentialPool.mark_credential_error(db, credential_id, error)
        
        # 检查是否是认证失败
        if "401" in error or "403" in error or "PERMISSION_DENIED" in error:
            # 获取凭证信息
            result = await db.execute(select(Credential).where(Credential.id == credential_id))
            cred = result.scalar_one_or_none()
            
            if cred and cred.is_active:
                # 禁用凭证
                cred.is_active = False
                
                # 如果是公开凭证，降级用户额度
                if cred.is_public and cred.user_id:
                    user_result = await db.execute(select(User).where(User.id == cred.user_id))
                    user = user_result.scalar_one_or_none()
                    if user:
                        # 扣除之前奖励的额度
                        user.daily_quota = max(settings.default_daily_quota, user.daily_quota - settings.credential_reward_quota)
                        print(f"[凭证降级] 用户 {user.username} 凭证失效，额度降级", flush=True)
                
                await db.commit()
                print(f"[凭证禁用] 凭证 {credential_id} 已禁用: {error}", flush=True)
    
    @staticmethod
    async def get_all_credentials(db: AsyncSession):
        """获取所有凭证"""
        result = await db.execute(select(Credential).order_by(Credential.created_at.desc()))
        return result.scalars().all()
    
    @staticmethod
    async def add_credential(db: AsyncSession, name: str, api_key: str) -> Credential:
        """添加凭证"""
        credential = Credential(name=name, api_key=api_key)
        db.add(credential)
        await db.commit()
        await db.refresh(credential)
        return credential
    
    @staticmethod
    async def verify_credential_capabilities(cred: Credential, db: AsyncSession) -> dict:
        """
        统一的凭证能力检测函数
        - 检测有效性
        - 检测模型等级 (3.0 / 2.5)，严格检查 modelVersion 防止回退
        - 检测账号类型 (pro / free)
        - 更新数据库中的凭证状态
        """
        import httpx
        
        access_token = await CredentialPool.get_access_token(cred, db)
        if not access_token:
            cred.is_active = False
            cred.last_error = "无法获取 access token"
            await db.commit()
            return {"is_valid": False, "model_tier": "2.5", "supports_3": False, "account_type": "unknown", "error": "无法获取 access token"}

        is_valid = False
        supports_3 = False
        account_type = "unknown"
        error_msg = None
        storage_gb = None

        # 1. 检测账号类型
        if cred.project_id:
            try:
                type_result = await CredentialPool.detect_account_type(access_token, cred.project_id)
                account_type = type_result.get("account_type", "unknown")
                storage_gb = type_result.get("storage_gb")
            except Exception as e:
                print(f"[能力检测] 检测账号类型失败: {e}", flush=True)

        # 2. 检测模型能力（分步确认）
        async with httpx.AsyncClient(timeout=20) as client:
            test_url = "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            
            # 步骤一：基础有效性验证
            try:
                base_validation_payload = {
                    "model": settings.validation_model,
                    "project": cred.project_id or "",
                    "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
                }
                resp_base = await client.post(test_url, headers=headers, json=base_validation_payload)
                
                if resp_base.status_code in [200, 429]:
                    is_valid = True
                    if resp_base.status_code == 429:
                        error_msg = "配额已用尽 (429)"
                else:
                    error_msg = f"基础验证失败 ({resp_base.status_code})"

            except Exception as e:
                error_msg = f"基础验证请求异常: {str(e)[:30]}"

            # 步骤二：如果基础验证通过，则进行 3.0 能力探测
            if is_valid:
                try:
                    test_payload_3 = {
                        "model": "gemini-3-pro-preview",
                        "project": cred.project_id or "",
                        "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
                    }
                    resp_3 = await client.post(test_url, headers=headers, json=test_payload_3)
                    
                    if resp_3.status_code == 200:
                        data = resp_3.json()
                        model_version = data.get("modelVersion", "")
                        if "gemini-3" in model_version:
                            supports_3 = True
                        
                except Exception as e:
                    print(f"[能力检测] 3.0 探测异常: {e}", flush=True)

        # 3. 整合结果并更新数据库
        cred.is_active = is_valid
        cred.model_tier = "3" if supports_3 else "2.5"
        
        # 4. 如果不支持 3.0，则强制将账号类型降级为 free
        final_account_type = account_type
        if not supports_3 and account_type == "pro":
            final_account_type = "free"

        if error_msg:
            cred.last_error = error_msg
        elif final_account_type != "unknown":
            cred.last_error = f"account_type:{final_account_type}"
        
        await db.commit()

        return {
            "is_valid": is_valid,
            "model_tier": cred.model_tier,
            "supports_3": supports_3,
            "account_type": final_account_type,
            "storage_gb": storage_gb,
            "error": error_msg
        }

    @staticmethod
    async def detect_account_type(access_token: str, project_id: str) -> dict:
        """
        检测账号类型（Pro/Free）
        
        使用 cloudcode-pa 内部 API 进行并发测试：
        - 普通号：并发请求容易触发 429
        - Pro 号：并发请求不会触发 429
        
        Returns:
            {"account_type": "pro"/"free"/"unknown", ...}
        """
        import asyncio
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        
        # 使用内部 API (cloudcode-pa.googleapis.com)
        url = "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
        payload = {
            "model": "gemini-2.0-flash",
            "project": project_id,
            "request": {
                "contents": [{"role": "user", "parts": [{"text": "1"}]}],
                "generationConfig": {"maxOutputTokens": 1}
            }
        }
        
        print(f"[检测账号] 使用内部 API 检测账号类型...", flush=True)
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 顺序发送请求，遇到 429 立即停止
            success_count = 0
            
            for i in range(3):
                try:
                    resp = await client.post(url, headers=headers, json=payload)
                    print(f"[检测账号] 第 {i+1} 次请求: {resp.status_code}", flush=True)
                    
                    if resp.status_code == 200:
                        success_count += 1
                    elif resp.status_code == 429:
                        # 触发限速
                        error_text = resp.text.lower()
                        print(f"[检测账号] 429 详情: {resp.text[:200]}", flush=True)
                        
                        if "per day" in error_text or "daily" in error_text:
                            # 每日配额用完
                            print(f"[检测账号] ⚠️ 每日配额用完，无法判断", flush=True)
                            return {"account_type": "unknown", "error": "配额已用尽"}
                        else:
                            # 每分钟限速 = 普通号
                            print(f"[检测账号] ❌ 触发限速，判定为普号", flush=True)
                            return {"account_type": "free", "method": "rate_limit"}
                    elif resp.status_code in [401, 403]:
                        print(f"[检测账号] 认证失败: {resp.status_code}", flush=True)
                        return {"account_type": "unknown", "error": f"认证失败 ({resp.status_code})"}
                    else:
                        print(f"[检测账号] 未知错误: {resp.status_code}", flush=True)
                        return {"account_type": "unknown", "error": f"API 错误 ({resp.status_code})"}
                        
                except Exception as e:
                    print(f"[检测账号] 请求异常: {e}", flush=True)
                    return {"account_type": "unknown", "error": str(e)}
                
                # 短暂等待
                await asyncio.sleep(0.3)
            
            # 3 次全部成功 = Pro
            print(f"[检测账号] ✅ 3 次全部成功，判定为 Pro", flush=True)
            return {"account_type": "pro", "method": "rate_limit"}
