from typing import Optional
from datetime import datetime, timedelta
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
    def get_model_group(model: str) -> str:
        """
        根据模型名确定模型组（用于 CD 机制）
        返回: "flash", "pro", "30"
        """
        if not model:
            return "flash"
        model_lower = model.lower()
        # 3.0 模型
        if "gemini-3-" in model_lower or "/gemini-3-" in model_lower:
            return "30"
        # Pro 模型
        if "pro" in model_lower:
            return "pro"
        # 默认 Flash
        return "flash"
    
    @staticmethod
    def get_cd_seconds(model_group: str) -> int:
        """获取模型组的 CD 时间（秒）"""
        if model_group == "30":
            return settings.cd_30
        elif model_group == "pro":
            return settings.cd_pro
        else:
            return settings.cd_flash
    
    @staticmethod
    def is_credential_in_cd(credential: Credential, model_group: str) -> bool:
        """检查凭证在指定模型组是否处于 CD 中"""
        cd_seconds = CredentialPool.get_cd_seconds(model_group)
        if cd_seconds <= 0:
            return False
        
        # 获取对应模型组的最后使用时间
        if model_group == "30":
            last_used = credential.last_used_30
        elif model_group == "pro":
            last_used = credential.last_used_pro
        else:
            last_used = credential.last_used_flash
        
        if not last_used:
            return False
        
        cd_end_time = last_used + timedelta(seconds=cd_seconds)
        return datetime.utcnow() < cd_end_time
    
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
    async def has_tier3_credentials(user, db: AsyncSession) -> bool:
        """检查用户可用的凭证池中是否有 3.0 凭证（用于模型列表显示）"""
        pool_mode = settings.credential_pool_mode
        query = select(Credential).where(
            Credential.is_active == True,
            Credential.model_tier == "3"
        ).limit(1)
        
        if pool_mode == "private":
            # 私有模式：只检查自己的凭证
            query = query.where(Credential.user_id == user.id)
        
        elif pool_mode == "tier3_shared":
            # 3.0共享模式：有3.0凭证的用户可用公共3.0池
            user_has_tier3 = await CredentialPool.check_user_has_tier3_creds(db, user.id)
            if user_has_tier3:
                query = query.where(
                    or_(Credential.is_public == True, Credential.user_id == user.id)
                )
            else:
                query = query.where(Credential.user_id == user.id)
        
        else:  # full_shared (大锅饭模式)
            user_has_public = await CredentialPool.check_user_has_public_creds(db, user.id)
            if user_has_public:
                query = query.where(
                    or_(Credential.is_public == True, Credential.user_id == user.id)
                )
            else:
                query = query.where(Credential.user_id == user.id)
        
        result = await db.execute(query)
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
        
        # 排除没有 project_id 的凭证（没有 project_id 无法调用 API）
        query = query.where(Credential.project_id != None, Credential.project_id != "")
        
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
            # 3.0共享模式：
            # - 请求3.0模型：需要有3.0凭证才能用公共3.0池
            # - 请求2.5模型：所有用户都可以用公共2.5凭证
            user_has_tier3 = await CredentialPool.check_user_has_tier3_creds(db, user_id)
            
            if required_tier == "3":
                # 请求3.0模型
                if user_has_tier3:
                    # 用户有3.0凭证 → 可用公共3.0池
                    query = query.where(
                        or_(
                            Credential.is_public == True,
                            Credential.user_id == user_id
                        )
                    )
                else:
                    # 用户没有3.0凭证 → 只能用自己的凭证
                    query = query.where(Credential.user_id == user_id)
            else:
                # 请求2.5模型 → 所有用户都可以用公共凭证
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
        
        # 确定模型组（用于 CD 筛选）
        model_group = CredentialPool.get_model_group(model) if model else "flash"
        cd_seconds = CredentialPool.get_cd_seconds(model_group)
        
        result = await db.execute(
            query.order_by(Credential.last_used_at.asc().nullsfirst())
        )
        credentials = result.scalars().all()
        
        if not credentials:
            return None
        
        # 筛选不在 CD 中的凭证
        available_credentials = [
            c for c in credentials 
            if not CredentialPool.is_credential_in_cd(c, model_group)
        ]
        
        total_count = len(credentials)
        available_count = len(available_credentials)
        in_cd_count = total_count - available_count
        
        if not available_credentials:
            # 所有凭证都在 CD 中，选择第一个（按 last_used_at 排序的）
            credential = credentials[0]
            print(f"[CD] 模型组={model_group}, CD={cd_seconds}秒 | 全部{total_count}个凭证都在CD中，选择: {credential.email}", flush=True)
        else:
            # 选择最久未使用的凭证
            credential = available_credentials[0]
            print(f"[CD] 模型组={model_group}, CD={cd_seconds}秒 | 可用{available_count}/{total_count}个, 选择: {credential.email}", flush=True)
        
        # 更新使用时间和计数
        now = datetime.utcnow()
        credential.last_used_at = now
        credential.total_requests += 1
        
        # 更新对应模型组的 CD 时间
        if model_group == "30":
            credential.last_used_30 = now
        elif model_group == "pro":
            credential.last_used_pro = now
        else:
            credential.last_used_flash = now
        
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
        
        # 优先使用凭证自己的 client_id/secret，否则使用系统配置
        if credential.client_id and credential.client_secret:
            client_id = decrypt_credential(credential.client_id)
            client_secret = decrypt_credential(credential.client_secret)
            print(f"[Token刷新] 使用凭证自己的 client_id: {client_id[:20]}...", flush=True)
        else:
            client_id = settings.google_client_id
            client_secret = settings.google_client_secret
            print(f"[Token刷新] 使用系统配置的 client_id", flush=True)
        
        print(f"[Token刷新] 开始刷新 token, refresh_token 前20字符: {refresh_token[:20]}...", flush=True)
        
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "refresh_token": refresh_token,
                        "grant_type": "refresh_token"
                    }
                )
                data = response.json()
                print(f"[Token刷新] 响应状态: {response.status_code}", flush=True)
                
                if "access_token" in data:
                    print(f"[Token刷新] 刷新成功!", flush=True)
                    return data["access_token"]
                print(f"[Token刷新] 刷新失败: {data.get('error', 'unknown')} - {data.get('error_description', '')}", flush=True)
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
                
                # 如果是公开凭证，根据凭证等级降级用户奖励配额
                if cred.is_public and cred.user_id:
                    user_result = await db.execute(select(User).where(User.id == cred.user_id))
                    user = user_result.scalar_one_or_none()
                    if user:
                        # 根据凭证等级扣除奖励额度：2.5=flash+25pro, 3.0=flash+25pro+30pro
                        if cred.model_tier == "3":
                            deduct = settings.quota_flash + settings.quota_25pro + settings.quota_30pro
                        else:
                            deduct = settings.quota_flash + settings.quota_25pro
                        # 只扣除奖励配额，不影响基础配额
                        user.bonus_quota = max(0, (user.bonus_quota or 0) - deduct)
                        print(f"[凭证降级] 用户 {user.username} 凭证失效，扣除 {deduct} 奖励额度 (等级: {cred.model_tier})", flush=True)
                
                await db.commit()
                print(f"[凭证禁用] 凭证 {credential_id} 已禁用: {error}", flush=True)
    
    @staticmethod
    def parse_429_retry_after(error_text: str, headers: dict = None) -> int:
        """
        从 Google 429 响应中解析 CD 时间
        
        Google 429 响应格式示例:
        - Retry-After 头: "60"
        - 错误信息中: "retryDelay": "60s" 或 "retry after 60 seconds"
        
        Returns:
            CD 秒数，如果解析失败返回 0
        """
        import re
        
        cd_seconds = 0
        
        # 1. 尝试从 Retry-After 头解析
        if headers:
            retry_after = headers.get("Retry-After") or headers.get("retry-after")
            if retry_after:
                try:
                    cd_seconds = int(retry_after)
                    print(f"[429 CD] 从 Retry-After 头解析到 CD: {cd_seconds}s", flush=True)
                    return cd_seconds
                except:
                    pass
        
        # 2. 尝试从错误信息中解析 retryDelay
        # 格式: "retryDelay": "60s" 或 "retryDelay":"60s"
        match = re.search(r'"retryDelay"\s*:\s*"(\d+)s?"', error_text)
        if match:
            cd_seconds = int(match.group(1))
            print(f"[429 CD] 从 retryDelay 解析到 CD: {cd_seconds}s", flush=True)
            return cd_seconds
        
        # 3. 尝试匹配 "retry after X seconds" 格式
        match = re.search(r'retry\s+after\s+(\d+)\s*s', error_text, re.IGNORECASE)
        if match:
            cd_seconds = int(match.group(1))
            print(f"[429 CD] 从文本解析到 CD: {cd_seconds}s", flush=True)
            return cd_seconds
        
        # 4. 尝试匹配纯数字秒数
        match = re.search(r'(\d+)\s*seconds?', error_text, re.IGNORECASE)
        if match:
            cd_seconds = int(match.group(1))
            print(f"[429 CD] 从 seconds 解析到 CD: {cd_seconds}s", flush=True)
            return cd_seconds
        
        print(f"[429 CD] 未能解析 CD 时间，使用默认值", flush=True)
        return 0
    
    @staticmethod
    async def handle_429_rate_limit(
        db: AsyncSession, 
        credential_id: int, 
        model: str,
        error_text: str,
        headers: dict = None
    ):
        """
        处理 429 速率限制错误：
        1. 解析 Google 返回的 CD 时间
        2. 设置凭证对应模型组的 CD 时间
        """
        # 解析 CD 时间
        cd_seconds = CredentialPool.parse_429_retry_after(error_text, headers)
        
        if cd_seconds <= 0:
            # 如果没有解析到 CD 时间，使用默认值 60 秒
            cd_seconds = 60
            print(f"[429 CD] 使用默认 CD: {cd_seconds}s", flush=True)
        
        # 确定模型组
        model_group = CredentialPool.get_model_group(model)
        
        # 获取凭证
        result = await db.execute(select(Credential).where(Credential.id == credential_id))
        cred = result.scalar_one_or_none()
        
        if cred:
            # 设置 CD 结束时间 = 当前时间 - 配置的 CD 时间 + Google 返回的 CD 时间
            # 这样 is_credential_in_cd 函数会正确计算剩余 CD
            now = datetime.utcnow()
            
            # 直接设置 last_used 为一个特殊值，使得 CD 到期时间 = now + cd_seconds
            # CD 到期时间 = last_used + config_cd_seconds
            # 我们想要 CD 到期时间 = now + google_cd_seconds
            # 所以 last_used = now + google_cd_seconds - config_cd_seconds
            config_cd = CredentialPool.get_cd_seconds(model_group)
            if config_cd > 0:
                # 计算需要设置的 last_used 时间
                # 使 CD 到期时间 = now + google_cd_seconds
                cd_end = now + timedelta(seconds=cd_seconds)
                last_used = cd_end - timedelta(seconds=config_cd)
            else:
                # 如果配置的 CD 为 0，则直接使用当前时间
                # 此时 CD 机制不会生效，但我们仍然记录
                last_used = now
            
            if model_group == "30":
                cred.last_used_30 = last_used
            elif model_group == "pro":
                cred.last_used_pro = last_used
            else:
                cred.last_used_flash = last_used
            
            await db.commit()
            print(f"[429 CD] 凭证 {credential_id} 模型组 {model_group} 设置 CD {cd_seconds}s", flush=True)
    
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
    async def detect_account_type(access_token: str, project_id: str) -> dict:
        """
        检测账号类型（Pro/Free）
        
        方式1: 使用 Google Drive API 检测存储空间（需要 drive scope）
        方式2: 如果 Drive API 失败，回退到连续请求检测
        
        Returns:
            {"account_type": "pro"/"free"/"unknown", "storage_gb": float}
        """
        import asyncio
        
        headers = {"Authorization": f"Bearer {access_token}"}
        
        print(f"[检测账号] 尝试使用 Drive API 检测存储空间...", flush=True)
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            # 方式1: 尝试 Drive API
            try:
                resp = await client.get(
                    "https://www.googleapis.com/drive/v3/about?fields=storageQuota",
                    headers=headers
                )
                print(f"[检测账号] Drive API 响应: {resp.status_code}", flush=True)
                
                if resp.status_code == 200:
                    data = resp.json()
                    quota = data.get("storageQuota", {})
                    limit = int(quota.get("limit", 0))
                    
                    if limit > 0:
                        storage_gb = round(limit / (1024**3), 1)
                        print(f"[检测账号] 存储空间: {storage_gb} GB", flush=True)
                        
                        # Pro 账号是 2TB (2000GB) 存储空间
                        if storage_gb >= 2000:
                            return {"account_type": "pro", "storage_gb": storage_gb}
                        else:
                            return {"account_type": "free", "storage_gb": storage_gb}
                elif resp.status_code == 403:
                    print(f"[检测账号] Drive API 无权限，回退到连续请求检测", flush=True)
                else:
                    print(f"[检测账号] Drive API 意外响应: {resp.status_code}", flush=True)
                            
            except Exception as e:
                print(f"[检测账号] Drive API 异常: {e}", flush=True)
            
            # 方式2: 回退到连续请求检测
            print(f"[检测账号] Drive API 无权限，使用连续请求检测...", flush=True)
            
            headers["Content-Type"] = "application/json"
            url = "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
            payload = {
                "model": "gemini-2.0-flash",
                "project": project_id,
                "request": {
                    "contents": [{"role": "user", "parts": [{"text": "1"}]}],
                    "generationConfig": {"maxOutputTokens": 1}
                }
            }
            
            # 先等待 2 秒让之前的请求 RPM 窗口过去
            print(f"[检测账号] 等待 2 秒后开始连续请求检测...", flush=True)
            await asyncio.sleep(2)
            
            success_count = 0
            for i in range(5):  # 5 次检测
                try:
                    resp = await client.post(url, headers=headers, json=payload)
                    print(f"[检测账号] 第 {i+1} 次请求: {resp.status_code}", flush=True)
                    
                    if resp.status_code == 429:
                        error_text = resp.text.lower()
                        print(f"[检测账号] 429 详情: {resp.text[:200]}", flush=True)
                        # 只有日配额用尽才能确定，RPM 限速不做判断
                        if "per day" in error_text or "daily" in error_text:
                            return {"account_type": "unknown", "error": "配额已用尽，无法判断"}
                        # RPM 限速，等待后继续
                        print(f"[检测账号] RPM 限速，等待后继续...", flush=True)
                        await asyncio.sleep(3)
                        continue
                    elif resp.status_code == 200:
                        success_count += 1
                    else:
                        print(f"[检测账号] 非200响应: {resp.status_code}", flush=True)
                        return {"account_type": "unknown"}
                        
                except Exception as e:
                    print(f"[检测账号] 请求异常: {e}", flush=True)
                    return {"account_type": "unknown", "error": str(e)}
                
                await asyncio.sleep(1.5)
            
            # 5 次中至少 3 次成功才判定为 Pro
            if success_count >= 3:
                print(f"[检测账号] {success_count}/5 次请求成功，判定为 Pro", flush=True)
                return {"account_type": "pro"}
            else:
                print(f"[检测账号] 只有 {success_count}/5 次成功，无法确定", flush=True)
                return {"account_type": "unknown"}
