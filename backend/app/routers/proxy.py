from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import date, datetime, timedelta
from typing import Optional
import json
import time

from app.database import get_db
from app.models.user import User, UsageLog
from app.services.auth import get_user_by_api_key
from app.services.credential_pool import CredentialPool
from app.services.gemini_client import GeminiClient
from app.services.websocket import notify_log_update, notify_stats_update
from app.config import settings

router = APIRouter(tags=["API代理"])


async def get_user_from_api_key(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    """从请求中提取API Key并验证用户"""
    api_key = None
    
    # 1. 从Authorization header获取
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        api_key = auth_header[7:]
    
    # 2. 从x-api-key header获取
    if not api_key:
        api_key = request.headers.get("x-api-key")
    
    # 3. 从查询参数获取
    if not api_key:
        api_key = request.query_params.get("key")
    
    if not api_key:
        raise HTTPException(status_code=401, detail="未提供API Key")
    
    user = await get_user_by_api_key(db, api_key)
    if not user:
        raise HTTPException(status_code=401, detail="无效的API Key")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="账户已被禁用")
    
    # 检查配额
    today = date.today()
    result = await db.execute(
        select(func.count(UsageLog.id))
        .where(UsageLog.user_id == user.id)
        .where(func.date(UsageLog.created_at) == today)
    )
    today_usage = result.scalar() or 0
    
    if today_usage >= user.daily_quota:
        raise HTTPException(status_code=429, detail="已达到今日配额限制")
    
    return user


@router.options("/v1/chat/completions")
@router.options("/chat/completions")
@router.options("/v1/models")
@router.options("/models")
async def options_handler():
    """处理 CORS 预检请求"""
    return JSONResponse(content={}, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
    })


@router.get("/v1/models")
@router.get("/models")
async def list_models(user: User = Depends(get_user_from_api_key)):
    """列出可用模型 (OpenAI兼容)"""
    # 基础模型 (Gemini 2.5+)
    base_models = [
        "gemini-2.5-pro",
        "gemini-2.5-flash", 
        "gemini-3-pro-preview",
    ]
    
    # Thinking 后缀
    thinking_suffixes = ["-maxthinking", "-nothinking"]
    # Search 后缀
    search_suffix = "-search"
    
    models = []
    for base in base_models:
        # 基础模型
        models.append({"id": base, "object": "model", "owned_by": "google"})
        
        # 假流式模型
        models.append({"id": f"假流式/{base}", "object": "model", "owned_by": "google"})
        # 流式抗截断模型
        models.append({"id": f"流式抗截断/{base}", "object": "model", "owned_by": "google"})
        
        # thinking 变体
        for suffix in thinking_suffixes:
            models.append({"id": f"{base}{suffix}", "object": "model", "owned_by": "google"})
            models.append({"id": f"假流式/{base}{suffix}", "object": "model", "owned_by": "google"})
            models.append({"id": f"流式抗截断/{base}{suffix}", "object": "model", "owned_by": "google"})
        
        # search 变体
        models.append({"id": f"{base}{search_suffix}", "object": "model", "owned_by": "google"})
        models.append({"id": f"假流式/{base}{search_suffix}", "object": "model", "owned_by": "google"})
        models.append({"id": f"流式抗截断/{base}{search_suffix}", "object": "model", "owned_by": "google"})
        
        # thinking + search 组合
        for suffix in thinking_suffixes:
            combined = f"{suffix}{search_suffix}"
            models.append({"id": f"{base}{combined}", "object": "model", "owned_by": "google"})
            models.append({"id": f"假流式/{base}{combined}", "object": "model", "owned_by": "google"})
            models.append({"id": f"流式抗截断/{base}{combined}", "object": "model", "owned_by": "google"})
    
    # Image 模型
    models.append({"id": "gemini-2.5-flash-image", "object": "model", "owned_by": "google"})
    
    
    return {"object": "list", "data": models}


@router.post("/v1/chat/completions")
@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    user: User = Depends(get_user_from_api_key),
    db: AsyncSession = Depends(get_db)
):
    """Chat Completions (OpenAI兼容)"""
    start_time = time.time()
    
    try:
        body = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    
    model = body.get("model", "gemini-2.5-flash")
    messages = body.get("messages", [])
    stream = body.get("stream", False)
    
    if not messages:
        raise HTTPException(status_code=400, detail="messages不能为空")
    
    # 检查用户是否参与大锅饭
    user_has_public = await CredentialPool.check_user_has_public_creds(db, user.id)
    
    # 速率限制检查 (RPM)
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
    rpm_result = await db.execute(
        select(func.count(UsageLog.id))
        .where(UsageLog.user_id == user.id)
        .where(UsageLog.created_at >= one_minute_ago)
    )
    current_rpm = rpm_result.scalar() or 0
    max_rpm = settings.contributor_rpm if user_has_public else settings.base_rpm
    
    if current_rpm >= max_rpm:
        raise HTTPException(
            status_code=429, 
            detail=f"速率限制: {max_rpm} 次/分钟。{'上传凭证可提升至 ' + str(settings.contributor_rpm) + ' 次/分钟' if not user_has_public else ''}"
        )
    
    # 获取凭证（大锅饭规则 + 模型等级匹配）
    credential = await CredentialPool.get_available_credential(
        db, 
        user_id=user.id,
        user_has_public_creds=user_has_public,
        model=model  # 传入模型用于等级匹配
    )
    if not credential:
        required_tier = CredentialPool.get_required_tier(model)
        if required_tier == "3":
            raise HTTPException(
                status_code=503, 
                detail="没有可用的 Gemini 3 等级凭证。该模型需要有 Gemini 3 资格的凭证。"
            )
        if not user_has_public:
            raise HTTPException(
                status_code=503, 
                detail="您没有可用凭证。请在凭证管理页面上传凭证，或捐赠凭证以使用公共池。"
            )
        raise HTTPException(status_code=503, detail="暂无可用凭证，请稍后重试")
    
    # 获取 access_token（自动刷新）
    access_token = await CredentialPool.get_access_token(credential, db)
    if not access_token:
        await CredentialPool.mark_credential_error(db, credential.id, "Token 刷新失败")
        raise HTTPException(status_code=503, detail="凭证已失效，请重新授权")
    
    # 获取 project_id
    project_id = credential.project_id or ""
    print(f"[Proxy] 使用凭证: {credential.email}, project_id: {project_id}, model: {model}", flush=True)
    
    if not project_id:
        print(f"[Proxy] ⚠️ 凭证 {credential.email} 没有 project_id!", flush=True)
    
    client = GeminiClient(access_token, project_id)
    
    # 记录使用日志
    async def log_usage(status_code: int = 200):
        latency = (time.time() - start_time) * 1000
        log = UsageLog(
            user_id=user.id,
            credential_id=credential.id,
            model=model,
            endpoint="/v1/chat/completions",
            status_code=status_code,
            latency_ms=latency
        )
        db.add(log)
        await db.commit()
        
        # 更新凭证使用次数
        credential.total_requests = (credential.total_requests or 0) + 1
        credential.last_used_at = datetime.utcnow()
        await db.commit()
        
        # WebSocket 实时通知
        await notify_log_update({
            "username": user.username,
            "model": model,
            "status_code": status_code,
            "latency_ms": round(latency, 0),
            "created_at": datetime.utcnow().isoformat()
        })
        await notify_stats_update()
    
    # 检查是否使用假流式
    use_fake_streaming = client.is_fake_streaming(model)
    
    try:
        if stream:
            async def stream_generator():
                try:
                    if use_fake_streaming:
                        # 假流式：先发心跳，完成后一次性输出
                        async for chunk in client.chat_completions_fake_stream(
                            model=model,
                            messages=messages,
                            **{k: v for k, v in body.items() if k not in ["model", "messages", "stream"]}
                        ):
                            yield chunk
                    else:
                        # 真流式
                        async for chunk in client.chat_completions_stream(
                            model=model,
                            messages=messages,
                            **{k: v for k, v in body.items() if k not in ["model", "messages", "stream"]}
                        ):
                            yield chunk
                        yield "data: [DONE]\n\n"
                    await log_usage()
                except Exception as e:
                    await CredentialPool.handle_credential_failure(db, credential.id, str(e))
                    await log_usage(500)
                    yield f"data: {json.dumps({'error': str(e)})}\n\n"
            
            return StreamingResponse(
                stream_generator(),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
            )
        else:
            result = await client.chat_completions(
                model=model,
                messages=messages,
                **{k: v for k, v in body.items() if k not in ["model", "messages", "stream"]}
            )
            await log_usage()
            return JSONResponse(content=result)
    
    except Exception as e:
        await CredentialPool.handle_credential_failure(db, credential.id, str(e))
        await log_usage(500)
        raise HTTPException(status_code=500, detail=f"API调用失败: {str(e)}")


# ===== Gemini 原生接口支持 =====

@router.options("/v1beta/models/{model:path}:generateContent")
@router.options("/v1/models/{model:path}:generateContent")
@router.options("/v1beta/models/{model:path}:streamGenerateContent")
@router.options("/v1/models/{model:path}:streamGenerateContent")
async def gemini_options_handler(model: str):
    """Gemini 接口 CORS 预检"""
    return JSONResponse(content={}, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
    })


@router.get("/v1beta/models")
@router.get("/v1/v1beta/models")
async def list_gemini_models(user: User = Depends(get_user_from_api_key)):
    """Gemini 格式模型列表"""
    base_models = [
        "gemini-2.5-pro", "gemini-2.5-flash", 
        "gemini-3-pro-preview",
    ]
    
    models = []
    for base in base_models:
        models.append({
            "name": f"models/{base}",
            "version": "001",
            "displayName": base,
            "description": f"Gemini {base} model",
            "inputTokenLimit": 1000000,
            "outputTokenLimit": 65536,
            "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
        })
    
    return {"models": models}


@router.post("/v1beta/models/{model:path}:generateContent")
@router.post("/v1/models/{model:path}:generateContent")
@router.post("/v1/v1beta/models/{model:path}:generateContent")
async def gemini_generate_content(
    model: str,
    request: Request,
    user: User = Depends(get_user_from_api_key),
    db: AsyncSession = Depends(get_db)
):
    """Gemini 原生 generateContent 接口"""
    start_time = time.time()
    
    try:
        body = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    
    contents = body.get("contents", [])
    if not contents:
        raise HTTPException(status_code=400, detail="contents不能为空")
    
    # 清理模型名（移除 models/ 前缀）
    if model.startswith("models/"):
        model = model[7:]
    
    # 检查用户是否参与大锅饭
    user_has_public = await CredentialPool.check_user_has_public_creds(db, user.id)
    
    # 速率限制
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
    rpm_result = await db.execute(
        select(func.count(UsageLog.id))
        .where(UsageLog.user_id == user.id)
        .where(UsageLog.created_at >= one_minute_ago)
    )
    current_rpm = rpm_result.scalar() or 0
    max_rpm = settings.contributor_rpm if user_has_public else settings.base_rpm
    
    if current_rpm >= max_rpm:
        raise HTTPException(status_code=429, detail=f"速率限制: {max_rpm} 次/分钟")
    
    # 获取凭证
    credential = await CredentialPool.get_available_credential(
        db, user_id=user.id, user_has_public_creds=user_has_public, model=model
    )
    if not credential:
        raise HTTPException(status_code=503, detail="暂无可用凭证")
    
    access_token = await CredentialPool.get_access_token(credential, db)
    if not access_token:
        raise HTTPException(status_code=503, detail="凭证已失效")
    
    project_id = credential.project_id or ""
    print(f"[Gemini API] 使用凭证: {credential.email}, project_id: {project_id}, model: {model}", flush=True)
    
    # 记录日志
    async def log_usage(status_code: int = 200):
        latency = (time.time() - start_time) * 1000
        log = UsageLog(user_id=user.id, credential_id=credential.id, model=model, endpoint="/v1beta/generateContent", status_code=status_code, latency_ms=latency)
        db.add(log)
        credential.total_requests = (credential.total_requests or 0) + 1
        credential.last_used_at = datetime.utcnow()
        await db.commit()
    
    # 直接转发到 Google API
    try:
        import httpx
        url = "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
        
        # 构建 payload
        request_body = {"contents": contents}
        if "generationConfig" in body:
            request_body["generationConfig"] = body["generationConfig"]
        if "systemInstruction" in body:
            request_body["systemInstruction"] = body["systemInstruction"]
        if "safetySettings" in body:
            request_body["safetySettings"] = body["safetySettings"]
        if "tools" in body:
            request_body["tools"] = body["tools"]
        
        payload = {"model": model, "project": project_id, "request": request_body}
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                json=payload
            )
            
            if response.status_code != 200:
                error_text = response.text[:500]
                print(f"[Gemini API] ❌ 错误 {response.status_code}: {error_text}", flush=True)
                # 401/403 错误自动禁用凭证
                if response.status_code in [401, 403]:
                    await CredentialPool.handle_credential_failure(db, credential.id, f"API Error {response.status_code}: {error_text}")
                await log_usage(response.status_code)
                raise HTTPException(status_code=response.status_code, detail=response.text)
            
            await log_usage()
            return JSONResponse(content=response.json())
    
    except HTTPException:
        raise
    except Exception as e:
        await CredentialPool.handle_credential_failure(db, credential.id, str(e))
        await log_usage(500)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/v1beta/models/{model:path}:streamGenerateContent")
@router.post("/v1/models/{model:path}:streamGenerateContent")
@router.post("/v1/v1beta/models/{model:path}:streamGenerateContent")
async def gemini_stream_generate_content(
    model: str,
    request: Request,
    user: User = Depends(get_user_from_api_key),
    db: AsyncSession = Depends(get_db)
):
    """Gemini 原生 streamGenerateContent 接口"""
    start_time = time.time()
    
    try:
        body = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    
    contents = body.get("contents", [])
    if not contents:
        raise HTTPException(status_code=400, detail="contents不能为空")
    
    # 清理模型名
    if model.startswith("models/"):
        model = model[7:]
    
    # 检查用户是否参与大锅饭
    user_has_public = await CredentialPool.check_user_has_public_creds(db, user.id)
    
    # 速率限制
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
    rpm_result = await db.execute(
        select(func.count(UsageLog.id))
        .where(UsageLog.user_id == user.id)
        .where(UsageLog.created_at >= one_minute_ago)
    )
    current_rpm = rpm_result.scalar() or 0
    max_rpm = settings.contributor_rpm if user_has_public else settings.base_rpm
    
    if current_rpm >= max_rpm:
        raise HTTPException(status_code=429, detail=f"速率限制: {max_rpm} 次/分钟")
    
    # 获取凭证
    credential = await CredentialPool.get_available_credential(
        db, user_id=user.id, user_has_public_creds=user_has_public, model=model
    )
    if not credential:
        raise HTTPException(status_code=503, detail="暂无可用凭证")
    
    access_token = await CredentialPool.get_access_token(credential, db)
    if not access_token:
        raise HTTPException(status_code=503, detail="凭证已失效")
    
    project_id = credential.project_id or ""
    print(f"[Gemini Stream] 使用凭证: {credential.email}, project_id: {project_id}, model: {model}", flush=True)
    
    # 记录日志
    async def log_usage(status_code: int = 200):
        latency = (time.time() - start_time) * 1000
        log = UsageLog(user_id=user.id, credential_id=credential.id, model=model, endpoint="/v1beta/streamGenerateContent", status_code=status_code, latency_ms=latency)
        db.add(log)
        credential.total_requests = (credential.total_requests or 0) + 1
        credential.last_used_at = datetime.utcnow()
        await db.commit()
    
    # 流式转发
    import httpx
    url = "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
    
    request_body = {"contents": contents}
    if "generationConfig" in body:
        request_body["generationConfig"] = body["generationConfig"]
    if "systemInstruction" in body:
        request_body["systemInstruction"] = body["systemInstruction"]
    if "safetySettings" in body:
        request_body["safetySettings"] = body["safetySettings"]
    if "tools" in body:
        request_body["tools"] = body["tools"]
    
    payload = {"model": model, "project": project_id, "request": request_body}
    
    async def stream_generator():
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                async with client.stream(
                    "POST", url,
                    headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                    json=payload
                ) as response:
                    if response.status_code != 200:
                        error = await response.aread()
                        error_text = error.decode()[:500]
                        print(f"[Gemini Stream] ❌ 错误 {response.status_code}: {error_text}", flush=True)
                        # 401/403 错误自动禁用凭证
                        if response.status_code in [401, 403]:
                            await CredentialPool.handle_credential_failure(db, credential.id, f"API Error {response.status_code}: {error_text}")
                        yield f"data: {json.dumps({'error': error.decode()})}\n\n"
                        return
                    
                    async for line in response.aiter_lines():
                        if line:
                            yield f"{line}\n"
            
            await log_usage()
        except Exception as e:
            await CredentialPool.handle_credential_failure(db, credential.id, str(e))
            await log_usage(500)
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
    )
