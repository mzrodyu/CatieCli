import httpx
import json
from typing import AsyncGenerator, Optional, Dict, Any
from app.config import settings


class GeminiClient:
    """Gemini API 客户端 - 使用 Google 内部 API"""
    
    # 内部 API 端点
    INTERNAL_API_BASE = "https://cloudcode-pa.googleapis.com"
    
    def __init__(self, access_token: str, project_id: str = None):
        self.access_token = access_token
        self.project_id = project_id or ""
    
    async def generate_content(
        self,
        model: str,
        contents: list,
        generation_config: Optional[Dict] = None,
        system_instruction: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """生成内容 (非流式) - 使用内部 API"""
        url = f"{self.INTERNAL_API_BASE}/v1internal:generateContent"
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "User-Agent": "catiecli/1.0",
        }
        
        # 构建内部 API 格式的 payload
        request_body = {"contents": contents}
        if generation_config:
            request_body["generationConfig"] = generation_config
        if system_instruction:
            request_body["systemInstruction"] = system_instruction
        
        # 添加安全设置
        request_body["safetySettings"] = [
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "OFF"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "OFF"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "OFF"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "OFF"},
        ]
        
        payload = {
            "model": model,
            "project": self.project_id,
            "request": request_body,
        }
        
        print(f"[GeminiClient] 请求: model={model}, project={self.project_id}", flush=True)
        print(f"[GeminiClient] generationConfig: {generation_config}", flush=True)
        
        # 使用更细粒度的超时配置，避免长时间生成时连接中断
        timeout = httpx.Timeout(
            connect=30.0,    # 连接超时
            read=180.0,      # 读取超时（等待响应）
            write=30.0,      # 写入超时
            pool=30.0        # 连接池超时
        )
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, headers=headers, json=payload)
            
            # 打印所有响应头（调试用）
            print(f"[GeminiClient] 响应头: {dict(response.headers)}", flush=True)
            
            if response.status_code != 200:
                error_text = response.text
                print(f"[GeminiClient] ❌ 错误 {response.status_code}: {error_text[:500]}", flush=True)
                raise Exception(f"API Error {response.status_code}: {error_text}")
            result = response.json()
            # 调试：打印原始响应
            print(f"[GeminiClient] ✅ 原始响应: {json.dumps(result, ensure_ascii=False)[:1000]}", flush=True)
            return result
    
    async def generate_content_stream(
        self,
        model: str,
        contents: list,
        generation_config: Optional[Dict] = None,
        system_instruction: Optional[Dict] = None
    ) -> AsyncGenerator[str, None]:
        """生成内容 (流式) - 使用内部 API"""
        url = f"{self.INTERNAL_API_BASE}/v1internal:streamGenerateContent?alt=sse"
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "User-Agent": "catiecli/1.0",
        }
        
        # 构建内部 API 格式的 payload
        request_body = {"contents": contents}
        if generation_config:
            request_body["generationConfig"] = generation_config
        if system_instruction:
            request_body["systemInstruction"] = system_instruction
        
        # 添加安全设置
        request_body["safetySettings"] = [
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "OFF"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "OFF"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "OFF"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "OFF"},
        ]
        
        payload = {
            "model": model,
            "project": self.project_id,
            "request": request_body,
        }
        
        print(f"[GeminiClient] 流式请求: model={model}, project={self.project_id}", flush=True)
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST", url, headers=headers, json=payload
            ) as response:
                if response.status_code != 200:
                    error_text = await response.aread()
                    print(f"[GeminiClient] ❌ 流式错误 {response.status_code}: {error_text.decode()[:500]}", flush=True)
                    raise Exception(f"API Error {response.status_code}: {error_text.decode()}")
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        yield line[6:]
    
    def is_fake_streaming(self, model: str) -> bool:
        """检查是否使用假流式"""
        return model.startswith("假流式/")
    
    async def chat_completions(
        self,
        model: str,
        messages: list,
        **kwargs
    ) -> Dict[str, Any]:
        """OpenAI兼容的chat completions (非流式)"""
        contents, system_instruction = self._convert_messages_to_contents(messages)
        generation_config = self._build_generation_config(model, kwargs)
        gemini_model = self._map_model_name(model)
        
        result = await self.generate_content(gemini_model, contents, generation_config, system_instruction)
        return self._convert_to_openai_response(result, model)
    
    async def chat_completions_stream(
        self,
        model: str,
        messages: list,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """OpenAI兼容的chat completions (流式)"""
        contents, system_instruction = self._convert_messages_to_contents(messages)
        generation_config = self._build_generation_config(model, kwargs)
        gemini_model = self._map_model_name(model)
        
        async for chunk in self.generate_content_stream(gemini_model, contents, generation_config, system_instruction):
            yield self._convert_to_openai_stream(chunk, model)
    
    async def chat_completions_fake_stream(
        self,
        model: str,
        messages: list,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """假流式: 先发心跳，拿到完整响应后一次性输出"""
        import asyncio
        
        contents, system_instruction = self._convert_messages_to_contents(messages)
        generation_config = self._build_generation_config(model, kwargs)
        gemini_model = self._map_model_name(model)
        
        # 发送初始 chunk（空内容，保持连接）
        initial_chunk = {
            "id": "chatcmpl-catiecli",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": model,
            "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]
        }
        yield f"data: {json.dumps(initial_chunk)}\n\n"
        
        # 创建请求任务
        request_task = asyncio.create_task(
            self.generate_content(gemini_model, contents, generation_config, system_instruction)
        )
        
        # 每2秒发送心跳，直到请求完成
        heartbeat_chunk = {
            "id": "chatcmpl-catiecli",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": None}]
        }
        
        while not request_task.done():
            await asyncio.sleep(2)
            if not request_task.done():
                yield f"data: {json.dumps(heartbeat_chunk)}\n\n"
        
        # 获取完整响应
        try:
            result = await request_task
            content = ""
            
            # 内部 API 返回格式是 {"response": {"candidates": ...}}
            response_data = result.get("response", result)
            
            if "candidates" in response_data and response_data["candidates"]:
                candidate = response_data["candidates"][0]
                if "content" in candidate and "parts" in candidate["content"]:
                    for part in candidate["content"]["parts"]:
                        if "text" in part and not part.get("thought", False):
                            content += part.get("text", "")
            
            # 输出完整内容
            if content:
                content_chunk = {
                    "id": "chatcmpl-catiecli",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": model,
                    "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}]
                }
                yield f"data: {json.dumps(content_chunk)}\n\n"
            
            # 发送结束标记
            done_chunk = {
                "id": "chatcmpl-catiecli",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
            }
            yield f"data: {json.dumps(done_chunk)}\n\n"
            yield "data: [DONE]\n\n"
            
        except Exception as e:
            error_chunk = {
                "id": "chatcmpl-catiecli",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": model,
                "choices": [{"index": 0, "delta": {"content": f"\n\n[Error: {str(e)}]"}, "finish_reason": "stop"}]
            }
            yield f"data: {json.dumps(error_chunk)}\n\n"
            yield "data: [DONE]\n\n"
    
    def _build_generation_config(self, model: str, kwargs: dict) -> dict:
        """构建生成配置（包含 thinking 配置）"""
        generation_config = {}
        
        # 基础配置
        if "temperature" in kwargs:
            generation_config["temperature"] = kwargs["temperature"]
        if "max_tokens" in kwargs:
            generation_config["maxOutputTokens"] = kwargs["max_tokens"]
        if "top_p" in kwargs:
            generation_config["topP"] = kwargs["top_p"]
        if "top_k" in kwargs:
            generation_config["topK"] = kwargs["top_k"]
        
        # 默认 topK (避免某些模型问题)
        if "topK" not in generation_config:
            generation_config["topK"] = 64
        
        # Thinking 配置
        thinking_config = self._get_thinking_config(model)
        if thinking_config:
            generation_config.update(thinking_config)
        
        return generation_config
    
    def _convert_messages_to_contents(self, messages: list) -> tuple:
        """将OpenAI消息格式转换为Gemini contents格式
        
        Returns:
            (contents, system_instruction): contents 列表和系统指令字典
        """
        contents = []
        system_instructions = []
        
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            
            if role == "system":
                system_instructions.append(content)
                continue
            
            gemini_role = "user" if role == "user" else "model"
            
            contents.append({
                "role": gemini_role,
                "parts": [{"text": content}]
            })
        
        # 构建 systemInstruction
        system_instruction = None
        if system_instructions:
            combined = "\n\n".join(system_instructions)
            system_instruction = {"parts": [{"text": combined}]}
        
        # 如果 contents 为空，添加默认用户消息
        if not contents:
            contents.append({"role": "user", "parts": [{"text": "请根据系统指令回答。"}]})
        
        return contents, system_instruction
    
    def _map_model_name(self, model: str) -> str:
        """映射模型名称"""
        # 移除前缀（假流式/流式抗截断）
        prefixes = ["假流式/", "流式抗截断/"]
        for prefix in prefixes:
            if model.startswith(prefix):
                model = model[len(prefix):]
                break
        
        # OpenAI 别名映射
        model_mapping = {
            "gpt-4": "gemini-2.5-pro",
            "gpt-4-turbo": "gemini-2.5-pro",
            "gpt-4o": "gemini-2.5-pro",
            "gpt-3.5-turbo": "gemini-2.5-flash",
            "claude-3-5-sonnet": "gemini-2.5-pro",
            "gemini-pro": "gemini-2.5-pro",
            "gemini-flash": "gemini-2.5-flash",
        }
        
        base_model = model_mapping.get(model, model)
        
        # 移除变体后缀（保留基础模型名）
        suffixes = ["-maxthinking", "-nothinking", "-search", "-maxthinking-search", "-nothinking-search"]
        for suffix in suffixes:
            if base_model.endswith(suffix):
                base_model = base_model[:-len(suffix)]
                break
        
        return base_model
    
    def _get_thinking_config(self, model: str) -> Optional[Dict]:
        """根据模型名获取 thinking 配置"""
        # 显式指定 maxthinking
        if "-maxthinking" in model:
            if "flash" in model:
                return {"thinkingConfig": {"thinkingBudget": 24576, "includeThoughts": True}}
            return {"thinkingConfig": {"thinkingBudget": 32768, "includeThoughts": True}}
        # 显式指定 nothinking
        elif "-nothinking" in model:
            return {"thinkingConfig": {"thinkingBudget": 0}}
        # gemini-3-pro-preview 默认需要 thinkingBudget
        elif "gemini-3" in model:
            return {"thinkingConfig": {"thinkingBudget": 8192, "includeThoughts": True}}
        # 2.5 pro 也可能需要
        elif "2.5-pro" in model:
            return {"thinkingConfig": {"thinkingBudget": 1024, "includeThoughts": True}}
        return None
    
    def _get_search_config(self, model: str) -> Optional[Dict]:
        """根据模型名获取 search grounding 配置"""
        if "-search" in model:
            return {"tools": [{"googleSearch": {}}]}
        return None
    
    def _convert_to_openai_response(self, gemini_response: dict, model: str) -> dict:
        """将Gemini响应转换为OpenAI格式"""
        content = ""
        reasoning_content = ""
        
        # 内部 API 返回格式是 {"response": {"candidates": ...}}
        response_data = gemini_response.get("response", gemini_response)
        
        if "candidates" in response_data and response_data["candidates"]:
            candidate = response_data["candidates"][0]
            if "content" in candidate and "parts" in candidate["content"]:
                for part in candidate["content"]["parts"]:
                    text = part.get("text", "")
                    # 检查是否是 thinking 内容
                    if part.get("thought", False):
                        reasoning_content += text
                    else:
                        content += text
        
        message = {
            "role": "assistant",
            "content": content
        }
        # 如果有 reasoning 内容，添加到消息中
        if reasoning_content:
            message["reasoning_content"] = reasoning_content
        
        return {
            "id": "chatcmpl-catiecli",
            "object": "chat.completion",
            "created": 0,
            "model": model,
            "choices": [{
                "index": 0,
                "message": message,
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0
            }
        }
    
    def _convert_to_openai_stream(self, chunk_data: str, model: str) -> str:
        """将Gemini流式响应转换为OpenAI SSE格式"""
        try:
            data = json.loads(chunk_data)
            content = ""
            reasoning_content = ""
            
            # 内部 API 返回格式是 {"response": {"candidates": ...}}
            response_data = data.get("response", data)
            
            if "candidates" in response_data and response_data["candidates"]:
                candidate = response_data["candidates"][0]
                if "content" in candidate and "parts" in candidate["content"]:
                    for part in candidate["content"]["parts"]:
                        text = part.get("text", "")
                        if part.get("thought", False):
                            reasoning_content += text
                        else:
                            content += text
            
            # 构建 delta
            delta = {}
            if content:
                delta["content"] = content
            if reasoning_content:
                delta["reasoning_content"] = reasoning_content
            
            if not delta:
                return ""
            
            openai_chunk = {
                "id": "chatcmpl-catiecli",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": model,
                "choices": [{
                    "index": 0,
                    "delta": delta,
                    "finish_reason": None
                }]
            }
            return f"data: {json.dumps(openai_chunk)}\n\n"
        except:
            return ""
