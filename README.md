# 🐱 CatieCli-maomao

**Gemini API 代理服务** - 支持 OpenAI 兼容接口、Gemini 原生接口、凭证池管理、Discord Bot 集成

作者：**Catie猫猫**

## ✨ 功能特性

- 🔄 **OpenAI 兼容 API** - 直接替换 OpenAI 端点使用
- � **Gemini 原生 API** - 支持 generateContent / streamGenerateContent
- 🔀 **反向代理** - 可作为 Gemini API 反代使用
- � **凭证池管理** - 支持多凭证轮询、自动刷新 Token、失效自动禁用
- 👥 **用户系统** - 注册登录、配额管理、使用统计
- 🤖 **Discord Bot** - 通过 Discord 注册、获取 API Key、贡献凭证
- 📊 **实时监控** - WebSocket 推送、使用日志、统计面板
- 🔐 **OAuth 授权** - 支持 Google OAuth 获取 Gemini 凭证
- 📢 **公告系统** - 支持发布公告，强制阅读倒计时

## 📡 API 接口

### OpenAI 兼容接口

```
POST /v1/chat/completions
POST /chat/completions
```

### Gemini 原生接口

```
POST /v1beta/models/{model}:generateContent
POST /v1/models/{model}:generateContent
POST /models/{model}:generateContent

POST /v1beta/models/{model}:streamGenerateContent
POST /v1/models/{model}:streamGenerateContent
POST /models/{model}:streamGenerateContent

GET /v1beta/models
GET /v1/models
GET /models
```

### 支持的模型

- `gemini-2.5-flash`
- `gemini-2.5-pro`
- `gemini-3-pro-preview`

支持后缀：`-maxthinking` / `-nothinking` / `-search`

### 使用示例

**OpenAI 格式：**

```bash
curl http://localhost:5001/v1/chat/completions \
  -H "Authorization: Bearer cat-your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-2.5-flash",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

**Gemini 格式：**

```bash
curl http://localhost:5001/v1beta/models/gemini-2.5-flash:generateContent \
  -H "Authorization: Bearer cat-your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "contents": [{"parts": [{"text": "Hello!"}]}]
  }'
```

## 📁 项目结构

```
CatieCli/
├── backend/          # FastAPI 后端
│   ├── app/
│   │   ├── routers/  # API 路由
│   │   ├── models/   # 数据模型
│   │   ├── services/ # 业务逻辑
│   │   └── config.py # 配置
│   ├── run.py        # 启动入口
│   └── requirements.txt
├── frontend/         # React 前端
│   ├── src/
│   │   ├── pages/    # 页面组件
│   │   └── api.js    # API 客户端
│   └── package.json
└── discord-bot/      # Discord Bot
    ├── bot.py
    └── requirements.txt
```

## 🚀 快速开始

### 后端部署

```bash
cd backend

# 安装依赖
pip install -r requirements.txt

# 复制配置文件
cp .env.example .env
# 编辑 .env 设置必要的配置

# 启动服务
python run.py
```

### 前端部署

```bash
cd frontend

# 安装依赖
npm install

# 开发模式
npm run dev

# 构建生产版本（输出到 backend/static）
npm run build
```

### Discord Bot 部署

```bash
cd discord-bot

# 安装依赖
pip install -r requirements.txt

# 设置环境变量
export DISCORD_TOKEN=your_discord_bot_token
export API_BASE_URL=http://localhost:5001
export API_PUBLIC_URL=http://your-domain:5001

# 启动 Bot
python bot.py
```

## ⚙️ 配置说明

### 后端配置 (.env)

```env
# 数据库
DATABASE_URL=sqlite+aiosqlite:///./data/gemini_proxy.db

# JWT 密钥（请更改！）
SECRET_KEY=your-super-secret-key

# 管理员账号
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_admin_password

# 服务端口
PORT=5001

# 默认用户配额
DEFAULT_DAILY_QUOTA=100

# 注册开关
ALLOW_REGISTRATION=true

# Google OAuth（使用 Gemini CLI 官方凭据）
# 来源: https://github.com/anthropics/gemini-cli
GOOGLE_CLIENT_ID=681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=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
```

### Discord Bot 配置

| 环境变量         | 说明                        |
| ---------------- | --------------------------- |
| `DISCORD_TOKEN`  | Discord Bot Token           |
| `API_BASE_URL`   | 后端 API 地址（内部）       |
| `API_PUBLIC_URL` | 后端 API 地址（显示给用户） |
| `ADMIN_ROLE_ID`  | 管理员角色 ID（可选）       |

## 📡 API 使用

### OpenAI 兼容接口

```bash
curl http://localhost:5001/v1/chat/completions \
  -H "Authorization: Bearer cat-your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-2.5-flash",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### 支持的模型

- `gemini-2.5-flash` / `gemini-2.5-flash-preview-05-20`
- `gemini-2.5-pro` / `gemini-2.5-pro-preview-05-06`
- `gemini-2.0-flash`
- `gemini-2.0-flash-lite`

## 🤖 Discord Bot 命令

| 命令        | 说明                    |
| ----------- | ----------------------- |
| `/register` | 注册账号                |
| `/key`      | 获取 API Key            |
| `/resetkey` | 重新生成 API Key        |
| `/stats`    | 查看使用统计            |
| `/donate`   | 贡献凭证获取 OAuth 链接 |
| `/callback` | 提交 OAuth 回调 URL     |

## 🐳 Docker 部署

### 后端

```bash
cd backend
docker build -t catiecli-backend .
docker run -d -p 5001:5001 -v ./data:/app/data --env-file .env catiecli-backend
```

### Discord Bot

```bash
cd discord-bot
docker build -t catiecli-bot .
docker run -d --env-file .env catiecli-bot
```

## 📄 开源协议

MIT License

## 🙏 致谢

感谢所有贡献凭证的用户！
