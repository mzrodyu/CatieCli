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

## 🚀 部署教程

### 🎯 一键安装（推荐）

SSH 登录服务器，复制粘贴这一行命令：

```bash
curl -sSL https://raw.githubusercontent.com/mzrodyu/CatieCli/main/install.sh | bash
```

自动完成：安装 Docker → 下载代码 → 询问密码 → 启动服务

---

### 🦥 懒人专属（给复制粘贴都嫌累的人）

如果服务器已装好 Docker，一行搞定：

```bash
docker run -d -p 5001:5001 -v catiecli-data:/app/data --name catiecli ghcr.io/mzrodyu/catiecli:latest
```

访问 `http://你的IP:5001`，默认账号 `admin` / `admin123`

> ⚠️ 注意：这个镜像可能不是最新版，建议用上面的一键安装

---

### 方式一：1Panel 面板部署（推荐新手）

> 💡 1Panel 是一个开源的 Linux 服务器管理面板，官网：<https://1panel.cn>

#### 第一步：安装 1Panel（如已安装跳过）

```bash
curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh && bash quick_start.sh
```

安装完成后，浏览器访问 `http://你的服务器IP:面板端口` 进入 1Panel。

---

#### 第二步：下载项目代码

1. 在 1Panel 左侧菜单点击 **"终端"**
2. 输入以下命令并回车：

```bash
cd /opt
git clone https://github.com/mzrodyu/CatieCli.git
```

等待下载完成，会看到 `Cloning into 'CatieCli'...` 和 `done` 字样。

---

#### 第三步：创建后端运行环境

**3.1** 在 1Panel 左侧菜单，找到 **"网站"**，点一下

**3.2** 页面上方会出现几个标签：`PHP` `Java` `Node.js` `Go` `Python`，点击 **"Python"**

**3.3** 点击蓝色按钮 **"创建运行环境"**，会弹出一个表单

**3.4** 开始填写表单：

- **名称**：随便起个名字，比如 `catiecli`、`gemini-api`、`myapi` 都行
- **项目目录**：点击输入框右边的 📁 文件夹图标，在弹出的窗口里依次点击：
  - 点击 `opt` 文件夹
  - 点击 `CatieCli` 文件夹  
  - 点击 `backend` 文件夹
  - 点击右下角 **"选择"** 按钮
- **启动命令**：复制粘贴这一整行：

  ```bash
  pip install -r requirements.txt && python run.py
  ```

- **应用**：第一个下拉框选 `Python`，第二个下拉框选 `3.10` 或 `3.11` 或 `3.12`（选最新的就行）
- **容器名称**：输入 `catiecli`

**3.5** 配置端口（根据访问方式选择）

> 💡 **二选一**：如果你打算用纯域名访问（推荐），可以跳过端口配置，直接看第五步配置反向代理。

**如果你想用 IP+端口 访问**（如 `http://1.2.3.4:5001`）：

- 点击表单下方的 **"端口"** 标签
- 点击 **"添加"** 按钮
- 第一个输入框（容器端口）填：`5001`（可自定义，比如 `8080`）
- 第二个输入框（主机端口）填：`5001`（和上面一样）
- 把 **"端口外部访问"** 的开关打开（变成蓝色）
- 还需要配置防火墙：
  - 1Panel 左侧 **"主机"** → **"防火墙"** → **"创建规则"**
  - 协议 `TCP`，端口 `5001`，策略 `放行`
  - ⚠️ 云服务器还需在控制台"安全组"放行此端口

**如果你想用纯域名访问**（推荐，如 `https://cat.example.com`）：

- **端口不用配置！** 跳过这一步
- 后面第五步配置反向代理后，直接用域名访问
- 不带端口号，更安全更专业

**3.6** 配置环境变量（设置你的管理员账号密码）

- 点击 **"环境变量"** 标签
- 点击 **"添加"** 按钮，添加第一个变量：
  - 左边输入：`ADMIN_USERNAME`
  - 右边输入：`admin`（这是你的登录用户名）
- 再点 **"添加"**，添加第二个变量：
  - 左边输入：`ADMIN_PASSWORD`
  - 右边输入：`你的密码`（比如 `MyPass123`，记住它！）
- 再点 **"添加"**，添加第三个变量：
  - 左边输入：`SECRET_KEY`
  - 右边输入：随便敲一串字母数字（比如 `aabbcc112233ddeeff`）

**3.7** 全部填好后，点击右下角的 **"确认"** 按钮

**3.8** 等待启动

- 页面会回到列表，你会看到刚创建的 `catiecli`
- 状态可能显示"启动中"（黄色）或"构建中"
- 等 1-3 分钟，刷新页面，直到状态变成 **"已启动"**（绿色）
- 如果显示红色"失败"，点击名称查看日志排查问题

---

#### 第四步：测试访问

浏览器访问：`http://你的服务器IP:5001`

如果看到登录页面，说明部署成功！🎉

用刚才设置的用户名密码登录。

---

#### 第五步：配置域名访问（可选但推荐）

1. 在 1Panel 左侧点击 **"网站"** → **"网站"**
2. 点击 **"创建网站"** → 选择 **"反向代理"**
3. 填写：
   - 主域名：`你的域名`（如 `api.example.com`）
   - 代理地址：`http://127.0.0.1:5001`
4. 点击确认
5. 如需 HTTPS，点击网站列表中你的域名 → **"HTTPS"** → 申请证书

---

#### 第六步：部署 Discord Bot（可选）

如果你需要 Discord Bot 功能：

1. 去 [Discord Developer Portal](https://discord.com/developers/applications) 创建 Bot，获取 Token
2. 在 1Panel 再次进入 **"运行环境"** → **"Python"** → **"创建运行环境"**
3. 填写：

| 配置项   | 填什么                                             |
| -------- | -------------------------------------------------- |
| 名称     | `catiecli-bot`                                     |
| 项目目录 | `/opt/CatieCli/discord-bot`                        |
| 启动命令 | `pip install -r requirements.txt && python bot.py` |
| 应用     | Python 3.10+                                       |
| 容器名称 | `catiecli-bot`                                     |

4. 添加环境变量：

| 变量名           | 填什么                                     |
| ---------------- | ------------------------------------------ |
| `DISCORD_TOKEN`  | 你的 Discord Bot Token                     |
| `API_BASE_URL`   | `http://catiecli:5001`                     |
| `API_PUBLIC_URL` | `https://你的域名` 或 `http://你的IP:5001` |

5. 点击确认，等待启动

---

### 方式二：命令行部署

#### 后端

```bash
cd backend

# 安装依赖
pip install -r requirements.txt

# 首次启动会自动创建 .env 文件
# 可选：编辑 .env 修改配置

# 启动服务
python run.py
```

#### Discord Bot

```bash
cd discord-bot

# 安装依赖
pip install -r requirements.txt

# 设置环境变量
export DISCORD_TOKEN=your_discord_bot_token
export API_BASE_URL=http://localhost:5001
export API_PUBLIC_URL=https://your-domain.com

# 启动 Bot
python bot.py
```

---

### 方式三：Docker Compose 部署（最简单）

```bash
# 1. 克隆代码
git clone https://github.com/mzrodyu/CatieCli.git
cd CatieCli

# 2. 创建配置文件
cp .env.example .env

# 3. 修改配置
nano .env  # 修改 ADMIN_PASSWORD 和 SECRET_KEY

# 4. 一键启动
docker-compose up -d

# 5. 查看日志
docker-compose logs -f
```

访问 `http://你的IP:5001` 即可

#### 启用 Discord Bot

编辑 `docker-compose.yml`，取消 bot 服务的注释，填入 Token：

```yaml
bot:
  build: ./discord-bot
  environment:
    - DISCORD_TOKEN=你的Token
    - API_BASE_URL=http://backend:5001
    - API_PUBLIC_URL=https://你的域名
```

然后 `docker-compose up -d` 重新启动

---

## 🔄 更新升级

### Docker Compose 部署

```bash
cd /你的安装目录
git pull
docker-compose up -d --build
```

### 1Panel 部署

```bash
cd /opt/CatieCli  # 或你的项目目录
git pull
# 然后在 1Panel 面板重启运行环境
```

### 一键脚本安装的

```bash
cd /opt/catiecli
git pull
docker-compose up -d --build
```

---

## ⚠️ 注意事项

- **首次启动**自动创建 `.env` 配置文件和管理员账号
- **环境变量优先级**高于 `.env` 文件配置
- **修改管理员**用户名/密码后重启即生效，旧管理员自动降级
- **前端已构建**，无需手动 npm build
- **默认账号**：`admin` / `admin123`（请立即修改！）
- **默认端口**：`5001`，可通过环境变量 `PORT` 自定义
- **Google OAuth**：已内置 Gemini CLI 官方凭据，无需配置即可使用

### 关于 Google OAuth 凭据

项目已内置 Gemini CLI 官方公开凭据，**无需额外配置**即可获取 Gemini 凭证。

⚠️ **注意**：如果你自己配置了 `GOOGLE_CLIENT_ID` 和 `GOOGLE_CLIENT_SECRET`，需要在 [Google Cloud Console](https://console.cloud.google.com/apis/credentials) 添加回调地址 `http://localhost:8080`，否则会报 `redirect_uri_mismatch` 错误。

**建议**：直接使用默认凭据，不要自己配置。

### 关于端口

程序内部必须监听一个端口才能接收请求，默认是 `5001`。

**但你不一定需要关心这个端口：**

| 访问方式         | 用户看到的地址            | 是否需要配置端口 |
| ---------------- | ------------------------- | ---------------- |
| 域名 + 反向代理  | `https://cat.example.com` | ❌ 不需要         |
| IP + 端口        | `http://1.2.3.4:5001`     | ✅ 需要开放端口   |
| Zeabur/Vercel 等 | `https://xxx.zeabur.app`  | ❌ 平台自动处理   |

**简单来说：**
- 用域名访问 → 不用管端口，反向代理会处理
- 用 IP 访问 → 需要知道端口号（默认 5001）

### 自定义端口（可选）

如果你需要修改默认端口：

**Docker Compose：**
```yaml
environment:
  - PORT=8080
ports:
  - "8080:8080"
```

**1Panel 环境变量：**
```
PORT=8080
```
同时端口映射也改成 `8080:8080`

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

# 服务端口（可选，默认 5001，使用域名反代可不配置）
# PORT=5001

# 默认用户配额
DEFAULT_DAILY_QUOTA=100

# 注册开关
ALLOW_REGISTRATION=true

# Google OAuth（已内置默认凭据，无需配置）
# 如需自定义，取消注释并填入你的凭据
# GOOGLE_CLIENT_ID=your-client-id
# GOOGLE_CLIENT_SECRET=your-client-secret
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

> 💡 端口默认 `5001`，可通过环境变量 `PORT` 自定义。如果使用域名反向代理，直接用域名即可。

```bash
# 本地/IP 访问（替换为你的端口）
curl http://localhost:5001/v1/chat/completions \
  -H "Authorization: Bearer cat-your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-2.5-flash",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# 域名访问
curl https://your-domain.com/v1/chat/completions \
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
