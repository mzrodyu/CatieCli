import {
    Activity,
    BarChart2,
    Cat,
    Check,
    CheckCircle,
    Copy,
    Download,
    ExternalLink,
    Gift,
    LogOut,
    RefreshCcw,
    RefreshCw,
    Settings,
    Shield,
    Upload,
    Users,
    X,
    Zap
} from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import api from '../api'
import { useAuth } from '../App'
import { useWebSocket } from '../hooks/useWebSocket'

export default function Dashboard() {
  const { user, logout } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const [userInfo, setUserInfo] = useState(null)
  const [oauthMessage, setOauthMessage] = useState(null)
  const [copied, setCopied] = useState(false)
  const [stats, setStats] = useState(null)
  
  // API Key 相关
  const [showKeyModal, setShowKeyModal] = useState(false)
  const [myKey, setMyKey] = useState(null)
  const [keyLoading, setKeyLoading] = useState(false)
  const [keyCopied, setKeyCopied] = useState(false)

  // 凭证管理相关
  const [showCredModal, setShowCredModal] = useState(false)
  const [myCredentials, setMyCredentials] = useState([])
  const [credLoading, setCredLoading] = useState(false)
  const [uploadFiles, setUploadFiles] = useState([])
  const [uploadPublic, setUploadPublic] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [quotaModal, setQuotaModal] = useState(null)
  const [loadingQuota, setLoadingQuota] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)  // 检测结果弹窗

  // 处理 OAuth 回调消息
  useEffect(() => {
    const oauth = searchParams.get('oauth')
    if (oauth === 'success') {
      setOauthMessage({ type: 'success', text: '🎉 凭证贡献成功！感谢您的支持！' })
      setSearchParams({})
    } else if (oauth === 'error') {
      const msg = searchParams.get('msg') || '未知错误'
      setOauthMessage({ type: 'error', text: `凭证获取失败: ${msg}` })
      setSearchParams({})
    }
  }, [searchParams, setSearchParams])

  // WebSocket 实时更新
  const handleWsMessage = useCallback((data) => {
    if (data.type === 'stats_update' || data.type === 'log_update') {
      api.get('/api/auth/me').then(res => setUserInfo(res.data)).catch(() => {})
      fetchStats()
    }
  }, [])

  const { connected } = useWebSocket(handleWsMessage)

  // 获取公共统计
  const fetchStats = async () => {
    try {
      const res = await api.get('/api/public/stats')
      setStats(res.data)
    } catch (err) {
      // 忽略
    }
  }

  useEffect(() => {
    api.get('/api/auth/me').then(res => setUserInfo(res.data)).catch(() => {})
    fetchStats()
  }, [])

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      // HTTP 环境下的备用方案
      const textarea = document.createElement('textarea')
      textarea.value = text
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // 获取或创建 API Key
  const fetchOrCreateKey = async () => {
    setKeyLoading(true)
    try {
      // 先尝试获取现有的 key
      const res = await api.get('/api/auth/api-keys')
      if (res.data.length > 0) {
        setMyKey(res.data[0])
      } else {
        // 没有则创建一个
        const createRes = await api.post('/api/auth/api-keys', { name: 'default' })
        setMyKey({ key: createRes.data.key, name: 'default' })
      }
    } catch (err) {
      console.error('获取Key失败', err)
    } finally {
      setKeyLoading(false)
    }
  }

  const copyKey = async () => {
    if (myKey?.key) {
      try {
        await navigator.clipboard.writeText(myKey.key)
      } catch {
        // HTTP 环境下的备用方案
        const textarea = document.createElement('textarea')
        textarea.value = myKey.key
        document.body.appendChild(textarea)
        textarea.select()
        document.execCommand('copy')
        document.body.removeChild(textarea)
      }
      setKeyCopied(true)
      setTimeout(() => setKeyCopied(false), 2000)
    }
  }

  const [regenerating, setRegenerating] = useState(false)
  const regenerateKey = async () => {
    if (!myKey?.id) return
    if (!confirm('确定要重新生成 API 密钥吗？旧密钥将立即失效！')) return
    setRegenerating(true)
    try {
      const res = await api.post(`/api/auth/api-keys/${myKey.id}/regenerate`)
      setMyKey({ ...myKey, key: res.data.key })
      alert('密钥已重新生成！')
    } catch (err) {
      alert('重新生成失败: ' + (err.response?.data?.detail || err.message))
    } finally {
      setRegenerating(false)
    }
  }

  // 凭证管理函数
  const fetchMyCredentials = async () => {
    setCredLoading(true)
    try {
      const res = await api.get('/api/auth/credentials')
      setMyCredentials(res.data)
    } catch (err) {
      console.error('获取凭证失败', err)
    } finally {
      setCredLoading(false)
    }
  }

  const uploadCredential = async () => {
    if (uploadFiles.length === 0) return
    setUploading(true)
    try {
      const formData = new FormData()
      uploadFiles.forEach(file => formData.append('files', file))
      formData.append('is_public', uploadPublic)
      
      const res = await api.post('/api/auth/credentials/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      alert(`上传完成: 成功 ${res.data.uploaded_count}/${res.data.total_count} 个`)
      setUploadFiles([])
      fetchMyCredentials()
    } catch (err) {
      alert(err.response?.data?.detail || '上传失败')
    } finally {
      setUploading(false)
    }
  }

  const toggleCredActive = async (id, currentActive) => {
    try {
      await api.patch(`/api/auth/credentials/${id}`, null, {
        params: { is_active: !currentActive }
      })
      fetchMyCredentials()
    } catch (err) {
      alert('操作失败: ' + (err.response?.data?.detail || err.message))
    }
  }

  const toggleCredPublic = async (id, currentPublic) => {
    try {
      await api.patch(`/api/auth/credentials/${id}`, null, {
        params: { is_public: !currentPublic }
      })
      fetchMyCredentials()
    } catch (err) {
      console.error('更新失败', err)
    }
  }

  const deleteCred = async (id) => {
    if (!confirm('确定删除此凭证？')) return
    try {
      await api.delete(`/api/auth/credentials/${id}`)
      fetchMyCredentials()
    } catch (err) {
      console.error('删除失败', err)
    }
  }

  const fetchQuota = async (id) => {
    setLoadingQuota(true)
    try {
      const res = await api.get(`/api/manage/credentials/${id}/quota`)
      setQuotaModal(res.data)
    } catch (err) {
      alert('获取配额失败: ' + (err.response?.data?.detail || err.message))
    } finally {
      setLoadingQuota(false)
    }
  }

  const exportCred = async (id, email) => {
    try {
      const res = await api.get(`/api/auth/credentials/${id}/export`)
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `credential_${email || id}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      alert('导出失败: ' + (err.response?.data?.detail || err.message))
    }
  }

  // 检测单个凭证
  const [verifyingCred, setVerifyingCred] = useState(null)
  const verifyCred = async (id, email) => {
    setVerifyingCred(id)
    try {
      const res = await api.post(`/api/auth/credentials/${id}/verify`)
      setVerifyResult({ ...res.data, email })
      fetchMyCredentials()
    } catch (err) {
      setVerifyResult({ error: err.response?.data?.detail || err.message, is_valid: false, email })
    } finally {
      setVerifyingCred(null)
    }
  }

  const [activeTab, setActiveTab] = useState('stats')
  const apiEndpoint = `${window.location.origin}/v1`

  // 自动获取 API Key
  useEffect(() => {
    fetchOrCreateKey()
  }, [])

  return (
    <div className="min-h-screen">
      {/* 导航栏 */}
      <nav className="bg-dark-900 border-b border-dark-700">
        <div className="max-w-4xl mx-auto px-4 py-4">
          {/* 移动端：两行布局 */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Cat className="w-8 h-8 text-purple-400" />
              <span className="text-xl font-bold">Catiecli</span>
              {connected && (
                <span className="flex items-center gap-1 text-xs text-green-400">
                  <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
                  <span className="hidden sm:inline">实时</span>
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 sm:gap-4">
              <span className="text-gray-300 text-sm sm:text-base hidden sm:inline">欢迎，{user?.username}</span>
              <button onClick={logout} className="px-3 py-1.5 sm:px-4 sm:py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg flex items-center gap-1 sm:gap-2 text-sm sm:text-base">
                <LogOut size={16} />
                <span className="hidden sm:inline">退出登录</span>
              </button>
            </div>
          </div>
          {/* 管理员链接 - 移动端显示在第二行 */}
          {user?.is_admin && (
            <div className="flex items-center gap-4 mt-3 pt-3 border-t border-dark-700 overflow-x-auto">
              <Link to="/stats" className="text-gray-400 hover:text-white flex items-center gap-1 text-sm whitespace-nowrap">
                <Activity size={16} />
                统计
              </Link>
              <Link to="/settings" className="text-gray-400 hover:text-white flex items-center gap-1 text-sm whitespace-nowrap">
                <Settings size={16} />
                设置
              </Link>
              <Link to="/admin" className="text-gray-400 hover:text-white flex items-center gap-1 text-sm whitespace-nowrap">
                <Users size={16} />
                用户
              </Link>
            </div>
          )}
        </div>
      </nav>

      <div className="max-w-4xl mx-auto px-4 py-6">
        {/* OAuth 消息提示 */}
        {oauthMessage && (
          <div className={`mb-6 p-4 rounded-xl border ${
            oauthMessage.type === 'success' 
              ? 'bg-green-500/10 border-green-500/30 text-green-400'
              : 'bg-red-500/10 border-red-500/30 text-red-400'
          }`}>
            <div className="flex items-center justify-between">
              <span>{oauthMessage.text}</span>
              <button onClick={() => setOauthMessage(null)} className="text-gray-400 hover:text-white">✕</button>
            </div>
          </div>
        )}

        {/* Tab 导航 */}
        <div className="flex gap-2 border-b border-dark-700 mb-6">
          <button
            onClick={() => setActiveTab('stats')}
            className={`px-6 py-3 font-medium border-b-2 transition-colors ${
              activeTab === 'stats' 
                ? 'text-white border-purple-500' 
                : 'text-gray-400 border-transparent hover:text-white'
            }`}
          >
            个人统计
          </button>
          <button
            onClick={() => { setActiveTab('credentials'); fetchMyCredentials(); }}
            className={`px-6 py-3 font-medium border-b-2 transition-colors ${
              activeTab === 'credentials' 
                ? 'text-white border-purple-500' 
                : 'text-gray-400 border-transparent hover:text-white'
            }`}
          >
            凭证管理
          </button>
          <button
            onClick={() => setActiveTab('apikey')}
            className={`px-6 py-3 font-medium border-b-2 transition-colors ${
              activeTab === 'apikey' 
                ? 'text-red-400 border-red-500' 
                : 'text-gray-400 border-transparent hover:text-white'
            }`}
          >
            API密钥
          </button>
        </div>

        {/* Tab: 个人统计 */}
        {activeTab === 'stats' && (
          <>
            <h2 className="text-xl font-semibold mb-4">个人使用统计</h2>
            
            {/* 统计卡片 */}
            <div className="grid md:grid-cols-2 gap-4 mb-6">
              <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
                <div className="text-center">
                  <div className="text-4xl font-bold mb-2">
                    <span className="text-blue-400">{userInfo?.today_usage || 0}</span>
                    <span className="text-gray-500"> / {userInfo?.daily_quota || 100}</span>
                  </div>
                  <div className="text-gray-400">已使用 / 调用上限</div>
                </div>
              </div>
              <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
                <div className="text-center">
                  <div className="text-4xl font-bold text-green-400 mb-2">
                    {userInfo?.credential_count || 0}
                  </div>
                  <div className="text-gray-400">有效 Google 账号数</div>
                </div>
              </div>
            </div>

            {/* 贡献提示 */}
            <div className="bg-gradient-to-r from-purple-600/20 via-pink-600/20 to-purple-600/20 border border-purple-500/30 rounded-xl p-6 mb-6">
              <div className="flex items-center gap-4">
                <div className="flex-shrink-0">
                  <Gift className="w-12 h-12 text-purple-400" />
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold mb-1">贡献凭证，共享使用</h3>
                  <p className="text-gray-400 text-sm">
                    通过 Google OAuth 授权，将您的 Gemini API 凭证贡献到公共池，让更多人免费使用
                  </p>
                </div>
                <Link 
                  to="/oauth" 
                  className="px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium flex items-center gap-2"
                >
                  <ExternalLink size={18} />
                  立即贡献
                </Link>
              </div>
            </div>

            {/* 公共统计 */}
            <h3 className="text-lg font-semibold mb-3">全站统计</h3>
            <div className="grid md:grid-cols-3 gap-4">
              <div className="bg-dark-800 border border-dark-600 rounded-xl p-4 text-center">
                <Users className="w-6 h-6 text-blue-400 mx-auto mb-2" />
                <div className="text-xl font-bold">{stats?.user_count || '-'}</div>
                <div className="text-gray-400 text-sm">注册用户</div>
              </div>
              <div className="bg-dark-800 border border-dark-600 rounded-xl p-4 text-center">
                <Zap className="w-6 h-6 text-yellow-400 mx-auto mb-2" />
                <div className="text-xl font-bold">{stats?.active_credentials || '-'}</div>
                <div className="text-gray-400 text-sm">可用凭证</div>
              </div>
              <div className="bg-dark-800 border border-dark-600 rounded-xl p-4 text-center">
                <Activity className="w-6 h-6 text-green-400 mx-auto mb-2" />
                <div className="text-xl font-bold">{stats?.today_requests || '-'}</div>
                <div className="text-gray-400 text-sm">今日请求</div>
              </div>
            </div>
          </>
        )}

        {/* Tab: 凭证管理 */}
        {activeTab === 'credentials' && (
          <>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold">我的凭证</h2>
              <div className="flex gap-2">
                <Link 
                  to="/credentials"
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg flex items-center gap-2"
                >
                  <Upload size={16} />
                  上传凭证
                </Link>
                <Link 
                  to="/oauth"
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg flex items-center gap-2"
                >
                  <ExternalLink size={16} />
                  获取新凭证
                </Link>
              </div>
            </div>

            {credLoading ? (
              <div className="text-center py-8 text-gray-400">加载中...</div>
            ) : myCredentials.length === 0 ? (
              <div className="bg-dark-800 border border-dark-600 rounded-xl p-8 text-center">
                <Shield className="w-12 h-12 text-gray-500 mx-auto mb-4" />
                <p className="text-gray-400 mb-4">暂无凭证，去 OAuth 页面获取或上传 JSON</p>
                <Link 
                  to="/oauth"
                  className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg"
                >
                  <ExternalLink size={18} />
                  前往获取
                </Link>
              </div>
            ) : (
              <div className="space-y-3">
                {myCredentials.map(cred => (
                  <div key={cred.id} className="p-4 bg-dark-800 border border-dark-600 rounded-xl">
                    <div className="flex flex-col gap-3">
                      <div className="flex-1 min-w-0">
                        {/* 凭证名称 - 斜体灰色 */}
                        <div className="text-gray-400 italic mb-2 truncate">
                          {cred.email || cred.name}
                        </div>
                        
                        {/* 状态标签行 */}
                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                          {/* 启用状态 - 绿色实心 */}
                          {cred.is_active !== false ? (
                            <span className="text-xs px-2.5 py-1 bg-green-600 text-white rounded font-medium">
                              已启用
                            </span>
                          ) : (
                            <span className="text-xs px-2.5 py-1 bg-red-600 text-white rounded font-medium">
                              已禁用
                            </span>
                          )}
                          
                          {/* 模型等级 - 蓝色边框空心 */}
                          {cred.model_tier === '3' ? (
                            <span className="text-xs px-2.5 py-1 border border-blue-500 text-blue-400 rounded font-medium">
                              3.0可用
                            </span>
                          ) : (
                            <span className="text-xs px-2.5 py-1 border border-gray-500 text-gray-400 rounded font-medium">
                              2.5
                            </span>
                          )}
                          
                          {/* 捐赠状态 - 紫色边框空心 */}
                          {cred.is_public && (
                            <span className="text-xs px-2.5 py-1 border border-purple-500 text-purple-400 rounded font-medium">
                              已捐赠
                            </span>
                          )}
                          {!cred.is_public && (
                            <span className="text-xs px-2.5 py-1 border border-gray-600 text-gray-500 rounded font-medium">
                              私有
                            </span>
                          )}
                        </div>
                        
                        {/* 信息行 */}
                        <div className="text-xs text-gray-500">
                          最后成功: {cred.last_used_at ? new Date(cred.last_used_at).toLocaleString() : '从未使用'}
                        </div>
                      </div>
                      
                      <div className="flex items-center gap-2 flex-wrap">
                        {/* 配额按钮 */}
                        <button
                          onClick={() => fetchQuota(cred.id)}
                          disabled={loadingQuota}
                          className="px-3 py-1.5 rounded text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-50 flex items-center gap-1"
                          title="查看配额"
                        >
                          <BarChart2 size={12} />
                          配额
                        </button>
                        {/* 检测按钮 */}
                        <button
                          onClick={() => verifyCred(cred.id, cred.email)}
                          disabled={verifyingCred === cred.id}
                          className="px-3 py-1.5 rounded text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50 flex items-center gap-1"
                        >
                          {verifyingCred === cred.id ? (
                            <RefreshCw size={12} className="animate-spin" />
                          ) : (
                            <CheckCircle size={12} />
                          )}
                          检测
                        </button>
                        {/* 导出按钮 */}
                        <button
                          onClick={() => exportCred(cred.id, cred.email)}
                          className="px-3 py-1.5 rounded text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-1"
                          title="导出凭证"
                        >
                          <Download size={12} />
                          导出
                        </button>
                        {/* 启用/禁用开关 */}
                        <button
                          onClick={() => toggleCredActive(cred.id, cred.is_active)}
                          className={`px-3 py-1.5 rounded text-xs font-medium ${cred.is_active !== false ? 'bg-green-600 hover:bg-green-500' : 'bg-gray-600 hover:bg-gray-500'} text-white`}
                        >
                          {cred.is_active !== false ? '禁用' : '启用'}
                        </button>
                        {/* 捐赠/取消捐赠 */}
                        <button
                          onClick={() => toggleCredPublic(cred.id, cred.is_public)}
                          className={`px-3 py-1.5 rounded text-xs font-medium ${cred.is_public ? 'bg-gray-600 hover:bg-gray-500' : 'bg-green-600 hover:bg-green-500'} text-white`}
                        >
                          {cred.is_public ? '取消捐赠' : '捐赠'}
                        </button>
                        {/* 删除 */}
                        <button
                          onClick={() => deleteCred(cred.id)}
                          className="px-3 py-1.5 rounded text-xs font-medium bg-red-600 hover:bg-red-500 text-white"
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* 大锅饭规则提示 */}
            <div className="mt-6 bg-amber-500/10 border border-amber-500/30 rounded-xl p-4">
              <div className="text-amber-400 font-medium mb-1">💡 大锅饭规则</div>
              <div className="text-amber-300/70 text-sm">
                捐赠凭证后，您可以使用所有公共池凭证。不捐赠则只能用自己的凭证。
              </div>
            </div>
          </>
        )}

        {/* Tab: API密钥 */}
        {activeTab === 'apikey' && (
          <>
            <h2 className="text-xl font-semibold mb-4">API密钥</h2>
            
            {keyLoading ? (
              <div className="text-center py-8 text-gray-400">加载中...</div>
            ) : myKey ? (
              <>
                <div className="bg-dark-800 border border-dark-600 rounded-xl p-4 mb-4">
                  <div className="flex flex-col gap-3">
                    <code className="bg-dark-900 px-4 py-3 rounded-lg text-gray-300 font-mono text-sm overflow-x-auto break-all">
                      {myKey.key}
                    </code>
                    <div className="flex gap-2">
                      <button
                        onClick={copyKey}
                        className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center justify-center gap-2"
                      >
                        {keyCopied ? <Check size={16} /> : <Copy size={16} />}
                        {keyCopied ? '已复制' : '复制'}
                      </button>
                      <button
                        onClick={regenerateKey}
                        disabled={regenerating}
                        className="flex-1 px-4 py-2 bg-amber-600 hover:bg-amber-700 disabled:opacity-50 text-white rounded-lg flex items-center justify-center gap-2"
                      >
                        <RefreshCcw size={16} className={regenerating ? 'animate-spin' : ''} />
                        更改
                      </button>
                    </div>
                  </div>
                </div>

                {/* 使用提示 */}
                {!userInfo?.has_public_credentials && (
                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 mb-4">
                    <div className="flex items-start gap-3">
                      <span className="text-amber-400 text-lg">⚠️</span>
                      <div>
                        <div className="text-amber-400 font-medium">尚未上传有效凭证，Pro 模型调用频率限制为 5 次/分钟。</div>
                        <div className="text-amber-300/70 text-sm mt-1">
                          上传至少一个有效凭证即可提升到 10 次/分钟，并获得更高每日调用上限。
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* 使用说明 */}
                <div className="bg-dark-800 border border-dark-600 rounded-xl p-4">
                  <h3 className="font-semibold mb-3">使用方法</h3>
                  <div className="space-y-3 text-sm">
                    <div>
                      <div className="text-gray-400 mb-1">API 端点</div>
                      <code className="block bg-dark-900 px-3 py-2 rounded text-purple-400 font-mono">
                        {apiEndpoint}
                      </code>
                    </div>
                    <div>
                      <div className="text-gray-400 mb-1">在 SillyTavern / 酒馆 中使用</div>
                      <ol className="text-gray-300 space-y-1 list-decimal list-inside">
                        <li>打开连接设置 → Chat Completion</li>
                        <li>选择 <span className="text-purple-400">OpenAI</span></li>
                        <li>API 端点填写上方地址</li>
                        <li>API Key 填写您的密钥</li>
                        <li>模型: <span className="text-purple-400">gemini-2.5-flash</span> 或 <span className="text-purple-400">gemini-2.5-pro</span></li>
                      </ol>
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <div className="text-center py-8 text-red-400">获取失败，请刷新重试</div>
            )}
          </>
        )}
      </div>

      {/* 配额弹窗 */}
      {quotaModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-2xl w-full max-w-lg max-h-[80vh] overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-dark-600">
              <div>
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <BarChart2 className="text-indigo-400" />
                  模型配额信息
                </h3>
                <p className="text-sm text-gray-400 mt-1">{quotaModal.email || quotaModal.credential_name}</p>
              </div>
              <button onClick={() => setQuotaModal(null)} className="p-2 hover:bg-dark-600 rounded-lg">
                <X size={20} />
              </button>
            </div>
            
            <div className="px-4 pt-3">
              <span className={`text-xs px-2 py-1 rounded ${quotaModal.account_type === 'pro' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-gray-600/50 text-gray-400'}`}>
                {quotaModal.account_type === 'pro' ? '⭐ Pro 账号' : '普通账号'}
              </span>
            </div>
            
            {quotaModal.flash && (
              <div className="p-4 border-b border-dark-600">
                <div className="flex items-center justify-between text-sm mb-2">
                  <span className="font-semibold text-cyan-400">2.5-flash 配额</span>
                  <span className={`font-bold ${quotaModal.flash.percentage > 50 ? 'text-green-400' : quotaModal.flash.percentage > 20 ? 'text-yellow-400' : 'text-red-400'}`}>
                    {quotaModal.flash.percentage}%
                  </span>
                </div>
                <div className="h-3 bg-dark-600 rounded-full overflow-hidden">
                  <div className={`h-full rounded-full ${quotaModal.flash.percentage > 50 ? 'bg-cyan-500' : quotaModal.flash.percentage > 20 ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ width: `${quotaModal.flash.percentage}%` }} />
                </div>
                <div className="flex items-center justify-between text-xs text-gray-500 mt-1">
                  <span>已用 {quotaModal.flash.used} / {quotaModal.flash.limit}</span>
                  <span>剩余 {quotaModal.flash.remaining}</span>
                </div>
              </div>
            )}
            
            {quotaModal.premium && (
              <div className="p-4 border-b border-dark-600">
                <div className="flex items-center justify-between text-sm mb-2">
                  <span className="font-semibold text-purple-400">2.5-pro / 3.0 配额</span>
                  <span className={`font-bold ${quotaModal.premium.percentage > 50 ? 'text-green-400' : quotaModal.premium.percentage > 20 ? 'text-yellow-400' : 'text-red-400'}`}>
                    {quotaModal.premium.percentage}%
                  </span>
                </div>
                <div className="h-3 bg-dark-600 rounded-full overflow-hidden">
                  <div className={`h-full rounded-full ${quotaModal.premium.percentage > 50 ? 'bg-purple-500' : quotaModal.premium.percentage > 20 ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ width: `${quotaModal.premium.percentage}%` }} />
                </div>
                <div className="flex items-center justify-between text-xs text-gray-500 mt-1">
                  <span>已用 {quotaModal.premium.used} / {quotaModal.premium.limit}</span>
                  <span>剩余 {quotaModal.premium.remaining}</span>
                </div>
                <div className="text-xs text-purple-400/60 mt-1">{quotaModal.premium.note}</div>
              </div>
            )}
            
            <div className="p-4 overflow-y-auto max-h-[40vh]">
              <div className="text-xs text-gray-500 mb-2">各模型使用情况</div>
              {quotaModal.models?.filter(m => m.used > 0).length === 0 ? (
                <div className="text-center text-gray-500 py-4">今日暂无使用记录</div>
              ) : quotaModal.models?.filter(m => m.used > 0).map(item => (
                <div key={item.model} className="flex items-center justify-between py-2 border-b border-dark-700 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-sm">{item.model}</span>
                    {item.is_premium && <span className="text-xs px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded">高级</span>}
                  </div>
                  <span className="text-gray-400 text-sm">{item.used} 次</span>
                </div>
              ))}
            </div>
            
            <div className="px-4 py-2 bg-amber-500/10 border-t border-amber-500/30">
              <div className="text-xs text-amber-400/80">
                ⚠️ 此为本平台调用统计，不包含其他平台（如 AI Studio、CLI）的使用量
              </div>
            </div>
            <div className="p-4 border-t border-dark-600 flex items-center justify-between">
              <div className="text-xs text-gray-500">重置: {new Date(quotaModal.reset_time).toLocaleString()}</div>
              <button onClick={() => setQuotaModal(null)} className="px-4 py-2 bg-dark-600 hover:bg-dark-500 text-white rounded-lg text-sm">关闭</button>
            </div>
          </div>
        </div>
      )}

      {/* 检测结果弹窗 */}
      {verifyResult && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-2xl w-full max-w-md overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-dark-600">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <CheckCircle className={verifyResult.is_valid ? "text-green-400" : "text-red-400"} />
                凭证检测结果
              </h3>
              <button onClick={() => setVerifyResult(null)} className="p-2 hover:bg-dark-600 rounded-lg">
                <X size={20} />
              </button>
            </div>
            
            <div className="p-6 space-y-4">
              {/* 邮箱 */}
              <div className="text-gray-400 text-sm">{verifyResult.email}</div>
              
              {/* 状态 */}
              <div className="flex items-center gap-3">
                <span className="text-gray-400">状态</span>
                <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                  verifyResult.is_valid ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                }`}>
                  {verifyResult.is_valid ? '✅ 有效' : '❌ 无效'}
                </span>
              </div>
              
              {/* 模型等级 */}
              {verifyResult.model_tier && (
                <div className="flex items-center gap-3">
                  <span className="text-gray-400">模型等级</span>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    verifyResult.model_tier === '3' ? 'bg-purple-500/20 text-purple-400' : 'bg-gray-600/50 text-gray-300'
                  }`}>
                    {verifyResult.model_tier === '3' ? '🚀 3.0 可用' : '2.5'}
                  </span>
                </div>
              )}
              
              {/* 账号类型 */}
              {verifyResult.account_type && (
                <div className="flex items-center gap-3">
                  <span className="text-gray-400">账号类型</span>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    verifyResult.account_type === 'pro' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-gray-600/50 text-gray-300'
                  }`}>
                    {verifyResult.account_type === 'pro' ? '⭐ Pro (2TB存储)' : '普通账号'}
                  </span>
                </div>
              )}
              
              {/* 错误信息 */}
              {verifyResult.error && (
                <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                  {verifyResult.error}
                </div>
              )}
            </div>
            
            <div className="p-4 border-t border-dark-600 flex justify-end">
              <button
                onClick={() => setVerifyResult(null)}
                className="px-6 py-2 bg-dark-600 hover:bg-dark-500 text-white rounded-lg"
              >
                关闭
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
