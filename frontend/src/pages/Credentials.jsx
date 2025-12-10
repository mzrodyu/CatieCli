import {
    ArrowLeft,
    Cat,
    CheckCircle,
    Download,
    Gift,
    RefreshCw,
    Shield,
    Trash2,
    Upload
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../api'
import { useAuth } from '../App'

export default function Credentials() {
  const { user } = useAuth()
  const [credentials, setCredentials] = useState([])
  const [loading, setLoading] = useState(true)
  const [uploadFiles, setUploadFiles] = useState([])
  const [uploadPublic, setUploadPublic] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [message, setMessage] = useState({ type: '', text: '' })
  const [dragOver, setDragOver] = useState(false)
  const [quotaModal, setQuotaModal] = useState(null)  // 存储配额数据
  const [loadingQuota, setLoadingQuota] = useState(false)

  useEffect(() => {
    fetchCredentials()
  }, [])

  const fetchCredentials = async () => {
    setLoading(true)
    try {
      const res = await api.get('/api/auth/credentials')
      setCredentials(res.data)
    } catch (err) {
      setMessage({ type: 'error', text: '获取凭证失败' })
    } finally {
      setLoading(false)
    }
  }

  const uploadCredential = async () => {
    if (uploadFiles.length === 0) return
    setUploading(true)
    setMessage({ type: '', text: '' })
    try {
      const formData = new FormData()
      uploadFiles.forEach(file => formData.append('files', file))
      formData.append('is_public', uploadPublic)
      
      const res = await api.post('/api/auth/credentials/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      setMessage({ 
        type: 'success', 
        text: `上传完成: 成功 ${res.data.uploaded_count}/${res.data.total_count} 个` 
      })
      setUploadFiles([])
      // 清空文件选择
      document.getElementById('cred-file-input').value = ''
      fetchCredentials()
    } catch (err) {
      setMessage({ type: 'error', text: err.response?.data?.detail || '上传失败' })
    } finally {
      setUploading(false)
    }
  }

  const togglePublic = async (id, currentPublic) => {
    try {
      await api.patch(`/api/auth/credentials/${id}`, null, {
        params: { is_public: !currentPublic }
      })
      fetchCredentials()
    } catch (err) {
      setMessage({ type: 'error', text: '操作失败' })
    }
  }

  const toggleActive = async (id, currentActive) => {
    try {
      await api.patch(`/api/auth/credentials/${id}`, null, {
        params: { is_active: !currentActive }
      })
      fetchCredentials()
    } catch (err) {
      setMessage({ type: 'error', text: '操作失败' })
    }
  }

  const deleteCred = async (id) => {
    if (!confirm('确定删除此凭证？此操作不可恢复！')) return
    try {
      await api.delete(`/api/auth/credentials/${id}`)
      setMessage({ type: 'success', text: '删除成功' })
      fetchCredentials()
    } catch (err) {
      setMessage({ type: 'error', text: '删除失败' })
    }
  }

  const [verifying, setVerifying] = useState(null)
  
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
      setMessage({ type: 'success', text: '凭证已导出！' })
    } catch (err) {
      setMessage({ type: 'error', text: '导出失败: ' + (err.response?.data?.detail || err.message) })
    }
  }
  
  const verifyCred = async (id) => {
    setVerifying(id)
    setMessage({ type: '', text: '' })
    try {
      const res = await api.post(`/api/auth/credentials/${id}/verify`)
      const { is_valid, model_tier, supports_3, error } = res.data
      if (is_valid) {
        setMessage({ 
          type: 'success', 
          text: `✅ 凭证有效！等级: ${model_tier}${supports_3 ? ' 🎉 支持 Gemini 3!' : ''}` 
        })
      } else {
        setMessage({ type: 'error', text: `❌ 凭证无效: ${error || '未知错误'}` })
      }
      fetchCredentials()
    } catch (err) {
      setMessage({ type: 'error', text: '检测失败: ' + (err.response?.data?.detail || err.message) })
    } finally {
      setVerifying(null)
    }
  }

  const fetchQuota = async (id) => {
    setLoadingQuota(true)
    try {
      const res = await api.get(`/api/manage/credentials/${id}/quota`)
      setQuotaModal(res.data)
    } catch (err) {
      setMessage({ type: 'error', text: '获取配额失败: ' + (err.response?.data?.detail || err.message) })
    } finally {
      setLoadingQuota(false)
    }
  }

  return (
    <div className="min-h-screen">
      {/* 导航栏 */}
      <nav className="bg-dark-900 border-b border-dark-700">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Cat className="w-8 h-8 text-purple-400" />
            <span className="text-xl font-bold">Catiecli</span>
            <span className="text-sm text-gray-500 bg-dark-700 px-2 py-0.5 rounded">凭证管理</span>
          </div>
          <Link to="/dashboard" className="text-gray-400 hover:text-white flex items-center gap-2">
            <ArrowLeft size={20} />
            返回
          </Link>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto px-4 py-8">
        {/* 消息提示 */}
        {message.text && (
          <div className={`mb-6 p-4 rounded-xl border ${
            message.type === 'success' 
              ? 'bg-green-500/10 border-green-500/30 text-green-400' 
              : 'bg-red-500/10 border-red-500/30 text-red-400'
          }`}>
            {message.text}
          </div>
        )}

        {/* 上传区域 */}
        <div className="card p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Upload className="text-green-400" />
            上传凭证
          </h2>
          
          <div className="space-y-4">
            <div 
              className={`border-2 border-dashed rounded-lg p-6 text-center transition-colors ${
                dragOver ? 'border-purple-500 bg-purple-500/10' : 'border-dark-600 hover:border-purple-500'
              }`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault()
                setDragOver(false)
                const files = Array.from(e.dataTransfer.files).filter(f => f.name.endsWith('.json'))
                if (files.length > 0) setUploadFiles(prev => [...prev, ...files])
              }}
            >
              <input
                type="file"
                accept=".json"
                multiple
                onChange={(e) => setUploadFiles(prev => [...prev, ...Array.from(e.target.files)])}
                className="hidden"
                id="cred-file-input"
              />
              <label htmlFor="cred-file-input" className="cursor-pointer block">
                <Upload size={32} className="mx-auto mb-3 text-gray-400" />
                <div className="text-gray-300 mb-1">
                  {uploadFiles.length > 0 
                    ? `已选择 ${uploadFiles.length} 个文件` 
                    : '点击或拖拽 JSON 凭证文件'}
                </div>
                <div className="text-xs text-gray-500">支持多选，格式需包含 refresh_token 字段</div>
              </label>
            </div>
            
            {/* 已选文件列表 */}
            {uploadFiles.length > 0 && (
              <div className="bg-dark-800 rounded-lg p-3 space-y-2">
                <div className="text-xs text-gray-400 mb-2">已选择的文件：</div>
                {uploadFiles.map((file, idx) => (
                  <div key={idx} className="flex items-center justify-between text-sm bg-dark-700 rounded px-3 py-2">
                    <span className="truncate">{file.name}</span>
                    <button 
                      onClick={() => setUploadFiles(prev => prev.filter((_, i) => i !== idx))}
                      className="text-red-400 hover:text-red-300 ml-2"
                    >
                      ✕
                    </button>
                  </div>
                ))}
                <button 
                  onClick={() => { setUploadFiles([]); document.getElementById('cred-file-input').value = '' }}
                  className="text-xs text-gray-500 hover:text-gray-400"
                >
                  清空全部
                </button>
              </div>
            )}

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-3 cursor-pointer p-3 bg-purple-500/10 border border-purple-500/30 rounded-lg hover:bg-purple-500/20 transition-colors">
                <input
                  type="checkbox"
                  checked={uploadPublic}
                  onChange={(e) => setUploadPublic(e.target.checked)}
                  className="w-5 h-5 rounded"
                />
                <div>
                  <div className="text-purple-400 font-medium flex items-center gap-2">
                    <Gift size={16} />
                    捐赠到公共池
                  </div>
                  <div className="text-xs text-purple-300/70">捐赠后可使用所有公共凭证</div>
                </div>
              </label>

              <button
                onClick={uploadCredential}
                disabled={uploading || uploadFiles.length === 0}
                className="px-6 py-3 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg flex items-center gap-2 font-medium"
              >
                {uploading ? <RefreshCw className="animate-spin" size={18} /> : <Upload size={18} />}
                {uploading ? '上传中...' : '上传凭证'}
              </button>
            </div>
          </div>
        </div>

        {/* 凭证列表 */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Shield className="text-blue-400" />
              我的凭证 ({credentials.length})
            </h2>
            <button 
              onClick={fetchCredentials}
              className="text-gray-400 hover:text-white p-2"
              title="刷新"
            >
              <RefreshCw size={18} />
            </button>
          </div>

          {loading ? (
            <div className="text-center py-8 text-gray-400">
              <RefreshCw className="animate-spin mx-auto mb-2" />
              加载中...
            </div>
          ) : credentials.length === 0 ? (
            <div className="text-center py-12 text-gray-500">
              <Shield size={48} className="mx-auto mb-4 opacity-30" />
              <p>暂无凭证</p>
              <p className="text-sm mt-2">上传 JSON 文件或去 <Link to="/oauth" className="text-purple-400 hover:underline">OAuth 页面</Link> 获取</p>
            </div>
          ) : (
            <div className="space-y-3">
              {credentials.map(cred => (
                <div 
                  key={cred.id} 
                  className={`p-4 rounded-lg border transition-colors ${
                    cred.is_active 
                      ? 'bg-dark-800 border-dark-600' 
                      : 'bg-dark-900 border-dark-700 opacity-60'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      {/* 凭证名称 - 斜体灰色 */}
                      <div className="text-gray-400 italic mb-2 truncate">
                        {cred.email || cred.name}
                      </div>
                      
                      {/* 状态标签行 */}
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        {/* 启用状态 - 绿色实心 */}
                        {cred.is_active ? (
                          <span className="text-xs px-2.5 py-1 bg-green-600 text-white rounded font-medium">
                            已启用
                          </span>
                        ) : (
                          <span className="text-xs px-2.5 py-1 bg-red-600 text-white rounded font-medium">
                            已禁用
                          </span>
                        )}
                        
                        {/* Pro 标签 */}
                        {cred.account_type === "pro" && (
                          <span className="text-xs px-2.5 py-1 bg-yellow-500/20 text-yellow-400 rounded font-medium">
                            ⭐ Pro
                          </span>
                        )}
                        
                        {/* 模型等级 */}
                        {cred.model_tier === "3" ? (
                          <span className="text-xs px-2.5 py-1 bg-purple-500/20 text-purple-400 rounded font-medium">
                            3.0可用
                          </span>
                        ) : (
                          <span className="text-xs px-2.5 py-1 bg-gray-600/50 text-gray-400 rounded font-medium">
                            2.5
                          </span>
                        )}
                        
                        {/* 捐赠状态 - 紫色边框空心 */}
                        {cred.is_public && (
                          <span className="text-xs px-2.5 py-1 border border-purple-500 text-purple-400 rounded font-medium">
                            已捐赠
                          </span>
                        )}
                      </div>
                      
                      {/* 信息行 */}
                      <div className="text-xs text-gray-500">
                        最后成功: {cred.last_used_at ? new Date(cred.last_used_at).toLocaleString() : '从未使用'}
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-2 ml-4">
                      {/* 启用/禁用 */}
                      <button
                        onClick={() => toggleActive(cred.id, cred.is_active)}
                        className={`px-3 py-1.5 rounded text-xs font-medium ${
                          cred.is_active 
                            ? 'bg-amber-600 hover:bg-amber-500 text-white' 
                            : 'bg-green-600 hover:bg-green-500 text-white'
                        }`}
                      >
                        {cred.is_active ? '禁用' : '启用'}
                      </button>
                      
                      {/* 配额 */}
                      <button
                        onClick={() => fetchQuota(cred.id)}
                        disabled={loadingQuota}
                        className="px-3 py-1.5 rounded text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-50 flex items-center gap-1"
                        title="查看配额使用情况"
                      >
                        <BarChart2 size={12} />
                        配额
                      </button>
                      
                      {/* 检测 */}
                      <button
                        onClick={() => verifyCred(cred.id)}
                        disabled={verifying === cred.id}
                        className="px-3 py-1.5 rounded text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50 flex items-center gap-1"
                      >
                        {verifying === cred.id ? (
                          <RefreshCw size={12} className="animate-spin" />
                        ) : (
                          <CheckCircle size={12} />
                        )}
                        检测
                      </button>
                      
                      {/* 导出 */}
                      <button
                        onClick={() => exportCred(cred.id, cred.email)}
                        className="px-3 py-1.5 rounded text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-1"
                      >
                        <Download size={12} />
                        导出
                      </button>
                      
                      {/* 捐赠/取消捐赠 */}
                      <button
                        onClick={() => togglePublic(cred.id, cred.is_public)}
                        disabled={!cred.is_public && !cred.is_active}
                        title={!cred.is_public && !cred.is_active ? '请先检测凭证有效后再捐赠' : ''}
                        className={`px-3 py-1.5 rounded text-xs font-medium ${
                          cred.is_public 
                            ? 'bg-gray-600 hover:bg-gray-500 text-white' 
                            : !cred.is_active
                              ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                              : 'bg-purple-600 hover:bg-purple-500 text-white'
                        }`}
                      >
                        {cred.is_public ? '取消捐赠' : '捐赠'}
                      </button>
                      
                      {/* 删除 */}
                      <button
                        onClick={() => deleteCred(cred.id)}
                        className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded"
                        title="删除"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* 说明 */}
        <div className="mt-6 p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl text-sm">
          <div className="text-amber-400 font-medium mb-2">💡 大锅饭规则</div>
          <ul className="text-amber-300/70 space-y-1">
            <li>• 捐赠凭证后，您可以使用所有公共池中的凭证</li>
            <li>• 不捐赠则只能使用自己的私有凭证</li>
            <li>• 所有凭证数据均已加密存储，安全可靠</li>
          </ul>
        </div>
      </div>

      {/* 配额弹窗 */}
      {quotaModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-2xl w-full max-w-lg max-h-[80vh] overflow-hidden">
            {/* 弹窗头部 */}
            <div className="flex items-center justify-between p-4 border-b border-dark-600">
              <div>
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <BarChart2 className="text-indigo-400" />
                  模型配额信息
                </h3>
                <p className="text-sm text-gray-400 mt-1">{quotaModal.email || quotaModal.credential_name}</p>
              </div>
              <button 
                onClick={() => setQuotaModal(null)}
                className="p-2 hover:bg-dark-600 rounded-lg transition-colors"
              >
                <X size={20} />
              </button>
            </div>
            
            {/* 账号类型 */}
            <div className="px-4 pt-3">
              <span className={`text-xs px-2 py-1 rounded ${
                quotaModal.account_type === 'pro' 
                  ? 'bg-yellow-500/20 text-yellow-400' 
                  : 'bg-gray-600/50 text-gray-400'
              }`}>
                {quotaModal.account_type === 'pro' ? '⭐ Pro 账号' : '普通账号'}
              </span>
            </div>
            
            {/* Flash 配额 */}
            {quotaModal.flash && (
              <div className="p-4 border-b border-dark-600">
                <div className="flex items-center justify-between text-sm mb-2">
                  <span className="font-semibold text-cyan-400">2.5-flash 配额</span>
                  <span className={`font-bold ${
                    quotaModal.flash.percentage > 50 ? 'text-green-400' : 
                    quotaModal.flash.percentage > 20 ? 'text-yellow-400' : 'text-red-400'
                  }`}>
                    {quotaModal.flash.percentage}%
                  </span>
                </div>
                <div className="h-3 bg-dark-600 rounded-full overflow-hidden">
                  <div 
                    className={`h-full rounded-full transition-all ${
                      quotaModal.flash.percentage > 50 ? 'bg-cyan-500' : 
                      quotaModal.flash.percentage > 20 ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${quotaModal.flash.percentage}%` }}
                  />
                </div>
                <div className="flex items-center justify-between text-xs text-gray-500 mt-1">
                  <span>已用 {quotaModal.flash.used} / {quotaModal.flash.limit}</span>
                  <span>剩余 {quotaModal.flash.remaining}</span>
                </div>
              </div>
            )}
            
            {/* 高级模型配额 */}
            {quotaModal.premium && (
              <div className="p-4 border-b border-dark-600">
                <div className="flex items-center justify-between text-sm mb-2">
                  <span className="font-semibold text-purple-400">2.5-pro / 3.0 配额</span>
                  <span className={`font-bold ${
                    quotaModal.premium.percentage > 50 ? 'text-green-400' : 
                    quotaModal.premium.percentage > 20 ? 'text-yellow-400' : 'text-red-400'
                  }`}>
                    {quotaModal.premium.percentage}%
                  </span>
                </div>
                <div className="h-3 bg-dark-600 rounded-full overflow-hidden">
                  <div 
                    className={`h-full rounded-full transition-all ${
                      quotaModal.premium.percentage > 50 ? 'bg-purple-500' : 
                      quotaModal.premium.percentage > 20 ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${quotaModal.premium.percentage}%` }}
                  />
                </div>
                <div className="flex items-center justify-between text-xs text-gray-500 mt-1">
                  <span>已用 {quotaModal.premium.used} / {quotaModal.premium.limit}</span>
                  <span>剩余 {quotaModal.premium.remaining}</span>
                </div>
                <div className="text-xs text-purple-400/60 mt-1">{quotaModal.premium.note}</div>
              </div>
            )}
            
            {/* 各模型配额 */}
            <div className="p-4 overflow-y-auto max-h-[50vh] space-y-3">
              <div className="text-xs text-gray-500 mb-2">各模型使用情况（配额可能共享）</div>
              {quotaModal.models?.filter(m => m.used > 0).length === 0 ? (
                <div className="text-center text-gray-500 py-4">
                  今日暂无使用记录
                </div>
              ) : quotaModal.models?.filter(m => m.used > 0).map(item => (
                <div key={item.model} className="flex items-center justify-between py-2 border-b border-dark-700 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-sm">{item.model}</span>
                    {item.is_premium && (
                      <span className="text-xs px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded">
                        高级
                      </span>
                    )}
                  </div>
                  <span className="text-gray-400 text-sm font-medium">
                    {item.used} 次
                  </span>
                </div>
              ))}
            </div>
            
            {/* 提示 */}
            <div className="px-4 py-2 bg-amber-500/10 border-t border-amber-500/30">
              <div className="text-xs text-amber-400/80">
                ⚠️ 此为本平台调用统计，不包含其他平台（如 AI Studio、CLI）的使用量
              </div>
            </div>
            
            {/* 弹窗底部 */}
            <div className="p-4 border-t border-dark-600 flex items-center justify-between">
              <div className="text-xs text-gray-500">
                重置时间: {new Date(quotaModal.reset_time).toLocaleString()}
              </div>
              <button
                onClick={() => setQuotaModal(null)}
                className="px-4 py-2 bg-dark-600 hover:bg-dark-500 text-white rounded-lg text-sm"
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
