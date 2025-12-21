import {
    AlertTriangle,
    ArrowLeft,
    Cat,
    Check,
    ChevronDown,
    ChevronUp,
    Download,
    ExternalLink,
    Eye,
    Key,
    Plus,
    RefreshCw,
    ScrollText,
    Settings,
    Trash2,
    Users,
    X
} from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../api'
import { useAuth } from '../App'
import { AlertModal, ConfirmModal, InputModal, QuotaModal } from '../components/Modal'
import { useWebSocket } from '../hooks/useWebSocket'

export default function Admin() {
  const { user } = useAuth()
  const [tab, setTab] = useState('users')
  const [users, setUsers] = useState([])
  const [credentials, setCredentials] = useState([])
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [errorStats, setErrorStats] = useState({ by_code: {}, recent: [] })
  const [expandedErrors, setExpandedErrors] = useState({})  // 展开状态 { '429': true, '401': false }

  // 添加凭证表单
  const [newCredName, setNewCredName] = useState('')
  const [newCredKey, setNewCredKey] = useState('')
  const [verifyingAll, setVerifyingAll] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)
  const [startingAll, setStartingAll] = useState(false)
  const [startResult, setStartResult] = useState(null)
  
  // 凭证分页
  const [credPage, setCredPage] = useState(1)
  const credPerPage = 20

  // 模态框状态
  const [alertModal, setAlertModal] = useState({ open: false, title: '', message: '', type: 'info' })
  const [confirmModal, setConfirmModal] = useState({ open: false, title: '', message: '', onConfirm: null, danger: false })
  const [inputModal, setInputModal] = useState({ open: false, title: '', label: '', defaultValue: '', onSubmit: null })
  const [quotaModal, setQuotaModal] = useState({ open: false, userId: null, defaultValues: {} })
  const [credDetailModal, setCredDetailModal] = useState({ open: false, data: null, loading: false })
  const [duplicateModal, setDuplicateModal] = useState({ open: false, data: null, loading: false })
  const [logDetailModal, setLogDetailModal] = useState({ open: false, data: null, loading: false })

  const showAlert = (title, message, type = 'info') => setAlertModal({ open: true, title, message, type })
  const showConfirm = (title, message, onConfirm, danger = false) => setConfirmModal({ open: true, title, message, onConfirm, danger })
  const showInput = (title, label, defaultValue, onSubmit) => setInputModal({ open: true, title, label, defaultValue, onSubmit })
  
  // 查看日志详情
  const viewLogDetail = async (logId) => {
    setLogDetailModal({ open: true, data: null, loading: true })
    try {
      const res = await api.get(`/api/manage/logs/${logId}`)
      setLogDetailModal({ open: true, data: res.data, loading: false })
    } catch (err) {
      setLogDetailModal({ open: false, data: null, loading: false })
      showAlert('错误', '获取日志详情失败', 'error')
    }
  }

  // WebSocket 实时更新
  const handleWsMessage = useCallback((data) => {
    console.log('WS:', data.type)
    if (data.type === 'user_update') {
      // 实时更新用户列表
      api.get('/api/admin/users').then(res => setUsers(res.data.users)).catch(() => {})
    } else if (data.type === 'credential_update') {
      // 实时更新凭证列表
      api.get('/api/admin/credentials').then(res => setCredentials(res.data.credentials)).catch(() => {})
    } else if (data.type === 'log_update' && data.data) {
      // 实时插入新日志
      setLogs(prev => [data.data, ...prev].slice(0, 100))
    }
  }, [])

  const { connected } = useWebSocket(handleWsMessage)

  const fetchData = async () => {
    setLoading(true)
    try {
      if (tab === 'users') {
        const res = await api.get('/api/admin/users')
        setUsers(res.data.users)
      } else if (tab === 'credentials') {
        const res = await api.get('/api/admin/credentials')
        setCredentials(res.data.credentials)
      } else if (tab === 'logs') {
        const res = await api.get('/api/admin/logs?limit=100')
        setLogs(res.data.logs)
      } else if (tab === 'errors') {
        const res = await api.get('/api/manage/stats/global')
        setErrorStats(res.data.errors || { by_code: {}, recent: [] })
      }
    } catch (err) {
      console.error('获取数据失败', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [tab])

  // CD 实时倒计时
  useEffect(() => {
    if (tab !== 'credentials') return
    const hasCD = credentials.some(c => c.cd_flash > 0 || c.cd_pro > 0 || c.cd_30 > 0)
    if (!hasCD) return
    
    const timer = setInterval(() => {
      setCredentials(prev => prev.map(c => ({
        ...c,
        cd_flash: Math.max(0, (c.cd_flash || 0) - 1),
        cd_pro: Math.max(0, (c.cd_pro || 0) - 1),
        cd_30: Math.max(0, (c.cd_30 || 0) - 1)
      })))
    }, 1000)
    
    return () => clearInterval(timer)
  }, [tab, credentials.length])

  // 用户操作
  const toggleUserActive = async (userId, isActive) => {
    try {
      await api.put(`/api/admin/users/${userId}`, { is_active: !isActive })
      fetchData()
    } catch (err) {
      showAlert('操作失败', '用户状态更新失败', 'error')
    }
  }

  const updateUserQuota = (userId, user) => {
    setQuotaModal({
      open: true,
      userId,
      defaultValues: {
        daily_quota: user.daily_quota || 0,
        quota_flash: user.quota_flash || 0,
        quota_25pro: user.quota_25pro || 0,
        quota_30pro: user.quota_30pro || 0
      }
    })
  }

  const handleQuotaSubmit = async (values) => {
    try {
      await api.put(`/api/admin/users/${quotaModal.userId}`, values)
      fetchData()
      showAlert('成功', '配额已更新', 'success')
    } catch (err) {
      showAlert('操作失败', '配额更新失败', 'error')
    }
  }

  const deleteUser = (userId) => {
    showConfirm('删除用户', '确定删除此用户？此操作不可恢复！\n\n注意：将同时删除该用户的所有凭证！', async () => {
      try {
        await api.delete(`/api/admin/users/${userId}`)
        fetchData()
        showAlert('成功', '用户已删除（关联凭证已同时删除）', 'success')
      } catch (err) {
        showAlert('删除失败', err.response?.data?.detail || '删除用户失败', 'error')
      }
    }, true)
  }

  const resetUserPassword = (userId, username) => {
    showInput('重置密码', `为用户 ${username} 设置新密码`, '', async (newPassword) => {
      if (!newPassword || newPassword.length < 6) {
        showAlert('错误', '密码长度至少6位', 'error')
        return
      }
      try {
        await api.put(`/api/admin/users/${userId}/password`, { new_password: newPassword })
        showAlert('成功', `用户 ${username} 的密码已重置`, 'success')
      } catch (err) {
        showAlert('重置失败', err.response?.data?.detail || '密码重置失败', 'error')
      }
    })
  }

  // 凭证操作
  const addCredential = async () => {
    if (!newCredName.trim() || !newCredKey.trim()) return
    try {
      await api.post('/api/admin/credentials', { name: newCredName, api_key: newCredKey })
      setNewCredName('')
      setNewCredKey('')
      fetchData()
      showAlert('成功', '凭证添加成功', 'success')
    } catch (err) {
      showAlert('添加失败', '凭证添加失败', 'error')
    }
  }

  const toggleCredActive = async (credId, isActive) => {
    try {
      await api.put(`/api/admin/credentials/${credId}`, { is_active: !isActive })
      fetchData()
    } catch (err) {
      showAlert('操作失败', '凭证状态更新失败', 'error')
    }
  }

  const deleteCredential = (credId) => {
    showConfirm('删除凭证', '确定删除此凭证？此操作不可恢复！', async () => {
      try {
        await api.delete(`/api/admin/credentials/${credId}`)
        // 如果当前页只剩一个凭证且不是第一页，则回退一页
        const currentPageCreds = credentials.slice((credPage - 1) * credPerPage, credPage * credPerPage)
        if (currentPageCreds.length <= 1 && credPage > 1) {
          setCredPage(credPage - 1)
        }
        fetchData()
        showAlert('成功', '凭证已删除', 'success')
      } catch (err) {
        showAlert('删除失败', '凭证删除失败', 'error')
      }
    }, true)
  }

  const pollTaskStatus = async (taskId, type) => {
    // 轮询任务状态
    const poll = async () => {
      try {
        const res = await api.get(`/api/manage/credentials/task-status/${taskId}`)
        if (res.data.status === 'done') {
          fetchData()
          if (type === 'verify') {
            setVerifyingAll(false)
            setVerifyResult(res.data)
            showAlert('检测完成', `总计: ${res.data.total}\n有效: ${res.data.valid}\n无效: ${res.data.invalid}\n3.0可用: ${res.data.tier3}\nPro账号: ${res.data.pro}`, 'success')
          } else {
            setStartingAll(false)
            setStartResult(res.data)
            showAlert('启动完成', `总计: ${res.data.total}\n成功: ${res.data.success}\n失败: ${res.data.failed}`, 'success')
          }
        } else {
          // 继续轮询
          setTimeout(poll, 2000)
        }
      } catch (err) {
        console.error('轮询失败', err)
        setTimeout(poll, 3000)
      }
    }
    poll()
  }

  const verifyAllCredentials = () => {
    showConfirm('检测凭证', '确定要检测所有凭证？检测将在后台运行，完成后会弹窗通知结果。', async () => {
      setVerifyingAll(true)
      setVerifyResult(null)
      try {
        const res = await api.post('/api/manage/credentials/verify-all')
        showAlert('检测中', `后台任务已启动，正在检测 ${res.data.total} 个凭证...`, 'info')
        pollTaskStatus(res.data.task_id, 'verify')
      } catch (err) {
        setVerifyingAll(false)
        showAlert('检测失败', err.response?.data?.detail || err.message, 'error')
      }
    })
  }

  const startAllCredentials = () => {
    showConfirm('启动凭证', '确定要一键启动所有凭证？将刷新所有 OAuth 凭证的 access_token。', async () => {
      setStartingAll(true)
      setStartResult(null)
      try {
        const res = await api.post('/api/manage/credentials/start-all')
        showAlert('启动中', `后台任务已启动，正在刷新 ${res.data.total} 个凭证...`, 'info')
        pollTaskStatus(res.data.task_id, 'start')
      } catch (err) {
        setStartingAll(false)
        showAlert('启动失败', err.response?.data?.detail || err.message, 'error')
      }
    })
  }

  const exportAllCredentials = async () => {
    try {
      const res = await api.get('/api/admin/credentials/export')
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `all_credentials_${new Date().toISOString().slice(0, 10)}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      showAlert('导出成功', '凭证已导出为 JSON 文件', 'success')
    } catch (err) {
      showAlert('导出失败', err.response?.data?.detail || err.message, 'error')
    }
  }

  const deleteInactiveCredentials = async () => {
    if (!window.confirm('确定要删除所有无效凭证吗？此操作不可恢复！')) {
      return
    }
    try {
      const res = await api.delete('/api/manage/credentials/inactive')
      showAlert('清理完成', res.data.message, 'success')
      setCredPage(1)  // 重置分页到第一页
      fetchData()
    } catch (err) {
      showAlert('清理失败', err.response?.data?.detail || err.message, 'error')
    }
  }

  const viewCredentialDetail = async (credId) => {
    setCredDetailModal({ open: true, data: null, loading: true })
    try {
      const res = await api.get(`/api/admin/credentials/${credId}/detail`)
      setCredDetailModal({ open: true, data: res.data, loading: false })
    } catch (err) {
      setCredDetailModal({ open: false, data: null, loading: false })
      showAlert('获取失败', err.response?.data?.detail || err.message, 'error')
    }
  }

  const checkDuplicates = async () => {
    setDuplicateModal({ open: true, data: null, loading: true })
    try {
      const res = await api.get('/api/admin/credential-duplicates')
      setDuplicateModal({ open: true, data: res.data, loading: false })
    } catch (err) {
      setDuplicateModal({ open: false, data: null, loading: false })
      showAlert('检测失败', err.response?.data?.detail || err.message, 'error')
    }
  }

  const deleteDuplicates = async () => {
    if (!confirm(`确定要删除所有重复凭证吗？\n\n将优先保留每组有效凭证，如果都有效或都无效则保留最早上传的，删除其他 ${duplicateModal.data?.duplicate_count || 0} 个重复凭证。\n\n此操作不可撤销！`)) {
      return
    }
    setDuplicateModal(prev => ({ ...prev, loading: true }))
    try {
      const res = await api.delete('/api/admin/credential-duplicates')
      showAlert('清除成功', res.data.message, 'success')
      setDuplicateModal({ open: false, data: null, loading: false })
      fetchData()
    } catch (err) {
      setDuplicateModal(prev => ({ ...prev, loading: false }))
      showAlert('清除失败', err.response?.data?.detail || err.message, 'error')
    }
  }

  const tabs = [
    { id: 'users', label: '用户管理', icon: Users },
    { id: 'credentials', label: '凭证池', icon: Key },
    { id: 'logs', label: '使用日志', icon: ScrollText },
    { id: 'errors', label: '报错统计', icon: AlertTriangle },
    { id: 'settings', label: '配额设置', icon: Settings },
  ]

  // 用户管理：搜索、排序、翻页
  const [userSearch, setUserSearch] = useState('')
  const [userSort, setUserSort] = useState({ field: 'id', order: 'asc' })
  const [userPage, setUserPage] = useState(1)
  const usersPerPage = 20

  // 处理用户列表：搜索 -> 排序 -> 分页
  const processedUsers = (() => {
    let result = [...users]
    // 搜索
    if (userSearch.trim()) {
      const search = userSearch.toLowerCase()
      result = result.filter(u => 
        u.username?.toLowerCase().includes(search) ||
        u.discord_name?.toLowerCase().includes(search) ||
        u.discord_id?.includes(search) ||
        String(u.id).includes(search)
      )
    }
    // 排序
    result.sort((a, b) => {
      let aVal = a[userSort.field]
      let bVal = b[userSort.field]
      if (typeof aVal === 'string') aVal = aVal.toLowerCase()
      if (typeof bVal === 'string') bVal = bVal.toLowerCase()
      if (aVal < bVal) return userSort.order === 'asc' ? -1 : 1
      if (aVal > bVal) return userSort.order === 'asc' ? 1 : -1
      return 0
    })
    return result
  })()

  const totalUserPages = Math.ceil(processedUsers.length / usersPerPage)
  const paginatedUsers = processedUsers.slice((userPage - 1) * usersPerPage, userPage * usersPerPage)

  const handleUserSort = (field) => {
    setUserSort(prev => ({
      field,
      order: prev.field === field && prev.order === 'asc' ? 'desc' : 'asc'
    }))
  }

  // 使用日志：搜索、分页、筛选
  const [logSearch, setLogSearch] = useState('')
  const [logPage, setLogPage] = useState(1)
  const [logStatus, setLogStatus] = useState('all')  // all, success, error
  const [logStartDate, setLogStartDate] = useState('')
  const [logEndDate, setLogEndDate] = useState('')
  const [logTotal, setLogTotal] = useState(0)
  const [logPages, setLogPages] = useState(1)
  const logsPerPage = 50

  // 获取日志数据（带筛选）
  const fetchLogs = async () => {
    try {
      const params = new URLSearchParams()
      params.append('limit', logsPerPage)
      params.append('page', logPage)
      if (logStartDate) params.append('start_date', logStartDate)
      if (logEndDate) params.append('end_date', logEndDate)
      if (logSearch) params.append('username', logSearch)
      if (logStatus !== 'all') params.append('status', logStatus)
      
      const res = await api.get(`/api/admin/logs?${params.toString()}`)
      setLogs(res.data.logs)
      setLogTotal(res.data.total)
      setLogPages(res.data.pages)
    } catch (err) {
      console.error('获取日志失败', err)
    }
  }

  // 日志筛选变化时重新获取
  useEffect(() => {
    if (tab === 'logs') {
      fetchLogs()
    }
  }, [tab, logPage, logStatus, logStartDate, logEndDate])

  // 搜索防抖
  useEffect(() => {
    if (tab !== 'logs') return
    const timer = setTimeout(() => {
      setLogPage(1)
      fetchLogs()
    }, 300)
    return () => clearTimeout(timer)
  }, [logSearch])

  // 配额设置相关
  const [defaultQuota, setDefaultQuota] = useState(100)
  const [batchQuota, setBatchQuota] = useState('')

  const updateDefaultQuota = async () => {
    try {
      await api.post('/api/admin/settings/default-quota', { quota: defaultQuota })
      showAlert('成功', '默认配额已更新', 'success')
    } catch (err) {
      showAlert('更新失败', '配额更新失败', 'error')
    }
  }

  const applyQuotaToAll = () => {
    if (!batchQuota) return
    showConfirm('批量设置配额', `确定将所有用户配额设为 ${batchQuota} 次/天？`, async () => {
      try {
        await api.post('/api/admin/settings/batch-quota', { quota: parseInt(batchQuota) })
        showAlert('成功', '批量更新成功', 'success')
        fetchData()
      } catch (err) {
        showAlert('更新失败', '批量更新失败', 'error')
      }
    })
  }

  return (
    <div className="min-h-screen">
      {/* 导航栏 */}
      <nav className="bg-dark-900 border-b border-dark-700">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Cat className="w-8 h-8 text-purple-400" />
            <span className="text-xl font-bold">Catiecli</span>
            <span className="text-sm text-gray-500 bg-dark-700 px-2 py-0.5 rounded">管理后台</span>
            {connected && (
              <span className="flex items-center gap-1 text-xs text-green-400">
                <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
                实时
              </span>
            )}
          </div>
          <Link to="/dashboard" className="text-gray-400 hover:text-white flex items-center gap-2">
            <ArrowLeft size={20} />
            返回
          </Link>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 py-6">
        {/* Tab 导航 */}
        <div className="flex gap-2 mb-6 overflow-x-auto pb-2">
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors whitespace-nowrap ${
                tab === t.id
                  ? 'bg-purple-600 text-white'
                  : 'bg-dark-800 text-gray-400 hover:text-white hover:bg-dark-700'
              }`}
            >
              <t.icon size={18} />
              {t.label}
            </button>
          ))}
          <button
            onClick={fetchData}
            className="ml-auto p-2 text-gray-400 hover:text-white hover:bg-dark-700 rounded-lg"
          >
            <RefreshCw size={20} />
          </button>
        </div>

        {loading ? (
          <div className="text-center py-12 text-gray-400">加载中...</div>
        ) : (
          <>
            {/* 用户管理 */}
            {tab === 'users' && (
              <div className="space-y-4">
                {/* 搜索和统计 */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <input
                      type="text"
                      placeholder="搜索用户名、Discord..."
                      value={userSearch}
                      onChange={(e) => { setUserSearch(e.target.value); setUserPage(1) }}
                      className="px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white placeholder-gray-500 w-64"
                    />
                    <span className="text-gray-400 text-sm">
                      共 {processedUsers.length} 个用户
                      {userSearch && ` (筛选自 ${users.length} 个)`}
                    </span>
                  </div>
                </div>

                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th className="cursor-pointer hover:text-purple-400" onClick={() => handleUserSort('id')}>
                          ID {userSort.field === 'id' && (userSort.order === 'asc' ? '↑' : '↓')}
                        </th>
                        <th className="cursor-pointer hover:text-purple-400" onClick={() => handleUserSort('username')}>
                          用户名 {userSort.field === 'username' && (userSort.order === 'asc' ? '↑' : '↓')}
                        </th>
                        <th>Discord</th>
                        <th className="cursor-pointer hover:text-purple-400" onClick={() => handleUserSort('daily_quota')}>
                          配额 {userSort.field === 'daily_quota' && (userSort.order === 'asc' ? '↑' : '↓')}
                        </th>
                        <th className="cursor-pointer hover:text-purple-400" onClick={() => handleUserSort('today_usage')}>
                          今日使用 {userSort.field === 'today_usage' && (userSort.order === 'asc' ? '↑' : '↓')}
                        </th>
                        <th className="cursor-pointer hover:text-purple-400" onClick={() => handleUserSort('credential_count')}>
                          凭证数 {userSort.field === 'credential_count' && (userSort.order === 'asc' ? '↑' : '↓')}
                        </th>
                        <th>状态</th>
                        <th>操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedUsers.map(u => (
                      <tr key={u.id}>
                        <td className="text-gray-400">{u.id}</td>
                        <td>
                          {u.username}
                          {u.is_admin && (
                            <span className="ml-2 text-xs bg-purple-500/20 text-purple-400 px-1.5 py-0.5 rounded">
                              管理员
                            </span>
                          )}
                        </td>
                        <td className="text-gray-400 text-xs">
                          {u.discord_id ? (
                            <div>
                              <div className="text-blue-400">{u.discord_name || 'Unknown'}</div>
                              <div className="text-gray-500 font-mono">{u.discord_id}</div>
                            </div>
                          ) : '-'}
                        </td>
                        <td>
                          <button
                            onClick={() => updateUserQuota(u.id, u)}
                            className="text-purple-400 hover:underline"
                          >
                            {u.daily_quota}
                          </button>
                        </td>
                        <td>{u.today_usage}</td>
                        <td className={u.credential_count > 0 ? 'text-green-400' : 'text-gray-500'}>
                          {u.credential_count || 0}
                        </td>
                        <td>
                          {u.is_active ? (
                            <span className="text-green-400">活跃</span>
                          ) : (
                            <span className="text-red-400">禁用</span>
                          )}
                        </td>
                        <td>
                          <div className="flex gap-1">
                            <button
                              onClick={() => toggleUserActive(u.id, u.is_active)}
                              className={`p-1.5 rounded hover:bg-dark-700 ${
                                u.is_active ? 'text-red-400' : 'text-green-400'
                              }`}
                              title={u.is_active ? '禁用' : '启用'}
                            >
                              {u.is_active ? <X size={16} /> : <Check size={16} />}
                            </button>
                            <button
                              onClick={() => resetUserPassword(u.id, u.username)}
                              className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-blue-400"
                              title="重置密码"
                            >
                              <Key size={16} />
                            </button>
                            <button
                              onClick={() => deleteUser(u.id)}
                              className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-red-400"
                              title="删除"
                            >
                              <Trash2 size={16} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                </div>

                {/* 分页 */}
                {totalUserPages > 1 && (
                  <div className="flex items-center justify-center gap-2 mt-4">
                    <button
                      onClick={() => setUserPage(1)}
                      disabled={userPage === 1}
                      className="px-3 py-1 bg-dark-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      首页
                    </button>
                    <button
                      onClick={() => setUserPage(p => Math.max(1, p - 1))}
                      disabled={userPage === 1}
                      className="px-3 py-1 bg-dark-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      上一页
                    </button>
                    <span className="px-4 py-1 text-gray-400">
                      第 {userPage} / {totalUserPages} 页
                    </span>
                    <button
                      onClick={() => setUserPage(p => Math.min(totalUserPages, p + 1))}
                      disabled={userPage === totalUserPages}
                      className="px-3 py-1 bg-dark-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      下一页
                    </button>
                    <button
                      onClick={() => setUserPage(totalUserPages)}
                      disabled={userPage === totalUserPages}
                      className="px-3 py-1 bg-dark-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      末页
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* 凭证池 */}
            {tab === 'credentials' && (
              <div className="space-y-4">
                {/* OAuth 认证入口 + 一键检测 */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-gradient-to-r from-purple-600/20 to-blue-600/20 border border-purple-500/30 rounded-xl p-4">
                    <div className="font-medium text-purple-400 mb-1">🔐 OAuth 认证获取凭证</div>
                    <p className="text-sm text-gray-400 mb-3">通过 Google OAuth 自动获取 Gemini API 凭证</p>
                    <Link to="/oauth" className="btn btn-primary flex items-center gap-2 w-full justify-center">
                      <ExternalLink size={16} />
                      去认证
                    </Link>
                  </div>
                  
                  <div className="bg-cyan-600/20 border border-cyan-500/30 rounded-xl p-4">
                    <div className="font-medium text-cyan-400 mb-1">🔍 一键检测</div>
                    <p className="text-sm text-gray-400 mb-3">检测所有凭证有效性</p>
                    <button
                      onClick={verifyAllCredentials}
                      disabled={verifyingAll}
                      className="btn bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-2 disabled:opacity-50 w-full justify-center"
                    >
                      {verifyingAll ? <RefreshCw size={16} className="animate-spin" /> : <Check size={16} />}
                      {verifyingAll ? '检测中...' : '开始检测'}
                    </button>
                  </div>
                  
                  <div className="bg-orange-600/20 border border-orange-500/30 rounded-xl p-4">
                    <div className="font-medium text-orange-400 mb-1">🚀 一键启动</div>
                    <p className="text-sm text-gray-400 mb-3">刷新所有凭证的Token</p>
                    <button
                      onClick={startAllCredentials}
                      disabled={startingAll}
                      className="btn bg-orange-600 hover:bg-orange-500 text-white flex items-center gap-2 disabled:opacity-50 w-full justify-center"
                    >
                      {startingAll ? <RefreshCw size={16} className="animate-spin" /> : <RefreshCw size={16} />}
                      {startingAll ? '启动中...' : '一键启动'}
                    </button>
                  </div>
                  
                  <div className="bg-green-600/20 border border-green-500/30 rounded-xl p-4">
                    <div className="font-medium text-green-400 mb-1">📦 导出凭证</div>
                    <p className="text-sm text-gray-400 mb-3">导出所有凭证为JSON</p>
                    <button
                      onClick={exportAllCredentials}
                      className="btn bg-green-600 hover:bg-green-500 text-white flex items-center gap-2 w-full justify-center"
                    >
                      <Download size={16} />
                      导出全部
                    </button>
                  </div>
                  
                  <div className="bg-red-600/20 border border-red-500/30 rounded-xl p-4">
                    <div className="font-medium text-red-400 mb-1">🗑️ 清理无效</div>
                    <p className="text-sm text-gray-400 mb-3">删除所有无效凭证</p>
                    <button
                      onClick={deleteInactiveCredentials}
                      className="btn bg-red-600 hover:bg-red-500 text-white flex items-center gap-2 w-full justify-center"
                    >
                      <Trash2 size={16} />
                      一键清理
                    </button>
                  </div>
                  
                  <div className="bg-yellow-600/20 border border-yellow-500/30 rounded-xl p-4">
                    <div className="font-medium text-yellow-400 mb-1">🔍 重复检测</div>
                    <p className="text-sm text-gray-400 mb-3">检测重复的凭证</p>
                    <button
                      onClick={checkDuplicates}
                      className="btn bg-yellow-600 hover:bg-yellow-500 text-white flex items-center gap-2 w-full justify-center"
                    >
                      <Eye size={16} />
                      开始检测
                    </button>
                  </div>
                </div>
                
                {/* 检测结果 */}
                {verifyResult && (
                  <div className="bg-dark-800 border border-dark-600 rounded-xl p-4">
                    <div className="flex flex-wrap items-center gap-2 md:gap-4">
                      <span className="text-gray-400">检测完成:</span>
                      <span className="text-green-400">✅ 有效 {verifyResult.valid}</span>
                      <span className="text-red-400">❌ 无效 {verifyResult.invalid}</span>
                      <span className="text-purple-400">⭐ Tier3 {verifyResult.tier3}</span>
                      <span className="text-gray-500">总计 {verifyResult.total}</span>
                    </div>
                  </div>
                )}

                <div className="card">
                  <h3 className="font-medium mb-3">手动添加凭证</h3>
                  <div className="flex flex-col md:flex-row gap-3">
                    <input
                      type="text"
                      value={newCredName}
                      onChange={(e) => setNewCredName(e.target.value)}
                      placeholder="凭证名称"
                      className="px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white placeholder-gray-500"
                    />
                    <input
                      type="text"
                      value={newCredKey}
                      onChange={(e) => setNewCredKey(e.target.value)}
                      placeholder="Gemini API Key"
                      className="flex-1 px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white placeholder-gray-500"
                    />
                    <button onClick={addCredential} className="btn btn-primary flex items-center gap-2 justify-center">
                      <Plus size={18} />
                      添加
                    </button>
                  </div>
                </div>

                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>名称</th>
                        <th>等级</th>
                        <th>API Key</th>
                        <th>请求数</th>
                        <th>失败数</th>
                        <th>状态</th>
                        <th>最后错误</th>
                        <th>操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {credentials.slice((credPage - 1) * credPerPage, credPage * credPerPage).map(c => (
                        <tr key={c.id}>
                          <td className="text-gray-400">{c.id}</td>
                          <td>{c.name}</td>
                          <td className="space-x-1">
                            {/* Pro 标签 */}
                            {c.last_error?.includes('account_type:pro') && (
                              <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 rounded text-xs">⭐ Pro</span>
                            )}
                            {/* 模型等级 */}
                            {c.model_tier === '3' ? (
                              <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs">3.0</span>
                            ) : (
                              <span className="px-2 py-0.5 bg-gray-600/50 text-gray-400 rounded text-xs">2.5</span>
                            )}
                          </td>
                          <td className="font-mono text-sm text-gray-400">{c.api_key}</td>
                          <td>{c.total_requests}</td>
                          <td className={c.failed_requests > 0 ? 'text-red-400' : ''}>
                            {c.failed_requests}
                          </td>
                          <td>
                            <div className="flex flex-col gap-1">
                              {c.is_active ? (
                                <span className="text-green-400">活跃</span>
                              ) : (
                                <span className="text-red-400">禁用</span>
                              )}
                              {/* CD 状态 */}
                              {(c.cd_flash > 0 || c.cd_pro > 0 || c.cd_30 > 0) && (
                                <div className="flex gap-1 flex-wrap">
                                  {c.cd_flash > 0 && <span className="text-xs px-1 bg-cyan-500/20 text-cyan-400 rounded">F:{c.cd_flash}s</span>}
                                  {c.cd_pro > 0 && <span className="text-xs px-1 bg-orange-500/20 text-orange-400 rounded">P:{c.cd_pro}s</span>}
                                  {c.cd_30 > 0 && <span className="text-xs px-1 bg-pink-500/20 text-pink-400 rounded">3:{c.cd_30}s</span>}
                                </div>
                              )}
                            </div>
                          </td>
                          <td className="text-xs text-gray-500 max-w-xs truncate">
                            {c.last_error || '-'}
                          </td>
                          <td>
                            <div className="flex gap-1">
                              <button
                                onClick={() => viewCredentialDetail(c.id)}
                                className="p-1.5 rounded hover:bg-dark-700 text-blue-400 hover:text-blue-300"
                                title="查看详情"
                              >
                                <Eye size={16} />
                              </button>
                              <button
                                onClick={() => toggleCredActive(c.id, c.is_active)}
                                className={`p-1.5 rounded hover:bg-dark-700 ${
                                  c.is_active ? 'text-red-400' : 'text-green-400'
                                }`}
                              >
                                {c.is_active ? <X size={16} /> : <Check size={16} />}
                              </button>
                              <button
                                onClick={() => deleteCredential(c.id)}
                                className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-red-400"
                              >
                                <Trash2 size={16} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                
                {/* 分页控件 */}
                {credentials.length > credPerPage && (
                  <div className="flex items-center justify-between mt-4">
                    <div className="text-sm text-gray-400">
                      共 {credentials.length} 个凭证，第 {credPage}/{Math.ceil(credentials.length / credPerPage)} 页
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setCredPage(p => Math.max(1, p - 1))}
                        disabled={credPage === 1}
                        className="px-3 py-1.5 bg-dark-700 hover:bg-dark-600 disabled:opacity-50 rounded text-sm"
                      >
                        上一页
                      </button>
                      <button
                        onClick={() => setCredPage(p => Math.min(Math.ceil(credentials.length / credPerPage), p + 1))}
                        disabled={credPage >= Math.ceil(credentials.length / credPerPage)}
                        className="px-3 py-1.5 bg-dark-700 hover:bg-dark-600 disabled:opacity-50 rounded text-sm"
                      >
                        下一页
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* 使用日志 */}
            {tab === 'logs' && (
              <div className="space-y-4">
                {/* 筛选器 */}
                <div className="flex flex-wrap items-center gap-3">
                  <input
                    type="text"
                    placeholder="搜索用户名..."
                    value={logSearch}
                    onChange={(e) => setLogSearch(e.target.value)}
                    className="px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white placeholder-gray-500 w-40"
                  />
                  <input
                    type="date"
                    value={logStartDate}
                    onChange={(e) => { setLogStartDate(e.target.value); setLogPage(1) }}
                    className="px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white"
                  />
                  <span className="text-gray-500">至</span>
                  <input
                    type="date"
                    value={logEndDate}
                    onChange={(e) => { setLogEndDate(e.target.value); setLogPage(1) }}
                    className="px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white"
                  />
                  <select
                    value={logStatus}
                    onChange={(e) => { setLogStatus(e.target.value); setLogPage(1) }}
                    className="px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white"
                  >
                    <option value="all">全部状态</option>
                    <option value="success">成功</option>
                    <option value="error">报错</option>
                  </select>
                  <button
                    onClick={() => { setLogStartDate(''); setLogEndDate(''); setLogSearch(''); setLogStatus('all'); setLogPage(1) }}
                    className="px-3 py-2 bg-dark-700 hover:bg-dark-600 rounded-lg text-gray-400"
                  >
                    重置
                  </button>
                  <span className="text-gray-400 text-sm ml-auto">
                    共 {logTotal} 条记录
                  </span>
                </div>

                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>时间</th>
                        <th>用户</th>
                        <th>模型</th>
                        <th>端点</th>
                        <th>状态</th>
                        <th>延迟</th>
                      </tr>
                    </thead>
                    <tbody>
                      {logs.map(log => (
                        <tr key={log.id}>
                          <td className="text-gray-400 text-sm whitespace-nowrap">
                            {new Date(log.created_at).toLocaleString()}
                          </td>
                          <td>{log.username}</td>
                          <td className="font-mono text-sm">{log.model}</td>
                          <td className="text-gray-400 text-sm">{log.endpoint || '-'}</td>
                          <td>
                            <span className={log.status_code === 200 ? 'text-green-400' : 'text-red-400'}>
                              {log.status_code}
                            </span>
                            {log.cd_seconds && (
                              <span className="ml-1 text-xs px-1 bg-orange-500/20 text-orange-400 rounded">
                                CD:{log.cd_seconds}s
                              </span>
                            )}
                          </td>
                          <td className="text-gray-400">{log.latency_ms?.toFixed(0)}ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* 分页 */}
                {logPages > 1 && (
                  <div className="flex items-center justify-center gap-2 mt-4">
                    <button
                      onClick={() => setLogPage(1)}
                      disabled={logPage === 1}
                      className="px-3 py-1 bg-dark-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      首页
                    </button>
                    <button
                      onClick={() => setLogPage(p => Math.max(1, p - 1))}
                      disabled={logPage === 1}
                      className="px-3 py-1 bg-dark-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      上一页
                    </button>
                    <span className="px-4 py-1 text-gray-400">
                      第 {logPage} / {logPages} 页
                    </span>
                    <button
                      onClick={() => setLogPage(p => Math.min(logPages, p + 1))}
                      disabled={logPage === logPages}
                      className="px-3 py-1 bg-dark-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      下一页
                    </button>
                    <button
                      onClick={() => setLogPage(logPages)}
                      disabled={logPage === logPages}
                      className="px-3 py-1 bg-dark-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      末页
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* 报错统计 */}
            {tab === 'errors' && (
              <div className="space-y-6">
                {/* 今日报错统计 */}
                <div className="card">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-orange-400" />
                      今日报错统计
                    </h3>
                    <button
                      onClick={fetchData}
                      className="text-gray-400 hover:text-white"
                    >
                      <RefreshCw size={18} />
                    </button>
                  </div>
                  
                  {Object.keys(errorStats.by_code || {}).length === 0 ? (
                    <div className="text-center py-8 text-gray-500">
                      <Check className="w-12 h-12 mx-auto mb-3 text-green-500/50" />
                      <p>今日暂无报错</p>
                    </div>
                  ) : (
                    <>
                      <div className="space-y-3">
                        {Object.entries(errorStats.by_code).map(([code, count]) => (
                          <div key={code}>
                            <button
                              onClick={() => setExpandedErrors(prev => ({ ...prev, [code]: !prev[code] }))}
                              className={`w-full px-4 py-3 rounded-lg flex items-center justify-between cursor-pointer transition-colors ${
                                code === '429' ? 'bg-orange-500/20 border border-orange-500/50 hover:bg-orange-500/30' :
                                code === '401' || code === '403' ? 'bg-red-500/20 border border-red-500/50 hover:bg-red-500/30' :
                                code === '500' ? 'bg-purple-500/20 border border-purple-500/50 hover:bg-purple-500/30' :
                                'bg-gray-500/20 border border-gray-500/50 hover:bg-gray-500/30'
                              }`}
                            >
                              <div className="flex items-center gap-3">
                                <div className={`text-2xl font-bold ${
                                  code === '429' ? 'text-orange-400' :
                                  code === '401' || code === '403' ? 'text-red-400' :
                                  code === '500' ? 'text-purple-400' :
                                  'text-gray-400'
                                }`}>{count}</div>
                                <div className="text-sm text-gray-400">
                                  {code === '429' ? '限速 (429)' :
                                   code === '401' ? '未认证 (401)' :
                                   code === '403' ? '禁止访问 (403)' :
                                   code === '500' ? '服务器错误 (500)' :
                                   `错误 (${code})`}
                                </div>
                              </div>
                              {expandedErrors[code] ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                            </button>
                            
                            {expandedErrors[code] && (
                              <div className="mt-2 ml-4 border-l-2 border-dark-600 pl-4 space-y-2">
                                {errorStats.recent
                                  .filter(err => String(err.status_code) === code)
                                  .slice(0, 10)
                                  .map(err => (
                                    <div key={err.id} className="text-sm flex items-center justify-between py-1">
                                      <span className="text-gray-400">
                                        <span className="text-white">{err.username}</span>
                                        <span className="mx-2">·</span>
                                        <span className="font-mono">{err.model}</span>
                                        {err.cd_seconds && <span className="ml-2 text-orange-400">CD:{err.cd_seconds}s</span>}
                                      </span>
                                      <span className="text-gray-500 text-xs">
                                        {new Date(err.created_at).toLocaleTimeString()}
                                      </span>
                                    </div>
                                  ))}
                                {errorStats.recent.filter(err => String(err.status_code) === code).length === 0 && (
                                  <div className="text-gray-500 text-sm py-2">暂无详细记录</div>
                                )}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                      
                      <div className="text-sm text-gray-500 mt-4">
                        总计：{Object.values(errorStats.by_code).reduce((a, b) => a + b, 0)} 次报错（点击展开详情）
                      </div>
                    </>
                  )}
                </div>
                
                {/* 最近报错详情 */}
                <div className="card">
                  <h3 className="font-semibold mb-4">最近报错详情</h3>
                  {(errorStats.recent || []).length === 0 ? (
                    <div className="text-center py-6 text-gray-500">暂无报错记录</div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="table w-full">
                        <thead>
                          <tr>
                            <th>时间</th>
                            <th>用户</th>
                            <th>模型</th>
                            <th>状态码</th>
                            <th>CD</th>
                            <th>操作</th>
                          </tr>
                        </thead>
                        <tbody>
                          {errorStats.recent.map(err => (
                            <tr key={err.id}>
                              <td className="text-gray-400 text-sm whitespace-nowrap">
                                {new Date(err.created_at).toLocaleString()}
                              </td>
                              <td>{err.username}</td>
                              <td className="font-mono text-sm">{err.model}</td>
                              <td>
                                <span className={
                                  err.status_code === 429 ? 'text-orange-400' :
                                  err.status_code === 401 || err.status_code === 403 ? 'text-red-400' :
                                  'text-gray-400'
                                }>
                                  {err.status_code}
                                </span>
                              </td>
                              <td>
                                {err.cd_seconds ? (
                                  <span className="text-orange-400">{err.cd_seconds}s</span>
                                ) : '-'}
                              </td>
                              <td>
                                <button
                                  onClick={() => viewLogDetail(err.id)}
                                  className="text-purple-400 hover:text-purple-300 text-sm"
                                >
                                  详情
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* 配额设置 */}
            {tab === 'settings' && (
              <div className="space-y-6">
                {/* 批量设置配额 */}
                <div className="card">
                  <h3 className="font-semibold mb-4">批量设置所有用户配额</h3>
                  <p className="text-gray-400 text-sm mb-4">
                    将所有现有用户的配额统一设置为指定值
                  </p>
                  <div className="flex gap-3">
                    <input
                      type="number"
                      value={batchQuota}
                      onChange={(e) => setBatchQuota(e.target.value)}
                      placeholder="输入配额值"
                      className="w-32 px-4 py-2 bg-dark-800 border border-dark-600 rounded-lg text-white placeholder-gray-500"
                    />
                    <button 
                      onClick={applyQuotaToAll} 
                      disabled={!batchQuota}
                      className="btn bg-amber-600 hover:bg-amber-700 text-white"
                    >
                      应用到所有用户
                    </button>
                  </div>
                </div>

                {/* 单独设置用户配额 */}
                <div className="card">
                  <h3 className="font-semibold mb-4">单独设置用户配额</h3>
                  <p className="text-gray-400 text-sm mb-4">
                    在「用户管理」页面点击用户的配额数值即可单独修改
                  </p>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* 模态框 */}
      <AlertModal
        isOpen={alertModal.open}
        onClose={() => setAlertModal({ ...alertModal, open: false })}
        title={alertModal.title}
        message={alertModal.message}
        type={alertModal.type}
      />
      <ConfirmModal
        isOpen={confirmModal.open}
        onClose={() => setConfirmModal({ ...confirmModal, open: false })}
        onConfirm={confirmModal.onConfirm}
        title={confirmModal.title}
        message={confirmModal.message}
        danger={confirmModal.danger}
      />
      <InputModal
        isOpen={inputModal.open}
        onClose={() => setInputModal({ ...inputModal, open: false })}
        onSubmit={inputModal.onSubmit}
        title={inputModal.title}
        label={inputModal.label}
        defaultValue={inputModal.defaultValue}
        type="text"
      />
      <QuotaModal
        isOpen={quotaModal.open}
        onClose={() => setQuotaModal({ ...quotaModal, open: false })}
        onSubmit={handleQuotaSubmit}
        title="设置用户配额"
        defaultValues={quotaModal.defaultValues}
      />

      {/* 凭证详情模态框 */}
      {credDetailModal.open && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-xl border border-dark-600 w-full max-w-2xl max-h-[80vh] overflow-auto">
            <div className="flex items-center justify-between p-4 border-b border-dark-600">
              <h3 className="text-lg font-medium">凭证详情</h3>
              <button
                onClick={() => setCredDetailModal({ open: false, data: null, loading: false })}
                className="p-1.5 rounded hover:bg-dark-700 text-gray-400"
              >
                <X size={20} />
              </button>
            </div>
            <div className="p-4">
              {credDetailModal.loading ? (
                <div className="text-center py-8 text-gray-400">加载中...</div>
              ) : credDetailModal.data ? (
                <div className="space-y-3 text-sm">
                  <div className="grid grid-cols-2 gap-3">
                    <div><span className="text-gray-500">ID:</span> {credDetailModal.data.id}</div>
                    <div><span className="text-gray-500">上传者:</span> {credDetailModal.data.username || '系统'}</div>
                    <div><span className="text-gray-500">邮箱:</span> {credDetailModal.data.email || '-'}</div>
                    <div><span className="text-gray-500">类型:</span> {credDetailModal.data.credential_type}</div>
                    <div><span className="text-gray-500">等级:</span> {credDetailModal.data.model_tier}</div>
                    <div><span className="text-gray-500">账号:</span> {credDetailModal.data.account_type}</div>
                    <div><span className="text-gray-500">状态:</span> {credDetailModal.data.is_active ? '活跃' : '禁用'}</div>
                    <div><span className="text-gray-500">公共:</span> {credDetailModal.data.is_public ? '是' : '否'}</div>
                    <div><span className="text-gray-500">请求:</span> {credDetailModal.data.total_requests}</div>
                    <div><span className="text-gray-500">失败:</span> {credDetailModal.data.failed_requests}</div>
                  </div>
                  <div>
                    <span className="text-gray-500">Project ID:</span>
                    <div className="mt-1 p-2 bg-dark-900 rounded font-mono text-xs break-all">{credDetailModal.data.project_id || '-'}</div>
                  </div>
                  <div>
                    <span className="text-gray-500">Refresh Token:</span>
                    <div className="mt-1 p-2 bg-dark-900 rounded font-mono text-xs break-all max-h-24 overflow-auto">{credDetailModal.data.refresh_token || '-'}</div>
                  </div>
                  <div>
                    <span className="text-gray-500">Access Token:</span>
                    <div className="mt-1 p-2 bg-dark-900 rounded font-mono text-xs break-all max-h-24 overflow-auto">{credDetailModal.data.access_token || '-'}</div>
                  </div>
                  {credDetailModal.data.client_id && (
                    <div>
                      <span className="text-gray-500">Client ID:</span>
                      <div className="mt-1 p-2 bg-dark-900 rounded font-mono text-xs break-all">{credDetailModal.data.client_id}</div>
                    </div>
                  )}
                  <div>
                    <span className="text-gray-500">最后错误:</span>
                    <div className="mt-1 p-2 bg-red-900/20 border border-red-500/30 rounded text-xs text-red-300 break-all max-h-32 overflow-auto">{credDetailModal.data.last_error || '无'}</div>
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* 重复检测模态框 */}
      {duplicateModal.open && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-xl border border-dark-600 w-full max-w-4xl max-h-[85vh] overflow-auto">
            <div className="flex items-center justify-between p-4 border-b border-dark-600 sticky top-0 bg-dark-800">
              <h3 className="text-lg font-medium">🔍 重复凭证检测</h3>
              <button
                onClick={() => setDuplicateModal({ open: false, data: null, loading: false })}
                className="p-1.5 rounded hover:bg-dark-700 text-gray-400"
              >
                <X size={20} />
              </button>
            </div>
            <div className="p-4">
              {duplicateModal.loading ? (
                <div className="text-center py-8 text-gray-400">检测中...</div>
              ) : duplicateModal.data ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 text-sm">
                      <span className="text-gray-400">总凭证数: <span className="text-white">{duplicateModal.data.total_credentials}</span></span>
                      <span className="text-yellow-400">重复凭证数: <span className="font-bold">{duplicateModal.data.duplicate_count}</span></span>
                    </div>
                    {duplicateModal.data.duplicate_count > 0 && (
                      <button
                        onClick={deleteDuplicates}
                        className="btn bg-red-600 hover:bg-red-500 text-white text-sm px-4 py-2"
                      >
                        🗑️ 一键清除重复 ({duplicateModal.data.duplicate_count})
                      </button>
                    )}
                  </div>
                  
                  {duplicateModal.data.duplicates.length === 0 ? (
                    <div className="text-center py-8 text-green-400">✅ 没有发现重复凭证</div>
                  ) : (
                    <div className="space-y-4">
                      {duplicateModal.data.duplicates.map((dup, idx) => (
                        <div key={idx} className="bg-dark-900 rounded-lg p-4 border border-yellow-500/30">
                          <div className="flex items-center gap-2 mb-3">
                            <span className={`px-2 py-0.5 rounded text-xs ${dup.type === 'email' ? 'bg-blue-500/20 text-blue-400' : 'bg-purple-500/20 text-purple-400'}`}>
                              {dup.type === 'email' ? '📧 邮箱重复' : '🔑 Token重复'}
                            </span>
                            <span className="text-gray-400 text-sm font-mono">{dup.key}</span>
                          </div>
                          <div className="overflow-x-auto">
                            <table className="w-full text-sm">
                              <thead>
                                <tr className="text-gray-500 text-left">
                                  <th className="pb-2 pr-4">ID</th>
                                  <th className="pb-2 pr-4">上传者</th>
                                  <th className="pb-2 pr-4">等级</th>
                                  <th className="pb-2 pr-4">状态</th>
                                  <th className="pb-2 pr-4">公共</th>
                                  <th className="pb-2 pr-4">请求数</th>
                                  <th className="pb-2">上传时间</th>
                                </tr>
                              </thead>
                              <tbody>
                                {dup.credentials.map((cred, cidx) => (
                                  <tr key={cidx} className={cidx === 0 ? 'text-green-400' : 'text-gray-300'}>
                                    <td className="py-1 pr-4">{cred.id}</td>
                                    <td className="py-1 pr-4">{cred.username}</td>
                                    <td className="py-1 pr-4">{cred.model_tier}</td>
                                    <td className="py-1 pr-4">{cred.is_active ? '✅' : '❌'}</td>
                                    <td className="py-1 pr-4">{cred.is_public ? '是' : '否'}</td>
                                    <td className="py-1 pr-4">{cred.total_requests}</td>
                                    <td className="py-1 text-xs text-gray-500">{cred.created_at?.slice(0, 10)}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          <div className="mt-2 text-xs text-gray-500">
                            💡 绿色行是最早上传的（建议保留），其他是后续重复上传的
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* 日志详情弹窗 */}
      {logDetailModal.open && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-xl w-full max-w-3xl max-h-[90vh] overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-dark-600">
              <h3 className="text-lg font-semibold">请求详情</h3>
              <button onClick={() => setLogDetailModal({ open: false, data: null, loading: false })} className="text-gray-400 hover:text-white">
                <X size={20} />
              </button>
            </div>
            <div className="p-4 overflow-y-auto max-h-[calc(90vh-60px)]">
              {logDetailModal.loading ? (
                <div className="text-center py-8 text-gray-400">加载中...</div>
              ) : logDetailModal.data ? (
                <div className="space-y-4">
                  {/* 基本信息 */}
                  <div className="bg-dark-900 rounded-lg p-4">
                    <h4 className="text-sm font-medium text-gray-400 mb-3">基本信息</h4>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <span className="text-gray-500">时间</span>
                        <p className="text-white">{logDetailModal.data.created_at ? new Date(logDetailModal.data.created_at).toLocaleString() : '-'}</p>
                      </div>
                      <div>
                        <span className="text-gray-500">状态</span>
                        <p className={logDetailModal.data.status_code === 200 ? 'text-green-400' : logDetailModal.data.status_code === 429 ? 'text-orange-400' : 'text-red-400'}>
                          {logDetailModal.data.status_code === 200 ? '成功' : '错误'} - {logDetailModal.data.status_code}
                        </p>
                      </div>
                      <div>
                        <span className="text-gray-500">耗时(ms)</span>
                        <p className="text-white">{logDetailModal.data.latency_ms?.toFixed(0) || '-'}</p>
                      </div>
                      <div>
                        <span className="text-gray-500">用户</span>
                        <p className="text-white">{logDetailModal.data.username}</p>
                      </div>
                      <div>
                        <span className="text-gray-500">模型</span>
                        <p className="text-white font-mono text-xs">{logDetailModal.data.model}</p>
                      </div>
                      <div>
                        <span className="text-gray-500">凭证</span>
                        <p className="text-white font-mono text-xs">{logDetailModal.data.credential_email || '-'}</p>
                      </div>
                      <div>
                        <span className="text-gray-500">源IP</span>
                        <p className="text-white font-mono text-xs">{logDetailModal.data.client_ip || '-'}</p>
                      </div>
                      {logDetailModal.data.cd_seconds && (
                        <div>
                          <span className="text-gray-500">CD时间</span>
                          <p className="text-orange-400">{logDetailModal.data.cd_seconds}s</p>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* 请求信息 */}
                  {logDetailModal.data.endpoint && (
                    <div className="bg-dark-900 rounded-lg p-4">
                      <h4 className="text-sm font-medium text-gray-400 mb-3">请求信息</h4>
                      <div className="space-y-3">
                        <div>
                          <span className="text-gray-500 text-sm">请求路径</span>
                          <p className="text-white font-mono text-xs bg-dark-700 p-2 rounded mt-1">{logDetailModal.data.endpoint}</p>
                        </div>
                        {logDetailModal.data.user_agent && (
                          <div>
                            <span className="text-gray-500 text-sm">User Agent</span>
                            <p className="text-white font-mono text-xs bg-dark-700 p-2 rounded mt-1 break-all">{logDetailModal.data.user_agent}</p>
                          </div>
                        )}
                        {logDetailModal.data.request_body && (
                          <div>
                            <span className="text-gray-500 text-sm">请求内容</span>
                            <pre className="text-white font-mono text-xs bg-dark-700 p-2 rounded mt-1 overflow-x-auto max-h-40">{
                              (() => {
                                try {
                                  return JSON.stringify(JSON.parse(logDetailModal.data.request_body), null, 2)
                                } catch {
                                  return logDetailModal.data.request_body
                                }
                              })()
                            }</pre>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* 错误信息 */}
                  {logDetailModal.data.error_message && (
                    <div className="bg-dark-900 rounded-lg p-4">
                      <h4 className="text-sm font-medium text-red-400 mb-3">错误信息</h4>
                      <pre className="text-red-300 font-mono text-xs bg-red-900/20 border border-red-500/30 p-3 rounded overflow-x-auto max-h-60 whitespace-pre-wrap">{logDetailModal.data.error_message}</pre>
                    </div>
                  )}
                </div>
              ) : null}
            </div>
            <div className="p-4 border-t border-dark-600 flex justify-end">
              <button onClick={() => setLogDetailModal({ open: false, data: null, loading: false })} className="btn bg-dark-600 hover:bg-dark-500 text-white">
                关闭
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
