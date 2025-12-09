import { ArrowLeft, Save, Settings as SettingsIcon } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api'

export default function Settings() {
  const navigate = useNavigate()
  const [config, setConfig] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState(null)

  useEffect(() => {
    fetchConfig()
  }, [])

  const fetchConfig = async () => {
    try {
      const res = await api.get('/api/manage/config')
      setConfig(res.data)
    } catch (err) {
      if (err.response?.status === 401 || err.response?.status === 403) {
        navigate('/login')
      }
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    setMessage(null)
    try {
      const formData = new FormData()
      formData.append('allow_registration', config.allow_registration)
      formData.append('discord_only_registration', config.discord_only_registration)
      formData.append('default_daily_quota', config.default_daily_quota)
      formData.append('credential_reward_quota', config.credential_reward_quota)
      formData.append('base_rpm', config.base_rpm)
      formData.append('contributor_rpm', config.contributor_rpm)
      formData.append('error_retry_count', config.error_retry_count)
      formData.append('credential_pool_mode', config.credential_pool_mode)
      formData.append('announcement_enabled', config.announcement_enabled)
      formData.append('announcement_title', config.announcement_title || '')
      formData.append('announcement_content', config.announcement_content || '')
      formData.append('announcement_read_seconds', config.announcement_read_seconds || 5)
      
      await api.post('/api/manage/config', formData)
      setMessage({ type: 'success', text: '配置已保存！' })
    } catch (err) {
      setMessage({ type: 'error', text: '保存失败: ' + (err.response?.data?.detail || err.message) })
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white">加载中...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <div className="max-w-2xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <SettingsIcon className="text-purple-400" />
            系统设置
          </h1>
          <button
            onClick={() => navigate('/dashboard')}
            className="px-4 py-2 bg-gray-700 rounded-lg hover:bg-gray-600 flex items-center gap-2"
          >
            <ArrowLeft size={18} />
            返回
          </button>
        </div>

        {message && (
          <div className={`mb-6 p-4 rounded-lg ${message.type === 'success' ? 'bg-green-600/20 text-green-400' : 'bg-red-600/20 text-red-400'}`}>
            {message.text}
          </div>
        )}

        <div className="bg-gray-800 rounded-xl p-6 space-y-6">
          {/* 用户注册 */}
          <div className="flex justify-between items-center">
            <div>
              <h3 className="font-semibold">允许用户注册</h3>
              <p className="text-gray-400 text-sm">关闭后新用户无法注册账号</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={config?.allow_registration || false}
                onChange={(e) => setConfig({ ...config, allow_registration: e.target.checked })}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
            </label>
          </div>

          {/* 仅 Discord Bot 注册 */}
          <div className="flex justify-between items-center">
            <div>
              <h3 className="font-semibold">仅允许 Discord Bot 注册</h3>
              <p className="text-gray-400 text-sm">开启后只能通过 Discord Bot 注册，网页注册将被禁用</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={config?.discord_only_registration || false}
                onChange={(e) => setConfig({ ...config, discord_only_registration: e.target.checked })}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>

          {/* 仅 Discord OAuth 注册 */}
          <div className="flex justify-between items-center">
            <div>
              <h3 className="font-semibold">仅允许 Discord 登录注册</h3>
              <p className="text-gray-400 text-sm">开启后只能通过网页 Discord 登录注册，普通注册将被禁用</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={config?.discord_oauth_only || false}
                onChange={(e) => setConfig({ ...config, discord_oauth_only: e.target.checked })}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
            </label>
          </div>

          {/* 默认配额 */}
          <div>
            <h3 className="font-semibold mb-2">新用户默认配额</h3>
            <p className="text-gray-400 text-sm mb-3">新注册用户的每日请求限制</p>
            <input
              type="number"
              value={config?.default_daily_quota ?? ''}
              onChange={(e) => setConfig({ ...config, default_daily_quota: e.target.value === '' ? '' : parseInt(e.target.value) })}
              className="w-full bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500"
            />
          </div>

          {/* 凭证奖励 */}
          <div>
            <h3 className="font-semibold mb-2">凭证贡献奖励额度 🎁</h3>
            <p className="text-gray-400 text-sm mb-3">用户每捐赠一个凭证到公共池时增加的配额</p>
            <input
              type="number"
              value={config?.credential_reward_quota ?? ''}
              onChange={(e) => setConfig({ ...config, credential_reward_quota: e.target.value === '' ? '' : parseInt(e.target.value) })}
              className="w-full bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500"
            />
            <p className="text-green-400 text-sm mt-2">
              💡 当前设置：用户贡献凭证后额度 +{config?.credential_reward_quota ?? 1000}
            </p>
          </div>

          {/* 凭证池模式 */}
          <div>
            <h3 className="font-semibold mb-2">凭证池模式 🏊</h3>
            <p className="text-gray-400 text-sm mb-3">控制用户如何共享凭证</p>
            <select
              value={config?.credential_pool_mode || 'full_shared'}
              onChange={(e) => setConfig({ ...config, credential_pool_mode: e.target.value })}
              className="w-full bg-gray-700 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-purple-500"
            >
              <option value="private">🔒 私有模式 - 只能用自己的凭证</option>
              <option value="tier3_shared">⚡ 3.0共享 - 有3.0凭证的用户可用公共3.0池</option>
              <option value="full_shared">🍲 大锅饭 - 捐赠凭证即可用所有公共池</option>
            </select>
            <div className="mt-2 text-sm">
              {config?.credential_pool_mode === 'private' && (
                <p className="text-yellow-400">⚠️ 私有模式下用户只能使用自己上传的凭证</p>
              )}
              {config?.credential_pool_mode === 'tier3_shared' && (
                <p className="text-blue-400">💎 用户有3.0凭证时可共享使用公共3.0池</p>
              )}
              {config?.credential_pool_mode === 'full_shared' && (
                <p className="text-green-400">🎉 用户捐赠任意凭证后可使用所有公共凭证</p>
              )}
            </div>
          </div>

          {/* 速率限制 */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h3 className="font-semibold mb-2">基础速率限制 ⏱️</h3>
              <p className="text-gray-400 text-sm mb-3">未贡献凭证用户的每分钟请求数</p>
              <input
                type="number"
                value={config?.base_rpm ?? ''}
                onChange={(e) => setConfig({ ...config, base_rpm: e.target.value === '' ? '' : parseInt(e.target.value) })}
                className="w-full bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
              <p className="text-gray-500 text-sm mt-1">次/分钟</p>
            </div>
            <div>
              <h3 className="font-semibold mb-2">贡献者速率限制 🚀</h3>
              <p className="text-gray-400 text-sm mb-3">贡献凭证用户的每分钟请求数</p>
              <input
                type="number"
                value={config?.contributor_rpm ?? ''}
                onChange={(e) => setConfig({ ...config, contributor_rpm: e.target.value === '' ? '' : parseInt(e.target.value) })}
                className="w-full bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
              <p className="text-gray-500 text-sm mt-1">次/分钟</p>
            </div>
          </div>

          {/* 错误重试 */}
          <div>
            <h3 className="font-semibold mb-2">报错切换凭证重试次数 🔄</h3>
            <p className="text-gray-400 text-sm mb-3">遇到 API 错误（如 404、500 等）时自动切换凭证重试的次数</p>
            <input
              type="number"
              min="0"
              max="10"
              value={config?.error_retry_count ?? ''}
              onChange={(e) => setConfig({ ...config, error_retry_count: e.target.value === '' ? '' : parseInt(e.target.value) })}
              className="w-32 bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500"
            />
            <p className="text-gray-500 text-sm mt-1">设为 0 则不重试，直接返回错误</p>
            <p className="text-blue-400 text-sm mt-2">
              💡 当凭证请求失败时，系统会自动尝试切换到其他可用凭证重试
            </p>
          </div>

          {/* 公告配置 */}
          <div className="pt-4 border-t border-gray-700">
            <div className="flex justify-between items-center mb-4">
              <div>
                <h3 className="font-semibold">📢 公告功能</h3>
                <p className="text-gray-400 text-sm">向所有用户显示重要通知</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={config?.announcement_enabled || false}
                  onChange={(e) => setConfig({ ...config, announcement_enabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-amber-600"></div>
              </label>
            </div>
            
            {config?.announcement_enabled && (
              <div className="space-y-4 bg-gray-700/30 rounded-lg p-4">
                <div>
                  <label className="block text-sm font-medium mb-2">公告标题</label>
                  <input
                    type="text"
                    value={config?.announcement_title || ''}
                    onChange={(e) => setConfig({ ...config, announcement_title: e.target.value })}
                    placeholder="例如：【重要通知】系统维护公告"
                    className="w-full bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-amber-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">公告内容</label>
                  <textarea
                    value={config?.announcement_content || ''}
                    onChange={(e) => setConfig({ ...config, announcement_content: e.target.value })}
                    placeholder="在这里输入公告内容，支持多行文本..."
                    rows={6}
                    className="w-full bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-amber-500 resize-none"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">阅读等待时间（秒）</label>
                  <input
                    type="number"
                    min="0"
                    max="60"
                    value={config?.announcement_read_seconds || 5}
                    onChange={(e) => setConfig({ ...config, announcement_read_seconds: parseInt(e.target.value) || 5 })}
                    className="w-32 bg-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-amber-500"
                  />
                  <p className="text-gray-500 text-sm mt-1">用户首次阅读需等待此时间才能关闭公告</p>
                </div>
              </div>
            )}
          </div>

          {/* 保存按钮 */}
          <div className="pt-4 border-t border-gray-700">
            <button
              onClick={handleSave}
              disabled={saving}
              className="w-full py-3 bg-purple-600 hover:bg-purple-700 rounded-lg font-semibold flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <Save size={18} />
              {saving ? '保存中...' : '保存配置'}
            </button>
          </div>
        </div>

        {/* 提示信息 */}
        <div className="mt-6 bg-green-900/20 border border-green-600/30 rounded-lg p-4">
          <h4 className="text-green-400 font-semibold mb-2">💾 自动保存</h4>
          <p className="text-green-200/80 text-sm">
            配置会自动保存到数据库，重启服务后依然生效。
          </p>
        </div>
      </div>
    </div>
  )
}
