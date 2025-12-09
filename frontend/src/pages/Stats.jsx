import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api'

export default function Stats() {
  const navigate = useNavigate()
  const [overview, setOverview] = useState(null)
  const [globalStats, setGlobalStats] = useState(null)
  const [byModel, setByModel] = useState([])
  const [byUser, setByUser] = useState([])
  const [daily, setDaily] = useState([])
  const [loading, setLoading] = useState(true)
  const [days, setDays] = useState(7)

  useEffect(() => {
    fetchStats()
  }, [days])

  const fetchStats = async () => {
    try {
      setLoading(true)
      const [overviewRes, globalRes, modelRes, userRes, dailyRes] = await Promise.all([
        api.get('/api/manage/stats/overview'),
        api.get('/api/manage/stats/global'),
        api.get(`/api/manage/stats/by-model?days=${days}`),
        api.get(`/api/manage/stats/by-user?days=${days}`),
        api.get(`/api/manage/stats/daily?days=${days}`),
      ])
      setOverview(overviewRes.data)
      setGlobalStats(globalRes.data)
      setByModel(modelRes.data.models || [])
      setByUser(userRes.data.users || [])
      setDaily(dailyRes.data.daily || [])
    } catch (err) {
      if (err.response?.status === 401 || err.response?.status === 403) {
        navigate('/login')
      }
    } finally {
      setLoading(false)
    }
  }

  const poolModeLabel = {
    private: '🔒 私有模式',
    tier3_shared: '⚡ 3.0共享',
    full_shared: '🍲 大锅饭',
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
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold">📊 使用统计</h1>
          <div className="flex gap-4 items-center">
            <select
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              className="bg-gray-800 text-white px-3 py-2 rounded-lg"
            >
              <option value={7}>最近 7 天</option>
              <option value={14}>最近 14 天</option>
              <option value={30}>最近 30 天</option>
            </select>
            <button
              onClick={() => navigate('/dashboard')}
              className="px-4 py-2 bg-gray-700 rounded-lg hover:bg-gray-600"
            >
              返回仪表盘
            </button>
          </div>
        </div>

        {/* 全站实时统计 */}
        {globalStats && (
          <div className="bg-gray-800 rounded-xl p-6 mb-8">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold">🌐 全站实时统计</h2>
              <span className="px-3 py-1 bg-purple-600/30 text-purple-400 rounded-full text-sm">
                {poolModeLabel[globalStats.pool_mode] || globalStats.pool_mode}
              </span>
            </div>
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="text-2xl font-bold text-yellow-400">{globalStats.requests.last_hour}</div>
                <div className="text-sm text-gray-400">最近1小时</div>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="text-2xl font-bold text-blue-400">{globalStats.requests.today}</div>
                <div className="text-sm text-gray-400">今日请求</div>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="text-2xl font-bold text-green-400">{globalStats.users.active_24h}</div>
                <div className="text-sm text-gray-400">活跃用户(24h)</div>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="text-2xl font-bold text-purple-400">{globalStats.credentials.tier_3}</div>
                <div className="text-sm text-gray-400">3.0凭证</div>
              </div>
            </div>

            {/* 按模型分类 */}
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div className="bg-cyan-600/20 border border-cyan-600/30 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-cyan-400">{globalStats.requests.by_category.flash}</div>
                <div className="text-sm text-cyan-300">Flash 请求</div>
              </div>
              <div className="bg-orange-600/20 border border-orange-600/30 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-orange-400">{globalStats.requests.by_category['pro_2.5']}</div>
                <div className="text-sm text-orange-300">2.5 Pro 请求</div>
              </div>
              <div className="bg-pink-600/20 border border-pink-600/30 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-pink-400">{globalStats.requests.by_category.tier_3}</div>
                <div className="text-sm text-pink-300">3.0 请求</div>
              </div>
            </div>

            {/* 凭证状态 */}
            <div className="flex items-center gap-4 text-sm text-gray-400">
              <span>凭证: {globalStats.credentials.active}/{globalStats.credentials.total} 活跃</span>
              <span>•</span>
              <span>公共池: {globalStats.credentials.public}</span>
              <span>•</span>
              <span>3.0: {globalStats.credentials.tier_3}</span>
            </div>
          </div>
        )}

        {/* 概览卡片 */}
        {overview && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-gradient-to-br from-blue-600 to-blue-800 p-6 rounded-xl">
              <h3 className="text-sm text-blue-200 mb-2">今日请求</h3>
              <p className="text-3xl font-bold">{overview.requests.today}</p>
            </div>
            <div className="bg-gradient-to-br from-green-600 to-green-800 p-6 rounded-xl">
              <h3 className="text-sm text-green-200 mb-2">本周请求</h3>
              <p className="text-3xl font-bold">{overview.requests.week}</p>
            </div>
            <div className="bg-gradient-to-br from-purple-600 to-purple-800 p-6 rounded-xl">
              <h3 className="text-sm text-purple-200 mb-2">本月请求</h3>
              <p className="text-3xl font-bold">{overview.requests.month}</p>
            </div>
            <div className="bg-gradient-to-br from-orange-600 to-orange-800 p-6 rounded-xl">
              <h3 className="text-sm text-orange-200 mb-2">活跃凭证</h3>
              <p className="text-3xl font-bold">{overview.credentials.active}/{overview.credentials.total}</p>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* 按模型统计 */}
          <div className="bg-gray-800 rounded-xl p-6">
            <h2 className="text-xl font-semibold mb-4">🤖 按模型统计</h2>
            <div className="space-y-3">
              {byModel.length === 0 ? (
                <p className="text-gray-400">暂无数据</p>
              ) : (
                byModel.map((item, idx) => (
                  <div key={idx} className="flex justify-between items-center">
                    <span className="text-gray-300 truncate flex-1">{item.model}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-32 bg-gray-700 rounded-full h-2">
                        <div
                          className="bg-blue-500 h-2 rounded-full"
                          style={{
                            width: `${Math.min(100, (item.count / (byModel[0]?.count || 1)) * 100)}%`
                          }}
                        />
                      </div>
                      <span className="text-white font-medium w-16 text-right">{item.count}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* 按用户统计 */}
          <div className="bg-gray-800 rounded-xl p-6">
            <h2 className="text-xl font-semibold mb-4">👥 按用户统计 (Top 20)</h2>
            <div className="space-y-3">
              {byUser.length === 0 ? (
                <p className="text-gray-400">暂无数据</p>
              ) : (
                byUser.map((item, idx) => (
                  <div key={idx} className="flex justify-between items-center">
                    <span className="text-gray-300">{item.username}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-32 bg-gray-700 rounded-full h-2">
                        <div
                          className="bg-green-500 h-2 rounded-full"
                          style={{
                            width: `${Math.min(100, (item.count / (byUser[0]?.count || 1)) * 100)}%`
                          }}
                        />
                      </div>
                      <span className="text-white font-medium w-16 text-right">{item.count}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* 每日趋势 */}
        <div className="bg-gray-800 rounded-xl p-6 mt-8">
          <h2 className="text-xl font-semibold mb-4">📈 近{days}日请求趋势</h2>
          <div className="h-48 flex items-end gap-2">
            {daily.length === 0 ? (
              <p className="text-gray-400">暂无数据</p>
            ) : (
              daily.map((item, idx) => {
                const maxCount = Math.max(...daily.map(d => d.count), 1)
                const height = (item.count / maxCount) * 100
                return (
                  <div key={idx} className="flex-1 flex flex-col items-center">
                    {/* 数字标签 */}
                    <span className="text-xs text-gray-400 mb-1">{item.count}</span>
                    {/* 柱形图 */}
                    <div className="w-full flex-1 flex items-end">
                      <div
                        className="w-full bg-blue-500 rounded-t hover:bg-blue-400 transition-colors"
                        style={{ height: `${Math.max(height, 4)}%`, minHeight: item.count > 0 ? '8px' : '2px' }}
                      />
                    </div>
                    {/* 日期标签 */}
                    <span className="text-xs text-gray-500 mt-1">{item.date?.slice(5) || ''}</span>
                  </div>
                )
              })
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
