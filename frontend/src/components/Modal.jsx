import { X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

/**
 * 通用模态框组件
 */
export function Modal({ isOpen, onClose, title, children }) {
  const modalRef = useRef(null)

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => {
      document.body.style.overflow = ''
    }
  }, [isOpen])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* 背景遮罩 */}
      <div 
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />
      {/* 模态框内容 */}
      <div 
        ref={modalRef}
        className="relative bg-dark-800 border border-dark-600 rounded-xl shadow-2xl max-w-md w-full mx-4 animate-in fade-in zoom-in-95 duration-200"
      >
        {/* 标题栏 */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-dark-600">
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          <button
            onClick={onClose}
            className="p-1 text-gray-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
          >
            <X size={20} />
          </button>
        </div>
        {/* 内容区域 */}
        <div className="px-6 py-4">
          {children}
        </div>
      </div>
    </div>
  )
}

/**
 * 确认框组件
 */
export function ConfirmModal({ isOpen, onClose, onConfirm, title, message, confirmText = '确定', cancelText = '取消', danger = false }) {
  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title}>
      <p className="text-gray-300 mb-6">{message}</p>
      <div className="flex justify-end gap-3">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-white rounded-lg transition-colors"
        >
          {cancelText}
        </button>
        <button
          onClick={() => { onConfirm(); onClose(); }}
          className={`px-4 py-2 rounded-lg transition-colors ${
            danger 
              ? 'bg-red-600 hover:bg-red-500 text-white' 
              : 'bg-purple-600 hover:bg-purple-500 text-white'
          }`}
        >
          {confirmText}
        </button>
      </div>
    </Modal>
  )
}

/**
 * 输入框模态框组件
 */
export function InputModal({ isOpen, onClose, onSubmit, title, label, placeholder, defaultValue = '', type = 'text' }) {
  const inputRef = useRef(null)

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus()
      inputRef.current.select()
    }
  }, [isOpen])

  const handleSubmit = (e) => {
    e.preventDefault()
    const value = inputRef.current?.value
    if (value !== null && value !== undefined) {
      onSubmit(value)
      onClose()
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title}>
      <form onSubmit={handleSubmit}>
        {label && <label className="block text-gray-400 text-sm mb-2">{label}</label>}
        <input
          ref={inputRef}
          type={type}
          defaultValue={defaultValue}
          placeholder={placeholder}
          className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-lg text-white placeholder-gray-500 focus:border-purple-500 focus:outline-none"
        />
        <div className="flex justify-end gap-3 mt-6">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-white rounded-lg transition-colors"
          >
            取消
          </button>
          <button
            type="submit"
            className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg transition-colors"
          >
            确定
          </button>
        </div>
      </form>
    </Modal>
  )
}

/**
 * 提示框组件
 */
export function AlertModal({ isOpen, onClose, title, message, type = 'info' }) {
  const colors = {
    info: 'text-blue-400',
    success: 'text-green-400',
    error: 'text-red-400',
    warning: 'text-yellow-400'
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title}>
      <p className={`${colors[type]} mb-6`}>{message}</p>
      <div className="flex justify-end">
        <button
          onClick={onClose}
          className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg transition-colors"
        >
          确定
        </button>
      </div>
    </Modal>
  )
}

/**
 * 配额设置弹窗（支持按模型分类）
 */
export function QuotaModal({ isOpen, onClose, onSubmit, title, defaultValues = {} }) {
  const [values, setValues] = useState({
    quota_flash: defaultValues.quota_flash || 0,
    quota_25pro: defaultValues.quota_25pro || 0,
    quota_30pro: defaultValues.quota_30pro || 0
  })

  useEffect(() => {
    if (isOpen) {
      setValues({
        quota_flash: defaultValues.quota_flash || 0,
        quota_25pro: defaultValues.quota_25pro || 0,
        quota_30pro: defaultValues.quota_30pro || 0
      })
    }
  }, [isOpen, defaultValues])

  // 总配额自动计算
  const totalQuota = values.quota_flash + values.quota_25pro + values.quota_30pro

  const handleSubmit = (e) => {
    e.preventDefault()
    // 提交时自动计算总配额
    onSubmit({ ...values, daily_quota: totalQuota })
    onClose()
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title}>
      <form onSubmit={handleSubmit}>
        <div className="space-y-4">
          <div>
            <p className="text-gray-400 text-sm mb-3">按模型配额（0=使用系统默认）</p>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="block text-cyan-400 text-xs mb-1">Flash</label>
                <input
                  type="number"
                  value={values.quota_flash}
                  onChange={(e) => setValues({ ...values, quota_flash: parseInt(e.target.value) || 0 })}
                  className="w-full px-3 py-2 bg-dark-900 border border-cyan-700/50 rounded-lg text-white text-sm focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-orange-400 text-xs mb-1">2.5 Pro</label>
                <input
                  type="number"
                  value={values.quota_25pro}
                  onChange={(e) => setValues({ ...values, quota_25pro: parseInt(e.target.value) || 0 })}
                  className="w-full px-3 py-2 bg-dark-900 border border-orange-700/50 rounded-lg text-white text-sm focus:border-orange-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-pink-400 text-xs mb-1">3.0</label>
                <input
                  type="number"
                  value={values.quota_30pro}
                  onChange={(e) => setValues({ ...values, quota_30pro: parseInt(e.target.value) || 0 })}
                  className="w-full px-3 py-2 bg-dark-900 border border-pink-700/50 rounded-lg text-white text-sm focus:border-pink-500 focus:outline-none"
                />
              </div>
            </div>
          </div>
          <div className="border-t border-dark-600 pt-4">
            <div className="flex justify-between items-center">
              <span className="text-gray-400 text-sm">总配额（自动计算）</span>
              <span className="text-purple-400 font-semibold">{totalQuota.toLocaleString()}</span>
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-white rounded-lg transition-colors"
          >
            取消
          </button>
          <button
            type="submit"
            className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg transition-colors"
          >
            确定
          </button>
        </div>
      </form>
    </Modal>
  )
}
