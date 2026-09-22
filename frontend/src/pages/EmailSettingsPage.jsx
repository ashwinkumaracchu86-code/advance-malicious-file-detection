import { useState, useEffect, useCallback } from 'react'
import {
  FiServer,
  FiMail,
  FiLock,
  FiKey,
  FiSettings,
  FiPlay,
  FiPause,
  FiCheckCircle,
  FiAlertTriangle,
  FiRefreshCw,
  FiEye,
  FiEyeOff,
  FiShield,
  FiClock,
} from 'react-icons/fi'
import toast from 'react-hot-toast'
import { emailSecurityAPI } from '../services/api'

const PROVIDERS = [
  { value: 'custom', label: 'Custom IMAP' },
  { value: 'gmail', label: 'Gmail' },
  { value: 'outlook', label: 'Outlook/Microsoft' },
]

const POLLING_INTERVALS = [
  { value: 30, label: '30 seconds' },
  { value: 60, label: '60 seconds' },
  { value: 120, label: '120 seconds' },
  { value: 300, label: '5 minutes' },
]

const DEFAULT_CONFIG = {
  provider: 'custom',
  imapHost: '',
  imapPort: 993,
  useSSL: true,
  username: '',
  password: '',
  pollingInterval: 60,
  folders: 'INBOX',
  maxAttachmentSizeMB: 25,
  autoQuarantineThreshold: 70,
}

const PROVIDER_PRESETS = {
  gmail: { imapHost: 'imap.gmail.com', imapPort: 993, useSSL: true },
  outlook: { imapHost: 'outlook.office365.com', imapPort: 993, useSSL: true },
  custom: { imapHost: '', imapPort: 993, useSSL: true },
}

function InputField({ label, icon: Icon, children }) {
  return (
    <div className="space-y-1.5">
      <label className="flex items-center gap-2 text-sm font-medium text-dark-100">
        {Icon && <Icon className="w-4 h-4 text-cyan-400" />}
        {label}
      </label>
      {children}
    </div>
  )
}

function ToggleSwitch({ enabled, onChange, label }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!enabled)}
      className="flex items-center gap-3 group"
    >
      <div
        className={`relative w-11 h-6 rounded-full transition-colors ${
          enabled ? 'bg-cyan-600' : 'bg-dark-600'
        }`}
      >
        <div
          className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform shadow-sm ${
            enabled ? 'translate-x-5' : 'translate-x-0'
          }`}
        />
      </div>
      <span className="text-sm text-dark-100">{label}</span>
    </button>
  )
}

export default function EmailSettingsPage() {
  const [config, setConfig] = useState(DEFAULT_CONFIG)
  const [showPassword, setShowPassword] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [status, setStatus] = useState({
    connected: false,
    lastCheckTime: null,
    isMonitoring: false,
  })
  const [isStartingMonitor, setIsStartingMonitor] = useState(false)
  const [isStoppingMonitor, setIsStoppingMonitor] = useState(false)
  const [errors, setErrors] = useState({})
  const [touched, setTouched] = useState({})
  const [isConfigured, setIsConfigured] = useState(false)

  const loadConfig = useCallback(async () => {
    setIsLoading(true)
    try {
      const res = await emailSecurityAPI.getMonitoringConfig()
      const data = res.data || res
      if (data && data.configured) {
        setIsConfigured(true)
        setConfig({
          provider: data.provider || 'custom',
          imapHost: data.imap_host || '',
          imapPort: data.imap_port || 993,
          useSSL: data.use_ssl ?? true,
          username: data.username || '',
          password: '',
          pollingInterval: data.polling_interval_seconds || 60,
          folders: Array.isArray(data.folders_to_monitor) ? data.folders_to_monitor.join(', ') : (data.folders_to_monitor || 'INBOX'),
          maxAttachmentSizeMB: data.max_attachment_size_mb || 25,
          autoQuarantineThreshold: data.auto_quarantine_threshold || 70,
        })
      }
    } catch {
      toast.error('Failed to load configuration')
    } finally {
      setIsLoading(false)
    }
  }, [])

  const loadStatus = useCallback(async () => {
    try {
      const res = await emailSecurityAPI.getMonitoringStatus()
      const data = res.data || res
      if (data) {
        const running = data.monitor_running ?? false
        setStatus({
          connected: running,
          lastCheckTime: data.last_check || null,
          isMonitoring: running,
        })
        setIsConfigured(prev => prev || running || data.active_configs > 0)
      }
    } catch {
      // silent fail for status polling
    }
  }, [])

  useEffect(() => {
    loadConfig()
    loadStatus()
    const interval = setInterval(loadStatus, 10000)
    return () => clearInterval(interval)
  }, [loadConfig, loadStatus])

  const handleChange = (field, value) => {
    if (field === 'imapPort') {
      const num = parseInt(value, 10)
      value = isNaN(num) ? 993 : num
    }
    setConfig((prev) => ({ ...prev, [field]: value }))
    setTouched((prev) => ({ ...prev, [field]: true }))
    if (errors[field]) {
      setErrors((prev) => ({ ...prev, [field]: null }))
    }
  }

  const handleBlur = (field) => {
    setTouched((prev) => ({ ...prev, [field]: true }))
    const newErrors = {}
    if (field === 'imapHost' && !config.imapHost.trim()) {
      newErrors.imapHost = 'IMAP host is required'
    }
    if (field === 'imapPort' && (!config.imapPort || config.imapPort < 1 || config.imapPort > 65535)) {
      newErrors.imapPort = 'Port must be between 1 and 65535'
    }
    if (field === 'username' && !config.username.trim()) {
      newErrors.username = 'Username is required'
    }
    if (field === 'password' && !config.password) {
      newErrors.password = 'Password is required'
    }
    if (field === 'folders' && !config.folders.trim()) {
      newErrors.folders = 'At least one folder is required'
    }
    if (newErrors[field]) {
      setErrors((prev) => ({ ...prev, ...newErrors }))
    }
  }

  const handleProviderChange = (provider) => {
    const preset = PROVIDER_PRESETS[provider]
    setConfig((prev) => ({
      ...prev,
      provider,
      imapHost: preset.imapHost,
      imapPort: preset.imapPort,
      useSSL: preset.useSSL,
    }))
    setErrors((prev) => ({ ...prev, imapHost: null, imapPort: null }))
  }

  const validate = (skipPassword = false) => {
    const newErrors = {}
    if (!config.imapHost.trim()) {
      newErrors.imapHost = 'IMAP host is required'
    }
    if (!config.imapPort || config.imapPort < 1 || config.imapPort > 65535) {
      newErrors.imapPort = 'Port must be between 1 and 65535'
    }
    if (!config.username.trim()) {
      newErrors.username = 'Username is required'
    }
    if (!skipPassword && !config.password) {
      newErrors.password = 'Password is required'
    }
    if (!config.folders.trim()) {
      newErrors.folders = 'At least one folder is required'
    }
    if (
      config.maxAttachmentSizeMB < 1 ||
      config.maxAttachmentSizeMB > 100
    ) {
      newErrors.maxAttachmentSizeMB = 'Size must be between 1 and 100 MB'
    }
    if (
      config.autoQuarantineThreshold < 0 ||
      config.autoQuarantineThreshold > 100
    ) {
      newErrors.autoQuarantineThreshold =
        'Threshold must be between 0 and 100'
    }
    setErrors(newErrors)
    setTouched({
      imapHost: true, imapPort: true, username: true, password: true,
      folders: true, maxAttachmentSizeMB: true, autoQuarantineThreshold: true,
    })
    return Object.keys(newErrors).length === 0
  }

  const handleSave = async () => {
    if (!validate(isConfigured)) {
      toast.error('Please fix the errors in the form')
      return
    }
    setIsSaving(true)
    try {
      const payload = {
        provider: config.provider,
        imap_host: config.imapHost,
        imap_port: config.imapPort,
        use_ssl: config.useSSL,
        username: config.username,
        password: config.password || '',
        polling_interval_seconds: config.pollingInterval,
        folders_to_monitor: config.folders.split(',').map(f => f.trim()).filter(Boolean),
        max_attachment_size_mb: config.maxAttachmentSizeMB,
        auto_quarantine_threshold: config.autoQuarantineThreshold,
      }
      await emailSecurityAPI.saveMonitoringConfig(payload)
      toast.success('Configuration saved successfully')
    } catch {
      toast.error('Failed to save configuration')
    } finally {
      setIsSaving(false)
    }
  }

  const handleStartMonitoring = async () => {
    if (!validate(isConfigured)) {
      toast.error('Please fill in all required fields')
      return
    }
    setIsStartingMonitor(true)
    try {
      const savePayload = {
        provider: config.provider,
        imap_host: config.imapHost,
        imap_port: config.imapPort,
        use_ssl: config.useSSL,
        username: config.username,
        password: config.password || '',
        polling_interval_seconds: config.pollingInterval,
        folders_to_monitor: config.folders.split(',').map(f => f.trim()).filter(Boolean),
        max_attachment_size_mb: config.maxAttachmentSizeMB,
        auto_quarantine_threshold: config.autoQuarantineThreshold,
      }
      await emailSecurityAPI.saveMonitoringConfig(savePayload)
      await emailSecurityAPI.startMonitoring()
      setStatus((prev) => ({ ...prev, isMonitoring: true, connected: true }))
      setIsConfigured(true)
      toast.success('Email monitoring started')
      await loadStatus()
    } catch (err) {
      console.error('Start monitoring error:', err)
      const msg = err?.response?.data?.detail || err?.message || 'Failed to start monitoring'
      toast.error(msg)
    } finally {
      setIsStartingMonitor(false)
    }
  }

  const handleStopMonitoring = async () => {
    setIsStoppingMonitor(true)
    try {
      await emailSecurityAPI.stopMonitoring()
      setStatus((prev) => ({ ...prev, isMonitoring: false }))
      toast.success('Email monitoring stopped')
      await loadStatus()
    } catch {
      toast.error('Failed to stop monitoring')
    } finally {
      setIsStoppingMonitor(false)
    }
  }

  const formatLastCheck = (time) => {
    if (!time) return 'Never'
    const date = new Date(time)
    return date.toLocaleString()
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-dark-900 flex items-center justify-center">
        <div className="flex items-center gap-3 text-dark-400">
          <FiRefreshCw className="w-5 h-5 animate-spin" />
          <span>Loading configuration...</span>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-dark-900 p-6">
      <div className="max-w-4xl mx-auto space-y-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
            <FiMail className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-dark-100">
              Email Security Settings
            </h1>
            <p className="text-sm text-dark-400">
              Configure IMAP email monitoring for threat detection
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div
                className={`w-3 h-3 rounded-full ${
                  status.connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'
                }`}
              />
              <div>
                <p className="text-xs text-dark-400">Connection Status</p>
                <p
                  className={`text-sm font-medium ${
                    status.connected ? 'text-green-400' : 'text-red-400'
                  }`}
                >
                  {status.connected ? 'Connected' : 'Disconnected'}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-dark-700">
                <FiClock className="w-4 h-4 text-dark-400" />
              </div>
              <div>
                <p className="text-xs text-dark-400">Last Check</p>
                <p className="text-sm font-medium text-dark-100">
                  {formatLastCheck(status.lastCheckTime)}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-dark-800 border border-dark-700 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-dark-700">
                <FiShield className="w-4 h-4 text-dark-400" />
              </div>
              <div>
                <p className="text-xs text-dark-400">Monitoring</p>
                <p
                  className={`text-sm font-medium ${
                    status.isMonitoring ? 'text-cyan-400' : 'text-dark-400'
                  }`}
                >
                  {status.isMonitoring ? 'Active' : 'Inactive'}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleStartMonitoring}
            disabled={isStartingMonitor || status.isMonitoring}
            className="flex items-center gap-2 px-4 py-2.5 bg-green-600 hover:bg-green-700 disabled:bg-green-600/50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
          >
            <FiPlay className="w-4 h-4" />
            {isStartingMonitor ? 'Starting...' : 'Start Monitoring'}
          </button>
          <button
            onClick={handleStopMonitoring}
            disabled={isStoppingMonitor || !status.isMonitoring}
            className="flex items-center gap-2 px-4 py-2.5 bg-red-600 hover:bg-red-700 disabled:bg-red-600/50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
          >
            <FiPause className="w-4 h-4" />
            {isStoppingMonitor ? 'Stopping...' : 'Stop Monitoring'}
          </button>
          <button
            onClick={loadStatus}
            className="flex items-center gap-2 px-4 py-2.5 bg-dark-700 hover:bg-dark-600 text-dark-100 rounded-lg text-sm font-medium transition-colors ml-auto"
          >
            <FiRefreshCw className="w-4 h-4" />
            Refresh Status
          </button>
        </div>

        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-6">
            <FiSettings className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-dark-100">
              IMAP Connection Settings
            </h2>
          </div>

          <div className="space-y-5">
            <InputField label="Email Provider" icon={FiMail}>
              <select
                value={config.provider}
                onChange={(e) => handleProviderChange(e.target.value)}
                className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-2.5 text-sm text-dark-100 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors appearance-none cursor-pointer"
              >
                {PROVIDERS.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.label}
                  </option>
                ))}
              </select>
            </InputField>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <InputField label="IMAP Host" icon={FiServer}>
                <input
                  type="text"
                  value={config.imapHost}
                  onChange={(e) => handleChange('imapHost', e.target.value)}
                  onBlur={() => handleBlur('imapHost')}
                  placeholder="imap.example.com"
                  className={`w-full bg-dark-900 border rounded-lg px-4 py-2.5 text-sm text-dark-100 placeholder:text-dark-500 focus:outline-none focus:ring-1 transition-colors ${
                    touched.imapHost && errors.imapHost
                      ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
                      : 'border-dark-700 focus:border-cyan-500 focus:ring-cyan-500'
                  }`}
                />
                {touched.imapHost && errors.imapHost && (
                  <p className="text-xs text-red-400 mt-1">{errors.imapHost}</p>
                )}
              </InputField>

              <InputField label="IMAP Port" icon={FiServer}>
                <input
                  type="number"
                  value={config.imapPort}
                  onChange={(e) =>
                    handleChange('imapPort', e.target.value)
                  }
                  onBlur={() => handleBlur('imapPort')}
                  min={1}
                  max={65535}
                  className={`w-full bg-dark-900 border rounded-lg px-4 py-2.5 text-sm text-dark-100 focus:outline-none focus:ring-1 transition-colors ${
                    touched.imapPort && errors.imapPort
                      ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
                      : 'border-dark-700 focus:border-cyan-500 focus:ring-cyan-500'
                  }`}
                />
                {touched.imapPort && errors.imapPort && (
                  <p className="text-xs text-red-400 mt-1">{errors.imapPort}</p>
                )}
              </InputField>
            </div>

            <InputField label="Use SSL" icon={FiLock}>
              <ToggleSwitch
                enabled={config.useSSL}
                onChange={(val) => handleChange('useSSL', val)}
                label={config.useSSL ? 'SSL/TLS enabled' : 'SSL/TLS disabled'}
              />
            </InputField>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <InputField label="Username / Email" icon={FiKey}>
                <input
                  type="text"
                  value={config.username}
                  onChange={(e) => handleChange('username', e.target.value)}
                  onBlur={() => handleBlur('username')}
                  placeholder="you@example.com"
                  className={`w-full bg-dark-900 border rounded-lg px-4 py-2.5 text-sm text-dark-100 placeholder:text-dark-500 focus:outline-none focus:ring-1 transition-colors ${
                    touched.username && errors.username
                      ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
                      : 'border-dark-700 focus:border-cyan-500 focus:ring-cyan-500'
                  }`}
                />
                {touched.username && errors.username && (
                  <p className="text-xs text-red-400 mt-1">{errors.username}</p>
                )}
              </InputField>

              <InputField label="Password" icon={FiLock}>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={config.password}
                    onChange={(e) => handleChange('password', e.target.value)}
                    onBlur={() => handleBlur('password')}
                    placeholder={isConfigured ? "Leave blank to keep saved password" : "Enter password"}
                    className={`w-full bg-dark-900 border rounded-lg px-4 py-2.5 pr-10 text-sm text-dark-100 placeholder:text-dark-500 focus:outline-none focus:ring-1 transition-colors ${
                      touched.password && errors.password
                        ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
                        : 'border-dark-700 focus:border-cyan-500 focus:ring-cyan-500'
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-400 hover:text-dark-200 transition-colors"
                  >
                    {showPassword ? (
                      <FiEyeOff className="w-4 h-4" />
                    ) : (
                      <FiEye className="w-4 h-4" />
                    )}
                  </button>
                </div>
                {isConfigured && (
                  <p className="text-xs text-green-400 mt-1">Password saved — leave blank to keep current</p>
                )}
                {touched.password && errors.password && (
                  <p className="text-xs text-red-400 mt-1">{errors.password}</p>
                )}
              </InputField>
            </div>
          </div>
        </div>

        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-6">
            <FiSettings className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-dark-100">
              Monitoring Configuration
            </h2>
          </div>

          <div className="space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <InputField label="Polling Interval" icon={FiClock}>
                <select
                  value={config.pollingInterval}
                  onChange={(e) =>
                    handleChange('pollingInterval', parseInt(e.target.value, 10))
                  }
                  className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-2.5 text-sm text-dark-100 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors appearance-none cursor-pointer"
                >
                  {POLLING_INTERVALS.map((interval) => (
                    <option key={interval.value} value={interval.value}>
                      {interval.label}
                    </option>
                  ))}
                </select>
              </InputField>

              <InputField label="Folders to Monitor" icon={FiMail}>
                <input
                  type="text"
                  value={config.folders}
                  onChange={(e) => handleChange('folders', e.target.value)}
                  onBlur={() => handleBlur('folders')}
                  placeholder="INBOX, Sent, Spam"
                  className={`w-full bg-dark-900 border rounded-lg px-4 py-2.5 text-sm text-dark-100 placeholder:text-dark-500 focus:outline-none focus:ring-1 transition-colors ${
                    touched.folders && errors.folders
                      ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
                      : 'border-dark-700 focus:border-cyan-500 focus:ring-cyan-500'
                  }`}
                />
                <p className="text-xs text-dark-500 mt-1">
                  Comma-separated folder names
                </p>
                {touched.folders && errors.folders && (
                  <p className="text-xs text-red-400 mt-1">{errors.folders}</p>
                )}
              </InputField>
            </div>

            <InputField
              label={`Max Attachment Size: ${config.maxAttachmentSizeMB} MB`}
              icon={FiServer}
            >
              <div className="flex items-center gap-4">
                <input
                  type="range"
                  min={1}
                  max={100}
                  value={config.maxAttachmentSizeMB}
                  onChange={(e) =>
                    handleChange('maxAttachmentSizeMB', parseInt(e.target.value, 10))
                  }
                  className="flex-1 h-2 bg-dark-700 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                />
                <input
                  type="number"
                  value={config.maxAttachmentSizeMB}
                  onChange={(e) =>
                    handleChange(
                      'maxAttachmentSizeMB',
                      Math.min(100, Math.max(1, parseInt(e.target.value, 10) || 1))
                    )
                  }
                  min={1}
                  max={100}
                  className="w-20 bg-dark-900 border border-dark-700 rounded-lg px-3 py-2.5 text-sm text-dark-100 text-center focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                />
                <span className="text-sm text-dark-400">MB</span>
              </div>
              {errors.maxAttachmentSizeMB && (
                <p className="text-xs text-red-400 mt-1">
                  {errors.maxAttachmentSizeMB}
                </p>
              )}
            </InputField>

            <InputField
              label={`Auto-Quarantine Threshold: ${config.autoQuarantineThreshold}%`}
              icon={FiAlertTriangle}
            >
              <div className="space-y-2">
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={config.autoQuarantineThreshold}
                  onChange={(e) =>
                    handleChange(
                      'autoQuarantineThreshold',
                      parseInt(e.target.value, 10)
                    )
                  }
                  className="w-full h-2 bg-dark-700 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                />
                <div className="flex justify-between text-xs text-dark-500">
                  <span>0% (Disabled)</span>
                  <span>50%</span>
                  <span>100% (Always)</span>
                </div>
                <p className="text-xs text-dark-400">
                  Files scoring above this threshold will be automatically
                  quarantined. Current: {config.autoQuarantineThreshold}%
                </p>
              </div>
              {errors.autoQuarantineThreshold && (
                <p className="text-xs text-red-400 mt-1">
                  {errors.autoQuarantineThreshold}
                </p>
              )}
            </InputField>
          </div>
        </div>

        <div className="flex items-center justify-end gap-3">
          <button
            onClick={loadConfig}
            className="flex items-center gap-2 px-5 py-2.5 bg-dark-700 hover:bg-dark-600 text-dark-100 rounded-lg text-sm font-medium transition-colors"
          >
            <FiRefreshCw className="w-4 h-4" />
            Reset
          </button>
          <button
            onClick={handleSave}
            disabled={isSaving}
            className="flex items-center gap-2 px-6 py-2.5 bg-cyan-600 hover:bg-cyan-700 disabled:bg-cyan-600/50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
          >
            <FiCheckCircle className="w-4 h-4" />
            {isSaving ? 'Saving...' : 'Save Configuration'}
          </button>
        </div>
      </div>
    </div>
  )
}
