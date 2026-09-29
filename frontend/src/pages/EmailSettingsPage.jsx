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
  FiExternalLink,
  FiHelpCircle,
  FiInfo,
  FiCheck,
  FiChevronDown,
  FiChevronUp,
} from 'react-icons/fi'
import toast from 'react-hot-toast'
import { emailSecurityAPI } from '../services/api'

const PROVIDERS = [
  {
    value: 'gmail',
    label: 'Gmail (Google Account)',
    badge: 'Google App Password',
    description: 'Monitor Google Workspace or personal Gmail via Google App Password',
  },
  {
    value: 'outlook',
    label: 'Outlook / Microsoft 365',
    badge: 'Microsoft Cloud',
    description: 'Connect to Microsoft 365 or Outlook.com IMAP mailbox',
  },
  {
    value: 'custom',
    label: 'Custom IMAP Server',
    badge: 'Generic IMAP',
    description: 'Connect to self-hosted mail servers, Yahoo, Zoho, or corporate IMAP',
  },
]

const POLLING_INTERVALS = [
  { value: 30, label: '30 seconds (Near real-time)' },
  { value: 60, label: '60 seconds (Recommended)' },
  { value: 120, label: '2 minutes' },
  { value: 300, label: '5 minutes' },
]

const DEFAULT_CONFIG = {
  provider: 'gmail',
  imapHost: 'imap.gmail.com',
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

function InputField({ label, icon: Icon, children, helpText, extraBadge }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <label className="flex items-center gap-2 text-sm font-medium text-dark-100">
          {Icon && <Icon className="w-4 h-4 text-cyan-400" />}
          {label}
        </label>
        {extraBadge}
      </div>
      {children}
      {helpText && <p className="text-xs text-dark-400">{helpText}</p>}
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
  const [hasSavedPassword, setHasSavedPassword] = useState(false)
  const [status, setStatus] = useState({
    connected: false,
    lastCheckTime: null,
    isMonitoring: false,
  })
  const [isTesting, setIsTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [isStartingMonitor, setIsStartingMonitor] = useState(false)
  const [isStoppingMonitor, setIsStoppingMonitor] = useState(false)
  const [errors, setErrors] = useState({})
  const [touched, setTouched] = useState({})
  const [isConfigured, setIsConfigured] = useState(false)
  const [showManualServer, setShowManualServer] = useState(false)
  const [showFaq, setShowFaq] = useState(false)

  const loadConfig = useCallback(async () => {
    setIsLoading(true)
    try {
      const res = await emailSecurityAPI.getMonitoringConfig()
      const data = res.data || res
      if (data && data.configured) {
        setIsConfigured(true)
        setHasSavedPassword(Boolean(data.has_password))
        const prov = data.provider || 'gmail'
        const preset = PROVIDER_PRESETS[prov] || PROVIDER_PRESETS.gmail
        setConfig({
          provider: prov,
          imapHost: prov === 'gmail' ? 'imap.gmail.com' : (data.imap_host || preset.imapHost),
          imapPort: data.imap_port || preset.imapPort,
          useSSL: data.use_ssl ?? preset.useSSL,
          username: data.username || '',
          password: '',
          pollingInterval: data.polling_interval_seconds || 60,
          folders: Array.isArray(data.folders_to_monitor)
            ? data.folders_to_monitor.join(', ')
            : (data.folders_to_monitor || 'INBOX'),
          maxAttachmentSizeMB: data.max_attachment_size_mb || 25,
          autoQuarantineThreshold: data.auto_quarantine_threshold ?? 70,
        })
      } else {
        // Not configured for this user: clean reset
        setIsConfigured(false)
        setHasSavedPassword(false)
        setConfig(DEFAULT_CONFIG)
      }
    } catch {
      toast.error('Failed to load configuration')
      setIsConfigured(false)
      setHasSavedPassword(false)
      setConfig(DEFAULT_CONFIG)
    } finally {
      setIsLoading(false)
    }
  }, [])

  const loadStatus = useCallback(async () => {
    try {
      const res = await emailSecurityAPI.getMonitoringStatus()
      const data = res.data || res
      if (data) {
        const isUserMonitoring = Boolean(data.is_active && data.monitoring_status === 'active')
        setStatus({
          connected: data.connection_status === 'connected',
          lastCheckTime: data.last_check || null,
          isMonitoring: isUserMonitoring,
        })
        if (data.configured !== undefined) {
          setIsConfigured(Boolean(data.configured))
        }
        if (data.has_password !== undefined) {
          setHasSavedPassword(Boolean(data.has_password))
        }
      }
    } catch {
      // silent polling
    }
  }, [])

  useEffect(() => {
    loadConfig()
    loadStatus()
    const interval = setInterval(loadStatus, 10000)
    return () => clearInterval(interval)
  }, [loadConfig, loadStatus])

  const handleProviderChange = (provider) => {
    const preset = PROVIDER_PRESETS[provider] || PROVIDER_PRESETS.custom
    setConfig((prev) => ({
      ...prev,
      provider,
      imapHost: preset.imapHost,
      imapPort: preset.imapPort,
      useSSL: preset.useSSL,
    }))
    setErrors((prev) => ({ ...prev, imapHost: null, imapPort: null }))
    setTestResult(null)
  }

  const handleChange = (field, value) => {
    // If user enters password for Gmail, auto-strip spaces (Google App Passwords have spaces)
    if (field === 'password' && config.provider === 'gmail') {
      value = value.replace(/\s+/g, '')
    }
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
    if (field === 'username') {
      if (!config.username.trim()) {
        newErrors.username = 'Email address is required'
      } else if (config.provider === 'gmail' && !config.username.includes('@')) {
        newErrors.username = 'Please enter your full Gmail address (e.g. name@gmail.com)'
      }
    }
    if (field === 'password' && !hasSavedPassword && !config.password) {
      newErrors.password = config.provider === 'gmail'
        ? 'Google App Password is required'
        : 'Password is required'
    }
    if (field === 'folders' && !config.folders.trim()) {
      newErrors.folders = 'At least one folder is required'
    }
    if (newErrors[field]) {
      setErrors((prev) => ({ ...prev, ...newErrors }))
    }
  }

  const validate = (skipPassword = false) => {
    const newErrors = {}
    const effectiveHost = config.provider === 'gmail' ? 'imap.gmail.com' : config.imapHost.trim()
    if (!effectiveHost) {
      newErrors.imapHost = 'IMAP host is required'
    }
    if (!config.imapPort || config.imapPort < 1 || config.imapPort > 65535) {
      newErrors.imapPort = 'Port must be between 1 and 65535'
    }
    if (!config.username.trim()) {
      newErrors.username = 'Email address is required'
    } else if (config.provider === 'gmail' && !config.username.includes('@')) {
      newErrors.username = 'Please enter your full Gmail address (e.g. name@gmail.com)'
    }
    if (!skipPassword && !hasSavedPassword && !config.password.trim()) {
      newErrors.password = config.provider === 'gmail'
        ? 'Google App Password is required'
        : 'Password is required'
    }
    if (!config.folders.trim()) {
      newErrors.folders = 'At least one folder is required'
    }
    if (config.maxAttachmentSizeMB < 1 || config.maxAttachmentSizeMB > 100) {
      newErrors.maxAttachmentSizeMB = 'Size must be between 1 and 100 MB'
    }
    if (config.autoQuarantineThreshold < 0 || config.autoQuarantineThreshold > 100) {
      newErrors.autoQuarantineThreshold = 'Threshold must be between 0 and 100'
    }
    setErrors(newErrors)
    setTouched({
      imapHost: true,
      imapPort: true,
      username: true,
      password: true,
      folders: true,
      maxAttachmentSizeMB: true,
      autoQuarantineThreshold: true,
    })
    return Object.keys(newErrors).length === 0
  }

  const getCleanPayload = () => {
    const cleanPassword = (config.password || '').trim().replace(/\s+/g, '')
    const isGmail = config.provider === 'gmail'
    return {
      provider: config.provider,
      imap_host: isGmail ? 'imap.gmail.com' : config.imapHost.trim(),
      imap_port: isGmail ? 993 : config.imapPort,
      use_ssl: isGmail ? true : config.useSSL,
      username: config.username.trim(),
      password: cleanPassword,
      polling_interval_seconds: config.pollingInterval,
      folders_to_monitor: config.folders
        .split(',')
        .map((f) => f.trim())
        .filter(Boolean),
      max_attachment_size_mb: config.maxAttachmentSizeMB,
      auto_quarantine_threshold: config.autoQuarantineThreshold,
    }
  }

  const handleSave = async () => {
    if (!validate(hasSavedPassword)) {
      toast.error('Please fix the errors in the form')
      return
    }
    setIsSaving(true)
    try {
      const payload = getCleanPayload()
      await emailSecurityAPI.saveMonitoringConfig(payload)
      setIsConfigured(true)
      if (payload.password) {
        setHasSavedPassword(true)
        setConfig((prev) => ({ ...prev, password: '' }))
      }
      toast.success('Email settings saved successfully')
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.message || 'Failed to save configuration'
      toast.error(msg)
    } finally {
      setIsSaving(false)
    }
  }

  const handleTestConnection = async () => {
    if (!validate(hasSavedPassword)) {
      toast.error('Please fill in your email address and Google App Password')
      return
    }
    setIsTesting(true)
    setTestResult(null)
    try {
      const payload = getCleanPayload()
      const res = await emailSecurityAPI.testConnection(payload)
      const data = res?.data || res
      const isOk = data && (data.status === 'CONNECTED' || data.code === 'ok' || data.success)
      setTestResult({
        success: isOk,
        message: data?.message || (isOk ? 'Connection verified successfully' : 'Connection failed'),
        server: data?.server || payload.imap_host,
        folders: data?.folders || [],
      })
      if (isOk) {
        toast.success('IMAP Connection Successful!')
      } else {
        toast.error(data?.message || 'Connection failed. Check your App Password.')
      }
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.message || 'Connection test failed'
      setTestResult({
        success: false,
        message: msg,
      })
      toast.error(msg)
    } finally {
      setIsTesting(false)
    }
  }

  const handleStartMonitoring = async () => {
    if (!validate(hasSavedPassword)) {
      toast.error('Please complete all required fields')
      return
    }
    setIsStartingMonitor(true)
    try {
      const payload = getCleanPayload()
      await emailSecurityAPI.saveMonitoringConfig(payload)
      await emailSecurityAPI.startMonitoring()
      setStatus((prev) => ({ ...prev, isMonitoring: true, connected: true }))
      setIsConfigured(true)
      if (payload.password) {
        setHasSavedPassword(true)
        setConfig((prev) => ({ ...prev, password: '' }))
      }
      toast.success('Live email monitoring started')
      await loadStatus()
    } catch (err) {
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
          <FiRefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
          <span>Loading email security configuration...</span>
        </div>
      </div>
    )
  }

  const isGmail = config.provider === 'gmail'
  const passwordLength = (config.password || '').length
  const isStandardPassword =
    isGmail &&
    Boolean(
      config.password &&
        (/[A-Z]/.test(config.password) ||
          /\d/.test(config.password) ||
          /[!@#$%^&*()_+\-=[\]{}|;':",./<>?`~]/.test(config.password) ||
          config.password.length !== 16)
    )

  return (
    <div className="min-h-screen bg-dark-900 p-6">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30">
              <FiMail className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-2">
                Email Security Settings
              </h1>
              <p className="text-sm text-dark-400">
                Connect your mailbox to inspect inbound emails, quarantine threats &amp; stop phishing
              </p>
            </div>
          </div>
          <button
            onClick={loadStatus}
            className="flex items-center gap-2 px-3 py-1.5 bg-dark-800 hover:bg-dark-700 text-dark-300 rounded-lg text-xs font-medium border border-dark-700 transition-colors"
          >
            <FiRefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>

        {/* Status Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-dark-800/90 border border-dark-700 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div
                className={`w-3.5 h-3.5 rounded-full ${
                  status.connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'
                }`}
              />
              <div>
                <p className="text-xs text-dark-400">Connection Status</p>
                <p
                  className={`text-sm font-semibold ${
                    status.connected ? 'text-emerald-400' : 'text-rose-400'
                  }`}
                >
                  {status.connected ? 'Connected to Mail Server' : 'Disconnected'}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-dark-800/90 border border-dark-700 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-dark-700">
                <FiClock className="w-4 h-4 text-dark-400" />
              </div>
              <div>
                <p className="text-xs text-dark-400">Last Scanned</p>
                <p className="text-sm font-medium text-dark-100">
                  {formatLastCheck(status.lastCheckTime)}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-dark-800/90 border border-dark-700 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div
                className={`p-2 rounded-lg ${
                  status.isMonitoring ? 'bg-cyan-500/10 text-cyan-400' : 'bg-dark-700 text-dark-400'
                }`}
              >
                <FiShield className="w-4 h-4" />
              </div>
              <div>
                <p className="text-xs text-dark-400">Active Monitoring</p>
                <p
                  className={`text-sm font-semibold ${
                    status.isMonitoring ? 'text-cyan-400' : 'text-dark-400'
                  }`}
                >
                  {status.isMonitoring ? 'Active & Protecting' : 'Inactive'}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Primary Controls */}
        <div className="flex flex-wrap items-center gap-3 bg-dark-800/60 border border-dark-700/80 rounded-xl p-4">
          <button
            onClick={handleTestConnection}
            disabled={isTesting}
            className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 disabled:bg-dark-700/60 disabled:cursor-not-allowed text-dark-100 rounded-lg text-sm font-medium border border-dark-600 transition-colors shadow-sm"
          >
            {isTesting ? (
              <FiRefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
            ) : (
              <FiKey className="w-4 h-4 text-cyan-400" />
            )}
            {isTesting ? 'Testing Connection...' : 'Test Connection'}
          </button>

          <button
            onClick={handleStartMonitoring}
            disabled={isStartingMonitor || status.isMonitoring}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-600/40 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors shadow-sm"
          >
            <FiPlay className="w-4 h-4" />
            {isStartingMonitor ? 'Starting...' : 'Start Monitoring'}
          </button>

          <button
            onClick={handleStopMonitoring}
            disabled={isStoppingMonitor || !status.isMonitoring}
            className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:bg-rose-600/40 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors shadow-sm"
          >
            <FiPause className="w-4 h-4" />
            {isStoppingMonitor ? 'Stopping...' : 'Stop Monitoring'}
          </button>

          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={handleSave}
              disabled={isSaving}
              className="flex items-center gap-2 px-5 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-600/40 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors shadow-sm"
            >
              <FiCheckCircle className="w-4 h-4" />
              {isSaving ? 'Saving...' : 'Save Configuration'}
            </button>
          </div>
        </div>

        {/* Test Result Alert Banner */}
        {testResult && (
          <div
            className={`p-4 rounded-xl border flex items-start gap-3 transition-all ${
              testResult.success
                ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
                : 'bg-rose-950/40 border-rose-500/40 text-rose-200'
            }`}
          >
            {testResult.success ? (
              <FiCheckCircle className="w-5 h-5 text-emerald-400 mt-0.5 shrink-0" />
            ) : (
              <FiAlertTriangle className="w-5 h-5 text-rose-400 mt-0.5 shrink-0" />
            )}
            <div className="space-y-1.5 text-sm flex-1">
              <p className="font-semibold text-base">
                {testResult.success ? 'Connection Test Succeeded' : 'Authentication Error'}
              </p>
              <p className="text-xs opacity-90 leading-relaxed">{testResult.message}</p>

              {/* Actionable Error Resolution Card */}
              {!testResult.success && testResult.message.includes('Authentication failed') && (
                <div className="mt-3 p-3.5 bg-dark-900/90 border border-rose-500/30 rounded-xl space-y-2.5 text-xs text-dark-200 shadow-md">
                  <p className="font-bold text-rose-300 flex items-center gap-1.5 text-sm">
                    <FiInfo className="w-4 h-4" />
                    How to Fix This Error:
                  </p>
                  <p className="text-dark-300 leading-relaxed">
                    <strong>1. Why this happened:</strong> Google strictly forbids using your regular personal password (e.g. Gmail sign-in password) for IMAP apps. You must use a <strong>16-character App Password</strong> generated from your Google Security console.
                  </p>
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <a
                      href="https://myaccount.google.com/apppasswords"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all"
                    >
                      <span>Create New App Password at Google</span>
                      <FiExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
              )}

              {testResult.folders && testResult.folders.length > 0 && (
                <div className="text-xs pt-1 flex items-center gap-2">
                  <span className="opacity-75">Mailbox folders verified:</span>
                  {testResult.folders.map((f, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-xs"
                    >
                      {f.name || f}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* SECTION 1: Provider Selection */}
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FiMail className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg font-semibold text-dark-100">
                Email Provider Selection
              </h2>
            </div>
            <span className="text-xs text-dark-400">Choose your mail service</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {PROVIDERS.map((p) => {
              const selected = config.provider === p.value
              return (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => handleProviderChange(p.value)}
                  className={`p-4 rounded-xl border text-left transition-all relative ${
                    selected
                      ? 'bg-gradient-to-b from-cyan-950/40 to-dark-850 border-cyan-500 shadow-md shadow-cyan-950/20 ring-1 ring-cyan-500/50'
                      : 'bg-dark-900/60 border-dark-700 hover:border-dark-600 hover:bg-dark-850'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-sm text-dark-100">{p.label}</span>
                    {selected && <FiCheck className="w-4 h-4 text-cyan-400" />}
                  </div>
                  <span
                    className={`inline-block text-[11px] font-medium px-2 py-0.5 rounded-full mb-1.5 ${
                      selected
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                        : 'bg-dark-700 text-dark-400'
                    }`}
                  >
                    {p.badge}
                  </span>
                  <p className="text-xs text-dark-400 line-clamp-2">{p.description}</p>
                </button>
              )
            })}
          </div>
        </div>

        {/* SECTION 2: Google App Password Setup Guide (Prominent for Gmail) */}
        {isGmail && (
          <div className="bg-gradient-to-br from-blue-950/40 via-dark-800 to-cyan-950/30 border border-blue-500/40 rounded-xl p-6 space-y-5 shadow-lg">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-blue-500/20">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-blue-500/20 border border-blue-400/30 text-blue-300">
                  <FiKey className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-dark-100 flex items-center gap-2">
                    Login with Google App Password
                    <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30">
                      Required by Google
                    </span>
                  </h3>
                  <p className="text-xs text-dark-300">
                    Google requires a dedicated 16-character App Password for IMAP access. Regular personal passwords are not accepted.
                  </p>
                </div>
              </div>

              {/* Quick Actions */}
              <div className="flex flex-wrap items-center gap-2">
                <a
                  href="https://myaccount.google.com/apppasswords"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-blue-900/30 transition-all shrink-0"
                >
                  <span>Generate App Password</span>
                  <FiExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>

            {/* Step-by-Step Instructions */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
              <div className="bg-dark-900/70 border border-dark-700/80 rounded-lg p-3 space-y-1.5">
                <div className="flex items-center gap-2 font-semibold text-cyan-400">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-xs">1</span>
                  <span>Turn on 2FA</span>
                </div>
                <p className="text-dark-400">
                  Ensure <strong>2-Step Verification</strong> is enabled in your Google Account Security settings.
                </p>
              </div>

              <div className="bg-dark-900/70 border border-dark-700/80 rounded-lg p-3 space-y-1.5">
                <div className="flex items-center gap-2 font-semibold text-cyan-400">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-xs">2</span>
                  <span>Open App Passwords</span>
                </div>
                <p className="text-dark-400">
                  Click the blue button above or visit <strong className="text-dark-200">myaccount.google.com/apppasswords</strong>.
                </p>
              </div>

              <div className="bg-dark-900/70 border border-dark-700/80 rounded-lg p-3 space-y-1.5">
                <div className="flex items-center gap-2 font-semibold text-cyan-400">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-xs">3</span>
                  <span>Create App Name</span>
                </div>
                <p className="text-dark-400">
                  Type <code className="text-cyan-300 bg-cyan-950/60 px-1 py-0.5 rounded font-mono">ThreatShield</code> in the App name field and click <strong>Create</strong>.
                </p>
              </div>

              <div className="bg-dark-900/70 border border-dark-700/80 rounded-lg p-3 space-y-1.5">
                <div className="flex items-center gap-2 font-semibold text-cyan-400">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-xs">4</span>
                  <span>Paste 16-Letter Code</span>
                </div>
                <p className="text-dark-400">
                  Copy the 16 characters from Google and paste into the field below. Spaces are stripped automatically.
                </p>
              </div>
            </div>

            {/* Expandable Troubleshooting */}
            <div className="pt-1">
              <button
                type="button"
                onClick={() => setShowFaq(!showFaq)}
                className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
              >
                <FiHelpCircle className="w-3.5 h-3.5" />
                <span>Troubleshooting &amp; FAQs for Google App Passwords</span>
                {showFaq ? <FiChevronUp className="w-3.5 h-3.5" /> : <FiChevronDown className="w-3.5 h-3.5" />}
              </button>

              {showFaq && (
                <div className="mt-3 p-4 bg-dark-900/80 border border-dark-700 rounded-lg space-y-3 text-xs text-dark-300">
                  <div>
                    <p className="font-semibold text-dark-100">Why does my regular password fail?</p>
                    <p className="text-dark-400 mt-0.5">
                      Google disabled basic password access for third-party email clients to prevent credential theft. A dedicated 16-letter App Password is required by Google.
                    </p>
                  </div>
                  <div>
                    <p className="font-semibold text-dark-100">I don't see "App Passwords" in my Google Account?</p>
                    <p className="text-dark-400 mt-0.5">
                      1. Check that <strong>2-Step Verification</strong> is active on your Google account.<br />
                      2. If you are using a school or work account (Google Workspace), your administrator might need to enable 2-Step Verification or App Passwords in the Admin console.<br />
                      3. You can also search for "App Passwords" directly in the top search bar of your Google Account settings.
                    </p>
                  </div>
                  <div>
                    <p className="font-semibold text-dark-100">Make sure IMAP is enabled in your Gmail settings</p>
                    <p className="text-dark-400 mt-0.5">
                      In Gmail, click the gear icon &gt; <em>See all settings</em> &gt; <em>Forwarding and POP/IMAP</em> &gt; select <strong>Enable IMAP</strong> and save changes.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* SECTION 3: Credentials & Server Configuration */}
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FiSettings className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg font-semibold text-dark-100">
                {isGmail ? 'Gmail Authentication & Server Settings' : 'Mailbox Credentials'}
              </h2>
            </div>
            {isGmail && (
              <button
                type="button"
                onClick={() => setShowManualServer(!showManualServer)}
                className="text-xs text-dark-400 hover:text-dark-200 transition-colors"
              >
                {showManualServer ? 'Hide Server Details' : 'Show Server Parameters'}
              </button>
            )}
          </div>

          {/* Server status pill for Gmail */}
          {isGmail && !showManualServer && (
            <div className="p-3.5 bg-dark-900/80 border border-dark-700/80 rounded-xl flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
                  <FiCheckCircle className="w-5 h-5" />
                </div>
                <div>
                  <p className="text-xs text-dark-400">Server Configuration</p>
                  <p className="text-sm font-semibold text-dark-100">
                    imap.gmail.com <span className="text-dark-400 font-normal">: Port 993 (SSL Enabled)</span>
                  </p>
                </div>
              </div>
              <span className="text-xs font-medium px-2.5 py-1 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Auto-Managed for Gmail
              </span>
            </div>
          )}

          {/* Manual host/port fields (shown for non-Gmail or if showManualServer is toggled) */}
          {(!isGmail || showManualServer) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 p-4 bg-dark-900/50 border border-dark-700/60 rounded-xl">
              <InputField
                label="IMAP Host"
                icon={FiServer}
                helpText="Mail server domain (e.g. imap.gmail.com or outlook.office365.com)"
              >
                <input
                  type="text"
                  value={config.imapHost}
                  onChange={(e) => handleChange('imapHost', e.target.value)}
                  onBlur={() => handleBlur('imapHost')}
                  placeholder="imap.example.com"
                  className={`w-full bg-dark-900 border rounded-lg px-4 py-2.5 text-sm text-dark-100 placeholder:text-dark-500 focus:outline-none focus:ring-1 transition-colors ${
                    touched.imapHost && errors.imapHost
                      ? 'border-rose-500 focus:border-rose-500 focus:ring-rose-500'
                      : 'border-dark-700 focus:border-cyan-500 focus:ring-cyan-500'
                  }`}
                />
                {touched.imapHost && errors.imapHost && (
                  <p className="text-xs text-rose-400 mt-1">{errors.imapHost}</p>
                )}
              </InputField>

              <InputField label="IMAP Port" icon={FiServer} helpText="Default 993 for secure IMAP over SSL">
                <input
                  type="number"
                  value={config.imapPort}
                  onChange={(e) => handleChange('imapPort', e.target.value)}
                  onBlur={() => handleBlur('imapPort')}
                  min={1}
                  max={65535}
                  className={`w-full bg-dark-900 border rounded-lg px-4 py-2.5 text-sm text-dark-100 focus:outline-none focus:ring-1 transition-colors ${
                    touched.imapPort && errors.imapPort
                      ? 'border-rose-500 focus:border-rose-500 focus:ring-rose-500'
                      : 'border-dark-700 focus:border-cyan-500 focus:ring-cyan-500'
                  }`}
                />
                {touched.imapPort && errors.imapPort && (
                  <p className="text-xs text-rose-400 mt-1">{errors.imapPort}</p>
                )}
              </InputField>

              <div className="md:col-span-2">
                <InputField label="Use SSL" icon={FiLock}>
                  <ToggleSwitch
                    enabled={config.useSSL}
                    onChange={(val) => handleChange('useSSL', val)}
                    label={config.useSSL ? 'SSL/TLS enabled (Port 993)' : 'SSL/TLS disabled'}
                  />
                </InputField>
              </div>
            </div>
          )}

          {/* Username & Password */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <InputField
              label={isGmail ? 'Gmail Address' : 'Username / Email'}
              icon={isGmail ? FiMail : FiKey}
              helpText={
                isGmail
                  ? 'Your full Google email (e.g. yourname@gmail.com)'
                  : 'Mailbox username or email address'
              }
            >
              <input
                type="text"
                value={config.username}
                onChange={(e) => handleChange('username', e.target.value)}
                onBlur={() => handleBlur('username')}
                placeholder={isGmail ? 'you@gmail.com' : 'you@example.com'}
                className={`w-full bg-dark-900 border rounded-lg px-4 py-2.5 text-sm text-dark-100 placeholder:text-dark-500 focus:outline-none focus:ring-1 transition-colors ${
                  touched.username && errors.username
                    ? 'border-rose-500 focus:border-rose-500 focus:ring-rose-500'
                    : 'border-dark-700 focus:border-cyan-500 focus:ring-cyan-500'
                }`}
              />
              {touched.username && errors.username && (
                <p className="text-xs text-rose-400 mt-1">{errors.username}</p>
              )}
            </InputField>

            <InputField
              label={isGmail ? 'Google App Password' : 'Password'}
              icon={FiLock}
              extraBadge={
                hasSavedPassword && !config.password ? (
                  <span className="text-[11px] font-semibold text-emerald-400 flex items-center gap-1 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
                    <FiCheck className="w-3 h-3" /> App Password Saved
                  </span>
                ) : !hasSavedPassword && !config.password ? (
                  <span className="text-[11px] font-semibold text-rose-400 flex items-center gap-1 bg-rose-500/10 px-2 py-0.5 rounded-full border border-rose-500/20">
                    <FiAlertTriangle className="w-3 h-3" /> App Password Required
                  </span>
                ) : isGmail && passwordLength > 0 ? (
                  passwordLength === 16 && !isStandardPassword ? (
                    <span className="text-[11px] font-semibold text-emerald-400 flex items-center gap-1">
                      <FiCheck className="w-3.5 h-3.5" /> 16 letters (Valid)
                    </span>
                  ) : isStandardPassword ? (
                    <span className="text-[11px] text-amber-400 font-semibold flex items-center gap-1">
                      <FiAlertTriangle className="w-3 h-3" /> Not an App Password
                    </span>
                  ) : passwordLength < 16 ? (
                    <span className="text-[11px] text-amber-400">
                      {16 - passwordLength} chars remaining
                    </span>
                  ) : (
                    <span className="text-[11px] text-rose-400">
                      {passwordLength} chars (expected 16)
                    </span>
                  )
                ) : null
              }
              helpText={
                isGmail
                  ? hasSavedPassword
                    ? 'Leave blank to preserve current securely saved App Password, or enter a new 16-letter code to update.'
                    : '16-letter code from Google. Spaces are stripped automatically.'
                  : hasSavedPassword
                  ? 'Leave blank to preserve current saved password'
                  : 'Enter mailbox password'
              }
            >
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={config.password}
                  onChange={(e) => handleChange('password', e.target.value)}
                  onBlur={() => handleBlur('password')}
                  placeholder={
                    hasSavedPassword
                      ? '•••••••••••••••• (Saved securely on server - leave blank to keep)'
                      : isGmail
                      ? '16-character code (e.g. abcd efgh ijkl mnop)'
                      : 'Enter password'
                  }
                  autoComplete="new-password"
                  className={`w-full bg-dark-900 border rounded-lg px-4 py-2.5 pr-10 text-sm text-dark-100 placeholder:text-dark-500 font-mono focus:outline-none focus:ring-1 transition-colors ${
                    isStandardPassword
                      ? 'border-amber-500 focus:border-amber-500 focus:ring-amber-500'
                      : touched.password && errors.password
                      ? 'border-rose-500 focus:border-rose-500 focus:ring-rose-500'
                      : 'border-dark-700 focus:border-cyan-500 focus:ring-cyan-500'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-400 hover:text-dark-200 transition-colors"
                >
                  {showPassword ? <FiEyeOff className="w-4 h-4" /> : <FiEye className="w-4 h-4" />}
                </button>
              </div>

              {/* Live Warning for Standard Passwords */}
              {isGmail && isStandardPassword && (
                <div className="mt-2 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-start gap-2">
                  <FiAlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <strong>Standard Password Detected:</strong> Google strictly blocks regular passwords on IMAP for security. You must generate a 16-letter App Password at <code>myaccount.google.com/apppasswords</code>.
                  </div>
                </div>
              )}

              {hasSavedPassword && !config.password && (
                <p className="text-xs text-emerald-400 mt-1 flex items-center gap-1">
                  <FiCheck className="w-3.5 h-3.5" /> App Password configured securely on server (leave blank to keep)
                </p>
              )}
              {!hasSavedPassword && !config.password && (
                <p className="text-xs text-rose-400 mt-1 flex items-center gap-1">
                  <FiAlertTriangle className="w-3.5 h-3.5" /> App Password required to connect mailbox
                </p>
              )}
              {touched.password && errors.password && (
                <p className="text-xs text-rose-400 mt-1">{errors.password}</p>
              )}
            </InputField>
          </div>
        </div>

        {/* SECTION 4: Monitoring Tuning */}
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 space-y-5">
          <div className="flex items-center gap-2 mb-2">
            <FiClock className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-dark-100">
              Monitoring Schedule &amp; Protection Rules
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <InputField
              label="Polling Interval"
              icon={FiClock}
              helpText="How frequently the background worker checks for new emails"
            >
              <select
                value={config.pollingInterval}
                onChange={(e) => handleChange('pollingInterval', parseInt(e.target.value, 10))}
                className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-2.5 text-sm text-dark-100 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors appearance-none cursor-pointer"
              >
                {POLLING_INTERVALS.map((interval) => (
                  <option key={interval.value} value={interval.value}>
                    {interval.label}
                  </option>
                ))}
              </select>
            </InputField>

            <InputField
              label="Folders to Monitor"
              icon={FiMail}
              helpText="Comma-separated folder names (e.g. INBOX, Spam, Junk)"
            >
              <input
                type="text"
                value={config.folders}
                onChange={(e) => handleChange('folders', e.target.value)}
                onBlur={() => handleBlur('folders')}
                placeholder="INBOX, Sent, Spam"
                className={`w-full bg-dark-900 border rounded-lg px-4 py-2.5 text-sm text-dark-100 placeholder:text-dark-500 focus:outline-none focus:ring-1 transition-colors ${
                  touched.folders && errors.folders
                    ? 'border-rose-500 focus:border-rose-500 focus:ring-rose-500'
                    : 'border-dark-700 focus:border-cyan-500 focus:ring-cyan-500'
                }`}
              />
              {touched.folders && errors.folders && (
                <p className="text-xs text-rose-400 mt-1">{errors.folders}</p>
              )}
            </InputField>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-2">
            <InputField
              label={`Max Attachment Size: ${config.maxAttachmentSizeMB} MB`}
              icon={FiServer}
              helpText="Attachments exceeding this size are safely skipped to avoid memory exhaustion"
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
                <span className="text-sm font-semibold text-cyan-400 w-16 text-right font-mono">
                  {config.maxAttachmentSizeMB} MB
                </span>
              </div>
            </InputField>

            <InputField
              label={`Auto-Quarantine Threshold: ${config.autoQuarantineThreshold}%`}
              icon={FiAlertTriangle}
              helpText="Emails or attachments scoring above this risk score are quarantined immediately"
            >
              <div className="space-y-1.5">
                <div className="flex items-center gap-4">
                  <input
                    type="range"
                    min={0}
                    max={100}
                    value={config.autoQuarantineThreshold}
                    onChange={(e) =>
                      handleChange('autoQuarantineThreshold', parseInt(e.target.value, 10))
                    }
                    className="flex-1 h-2 bg-dark-700 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                  />
                  <span className="text-sm font-semibold text-cyan-400 w-16 text-right font-mono">
                    {config.autoQuarantineThreshold}%
                  </span>
                </div>
                <div className="flex justify-between text-[11px] text-dark-500">
                  <span>0% (Quarantine all)</span>
                  <span>70% (Standard)</span>
                  <span>100% (Strict)</span>
                </div>
              </div>
            </InputField>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-2">
          <button
            onClick={loadConfig}
            className="flex items-center gap-2 px-4 py-2 bg-dark-800 hover:bg-dark-700 text-dark-300 rounded-lg text-sm font-medium border border-dark-700 transition-colors"
          >
            <FiRefreshCw className="w-4 h-4" />
            Reload Saved
          </button>

          <div className="flex items-center gap-3">
            <button
              onClick={handleTestConnection}
              disabled={isTesting}
              className="flex items-center gap-2 px-5 py-2.5 bg-dark-700 hover:bg-dark-600 disabled:bg-dark-700/60 disabled:cursor-not-allowed text-dark-100 rounded-lg text-sm font-medium border border-dark-600 transition-colors"
            >
              {isTesting ? (
                <FiRefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
              ) : (
                <FiKey className="w-4 h-4 text-cyan-400" />
              )}
              {isTesting ? 'Testing...' : 'Test Connection'}
            </button>
            <button
              onClick={handleSave}
              disabled={isSaving}
              className="flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-semibold shadow-md shadow-cyan-950/30 transition-all"
            >
              <FiCheckCircle className="w-4 h-4" />
              {isSaving ? 'Saving...' : 'Save Configuration'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
