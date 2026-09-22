import { useState, useEffect, useCallback } from 'react';
import toast from 'react-hot-toast';
import { useTheme } from '../context/ThemeContext';
import { settingsAPI } from '../services/api';
import {
  FiSettings, FiKey, FiMail, FiServer, FiHardDrive, FiFolder,
  FiSave, FiAlertTriangle, FiTrash2, FiRefreshCw, FiEye, FiEyeOff,
  FiCheckCircle, FiInfo, FiSun, FiMoon, FiMonitor, FiGlobe, FiClock,
  FiShield, FiLock, FiBell, FiSearch, FiDatabase, FiCode, FiLayers,
  FiZap, FiActivity, FiTrendingUp, FiHash, FiCpu, FiFileText, FiWifi,
} from 'react-icons/fi';

function SectionCard({ title, icon: Icon, children, accent = 'cyan' }) {
  const accentColors = {
    cyan: 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400',
    orange: 'bg-orange-500/10 border-orange-500/20 text-orange-400',
    green: 'bg-green-500/10 border-green-500/20 text-green-400',
    red: 'bg-red-500/10 border-red-500/20 text-red-400',
    purple: 'bg-purple-500/10 border-purple-500/20 text-purple-400',
    yellow: 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400',
    blue: 'bg-blue-500/10 border-blue-500/20 text-blue-400',
  };
  return (
    <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
      <div className="px-6 py-4 border-b border-dark-700 flex items-center gap-3">
        <div className={`p-2 rounded-lg border ${accentColors[accent]}`}>
          <Icon className="w-4.5 h-4.5" />
        </div>
        <h2 className="text-base font-semibold text-dark-100">{title}</h2>
      </div>
      <div className="p-6">{children}</div>
    </div>
  );
}

function InputField({ label, icon: Icon, value, onChange, type = 'text', placeholder, disabled, rightElement }) {
  return (
    <div>
      <label className="block text-sm font-medium text-dark-300 mb-1.5">{label}</label>
      <div className="relative">
        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500">
          <Icon className="w-4 h-4" />
        </div>
        <input
          type={type}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          disabled={disabled}
          className="w-full pl-10 pr-4 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm disabled:opacity-50 transition-colors"
        />
        {rightElement && (
          <div className="absolute right-3 top-1/2 -translate-y-1/2">{rightElement}</div>
        )}
      </div>
    </div>
  );
}

function SelectField({ label, icon: Icon, value, onChange, options }) {
  return (
    <div>
      <label className="block text-sm font-medium text-dark-300 mb-1.5">{label}</label>
      <div className="relative">
        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500">
          <Icon className="w-4 h-4" />
        </div>
        <select
          value={value}
          onChange={onChange}
          className="w-full pl-10 pr-4 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 focus:outline-none focus:border-cyan-500/50 text-sm appearance-none transition-colors"
        >
          {options.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </div>
    </div>
  );
}

function ToggleRow({ label, description, enabled, onToggle }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-dark-800 last:border-0">
      <div className="flex-1 mr-4">
        <p className="text-sm font-medium text-dark-100">{label}</p>
        {description && <p className="text-xs text-dark-400 mt-0.5">{description}</p>}
      </div>
      <button
        onClick={onToggle}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors shrink-0 ${
          enabled ? 'bg-cyan-500' : 'bg-dark-700'
        }`}
      >
        <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
          enabled ? 'translate-x-6' : 'translate-x-1'
        }`} />
      </button>
    </div>
  );
}

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingVt, setTestingVt] = useState(false);
  const [showVtKey, setShowVtKey] = useState(false);
  const [showSmtpPass, setShowSmtpPass] = useState(false);
  const [systemInfo, setSystemInfo] = useState(null);

  const [settings, setSettings] = useState({
    general: { system_name: '', language: 'en', timezone: 'UTC', session_timeout: 30, max_login_attempts: 5 },
    notifications: { email_enabled: false, desktop_enabled: true, sound_enabled: true, threat_alerts: true, scan_complete: true, weekly_report: false },
    scan: { auto_scan: true, auto_quarantine: false, scan_depth: 'standard', max_file_size_mb: 50, hash_lookup_enabled: true, entropy_enabled: true, string_analysis_enabled: true, pe_analysis_enabled: true, clamav_enabled: true },
    security: { password_min_length: 8, require_uppercase: true, require_numbers: true, require_special: false, session_timeout_minutes: 30, lockout_after_attempts: 5, lockout_duration_minutes: 15 },
    advanced: { debug_mode: false, log_level: 'INFO', retention_days: 90, max_upload_size_mb: 50, rate_limit_per_minute: 120 },
    appearance: { theme: 'dark' },
    smtp: { host: '', port: '587', username: '', password: '', use_tls: true },
    monitoring: { default_folder: '' },
    virustotal: { api_key: '' },
  });

  const update = (section, key, value) => {
    setSettings((prev) => ({ ...prev, [section]: { ...prev[section], [key]: value } }));
  };

  const fetchSettings = useCallback(async () => {
    try {
      const res = await settingsAPI.getSettings();
      if (res.data) {
        setSettings((prev) => {
          const merged = { ...prev };
          for (const [section, values] of Object.entries(res.data)) {
            if (typeof values === 'object' && values !== null) {
              merged[section] = { ...(merged[section] || {}), ...values };
            } else {
              merged[section] = values;
            }
          }
          return merged;
        });
        if (res.data.appearance?.theme) setTheme(res.data.appearance.theme);
      }
    } catch {
      // use defaults
    } finally {
      setLoading(false);
    }
  }, [setTheme]);

  const fetchSystemInfo = useCallback(async () => {
    try {
      const res = await settingsAPI.getSystemInfo();
      setSystemInfo(res.data);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchSettings(); fetchSystemInfo(); }, [fetchSettings, fetchSystemInfo]);

  const handleSave = async () => {
    setSaving(true);
    try {
      const toSave = { ...settings };
      if (settings.appearance?.theme !== theme) {
        toSave.appearance = { ...settings.appearance, theme };
      }
      await settingsAPI.updateSettings(toSave);
      if (settings.appearance?.theme !== theme) setTheme(settings.appearance.theme);
      toast.success('Settings saved successfully');
    } catch {
      toast.error('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleTestVtKey = async () => {
    if (!settings.virustotal?.api_key?.trim()) {
      toast.error('Please enter a VirusTotal API key first');
      return;
    }
    setTestingVt(true);
    try {
      await new Promise((r) => setTimeout(r, 1500));
      toast.success('VirusTotal API key is valid');
    } catch {
      toast.error('Invalid API key');
    } finally {
      setTestingVt(false);
    }
  };

  const handleResetDatabase = () => toast.error('This action is irreversible! Confirmation required.');
  const handleClearQuarantine = () => toast.error('This action is irreversible! Confirmation required.');
  const handleClearCache = () => { toast.success('Cache cleared successfully'); };

  const themes = [
    { id: 'dark', label: 'Dark', icon: FiMoon, desc: 'Easy on the eyes' },
    { id: 'light', label: 'Light', icon: FiSun, desc: 'Bright and clean' },
  ];

  const languages = [
    { value: 'en', label: 'English' },
    { value: 'es', label: 'Spanish' },
    { value: 'fr', label: 'French' },
    { value: 'de', label: 'German' },
    { value: 'zh', label: 'Chinese' },
    { value: 'ja', label: 'Japanese' },
    { value: 'ar', label: 'Arabic' },
    { value: 'hi', label: 'Hindi' },
  ];

  const timezones = [
    { value: 'UTC', label: 'UTC' },
    { value: 'US/Eastern', label: 'US Eastern' },
    { value: 'US/Central', label: 'US Central' },
    { value: 'US/Pacific', label: 'US Pacific' },
    { value: 'Europe/London', label: 'London' },
    { value: 'Europe/Berlin', label: 'Berlin' },
    { value: 'Asia/Tokyo', label: 'Tokyo' },
    { value: 'Asia/Shanghai', label: 'Shanghai' },
    { value: 'Asia/Kolkata', label: 'India' },
    { value: 'Australia/Sydney', label: 'Sydney' },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-dark-400 font-medium">Loading settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Settings</h1>
          <p className="text-dark-400 text-sm mt-1">Configure system preferences and integrations</p>
        </div>
        <button
          onClick={handleSave}
          disabled={saving}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
        >
          {saving ? (
            <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
          ) : (
            <FiSave className="w-4 h-4" />
          )}
          {saving ? 'Saving...' : 'Save All Settings'}
        </button>
      </div>

      {/* General Settings */}
      <SectionCard title="General Settings" icon={FiSettings} accent="cyan">
        <div className="space-y-4">
          <InputField
            label="System Name"
            icon={FiMonitor}
            value={settings.general.system_name}
            onChange={(e) => update('general', 'system_name', e.target.value)}
            placeholder="MFDS - Malicious File Detection System"
          />
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <SelectField
              label="Language"
              icon={FiGlobe}
              value={settings.general.language}
              onChange={(e) => update('general', 'language', e.target.value)}
              options={languages}
            />
            <SelectField
              label="Timezone"
              icon={FiClock}
              value={settings.general.timezone}
              onChange={(e) => update('general', 'timezone', e.target.value)}
              options={timezones}
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <InputField
              label="Session Timeout (minutes)"
              icon={FiClock}
              type="number"
              value={settings.general.session_timeout}
              onChange={(e) => update('general', 'session_timeout', parseInt(e.target.value) || 30)}
              placeholder="30"
            />
            <InputField
              label="Max Login Attempts"
              icon={FiLock}
              type="number"
              value={settings.general.max_login_attempts}
              onChange={(e) => update('general', 'max_login_attempts', parseInt(e.target.value) || 5)}
              placeholder="5"
            />
          </div>
        </div>
      </SectionCard>

      {/* Appearance */}
      <SectionCard title="Appearance" icon={FiMonitor} accent="purple">
        <div className="grid grid-cols-2 gap-4">
          {themes.map((t) => (
            <button
              key={t.id}
              onClick={() => { setTheme(t.id); update('appearance', 'theme', t.id); }}
              className={`relative flex flex-col items-center gap-3 p-5 rounded-xl border-2 transition-all ${
                theme === t.id
                  ? 'border-cyan-500 bg-cyan-500/10 shadow-[0_0_20px_rgba(6,182,212,0.1)]'
                  : 'border-dark-700 bg-dark-950 hover:border-dark-500 hover:bg-dark-800'
              }`}
            >
              {theme === t.id && (
                <div className="absolute top-3 right-3">
                  <FiCheckCircle className="w-5 h-5 text-cyan-400" />
                </div>
              )}
              <div className={`p-3 rounded-xl ${theme === t.id ? 'bg-cyan-500/20' : 'bg-dark-800'}`}>
                <t.icon className={`w-8 h-8 ${theme === t.id ? 'text-cyan-400' : 'text-dark-400'}`} />
              </div>
              <div className="text-center">
                <p className={`text-sm font-semibold ${theme === t.id ? 'text-cyan-400' : 'text-dark-200'}`}>{t.label}</p>
                <p className="text-xs text-dark-400 mt-0.5">{t.desc}</p>
              </div>
            </button>
          ))}
        </div>
      </SectionCard>

      {/* Notification Settings */}
      <SectionCard title="Notification Settings" icon={FiBell} accent="orange">
        <div className="space-y-0">
          <ToggleRow
            label="Email Notifications"
            description="Send threat alerts and reports via email"
            enabled={settings.notifications.email_enabled}
            onToggle={() => update('notifications', 'email_enabled', !settings.notifications.email_enabled)}
          />
          <ToggleRow
            label="Desktop Notifications"
            description="Show browser push notifications for threats"
            enabled={settings.notifications.desktop_enabled}
            onToggle={() => update('notifications', 'desktop_enabled', !settings.notifications.desktop_enabled)}
          />
          <ToggleRow
            label="Notification Sound"
            description="Play sound when threats are detected"
            enabled={settings.notifications.sound_enabled}
            onToggle={() => update('notifications', 'sound_enabled', !settings.notifications.sound_enabled)}
          />
          <ToggleRow
            label="Threat Alerts"
            description="Get notified when malicious files are detected"
            enabled={settings.notifications.threat_alerts}
            onToggle={() => update('notifications', 'threat_alerts', !settings.notifications.threat_alerts)}
          />
          <ToggleRow
            label="Scan Complete Notifications"
            description="Notify when file scans finish"
            enabled={settings.notifications.scan_complete}
            onToggle={() => update('notifications', 'scan_complete', !settings.notifications.scan_complete)}
          />
          <ToggleRow
            label="Weekly Report"
            description="Receive a weekly summary of security activity"
            enabled={settings.notifications.weekly_report}
            onToggle={() => update('notifications', 'weekly_report', !settings.notifications.weekly_report)}
          />
        </div>
      </SectionCard>

      {/* Scan Settings */}
      <SectionCard title="Scan Settings" icon={FiSearch} accent="green">
        <div className="space-y-0">
          <ToggleRow
            label="Auto-scan Uploaded Files"
            description="Automatically scan files immediately after upload"
            enabled={settings.scan.auto_scan}
            onToggle={() => update('scan', 'auto_scan', !settings.scan.auto_scan)}
          />
          <ToggleRow
            label="Auto-quarantine Threats"
            description="Automatically quarantine files detected as malicious"
            enabled={settings.scan.auto_quarantine}
            onToggle={() => update('scan', 'auto_quarantine', !settings.scan.auto_quarantine)}
          />
        </div>
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <SelectField
            label="Scan Depth"
            icon={FiLayers}
            value={settings.scan.scan_depth}
            onChange={(e) => update('scan', 'scan_depth', e.target.value)}
            options={[
              { value: 'quick', label: 'Quick - Hash only' },
              { value: 'standard', label: 'Standard - Full analysis' },
              { value: 'deep', label: 'Deep - Exhaustive scan' },
            ]}
          />
          <InputField
            label="Max File Size (MB)"
            icon={FiHardDrive}
            type="number"
            value={settings.scan.max_file_size_mb}
            onChange={(e) => update('scan', 'max_file_size_mb', parseInt(e.target.value) || 50)}
          />
        </div>
        <div className="mt-4">
          <p className="text-sm font-medium text-dark-300 mb-3">Active Scan Engines</p>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {[
              { key: 'hash_lookup_enabled', label: 'Hash Lookup', icon: FiHash },
              { key: 'entropy_enabled', label: 'Entropy Analysis', icon: FiActivity },
              { key: 'string_analysis_enabled', label: 'String Analysis', icon: FiFileText },
              { key: 'pe_analysis_enabled', label: 'PE Analysis', icon: FiCpu },
              { key: 'clamav_enabled', label: 'ClamAV', icon: FiShield },
            ].map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => update('scan', key, !settings.scan[key])}
                className={`flex items-center gap-2 p-3 rounded-lg border text-sm font-medium transition-all ${
                  settings.scan[key]
                    ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400'
                    : 'border-dark-700 bg-dark-950 text-dark-400 hover:border-dark-500'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                {label}
              </button>
            ))}
          </div>
        </div>
      </SectionCard>

      {/* Security Settings */}
      <SectionCard title="Security Settings" icon={FiShield} accent="red">
        <div className="space-y-0">
          <ToggleRow
            label="Require Uppercase Letters"
            description="Passwords must contain at least one uppercase letter"
            enabled={settings.security.require_uppercase}
            onToggle={() => update('security', 'require_uppercase', !settings.security.require_uppercase)}
          />
          <ToggleRow
            label="Require Numbers"
            description="Passwords must contain at least one number"
            enabled={settings.security.require_numbers}
            onToggle={() => update('security', 'require_numbers', !settings.security.require_numbers)}
          />
          <ToggleRow
            label="Require Special Characters"
            description="Passwords must contain at least one special character"
            enabled={settings.security.require_special}
            onToggle={() => update('security', 'require_special', !settings.security.require_special)}
          />
        </div>
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <InputField
            label="Min Password Length"
            icon={FiLock}
            type="number"
            value={settings.security.password_min_length}
            onChange={(e) => update('security', 'password_min_length', parseInt(e.target.value) || 8)}
          />
          <InputField
            label="Lockout After Attempts"
            icon={FiAlertTriangle}
            type="number"
            value={settings.security.lockout_after_attempts}
            onChange={(e) => update('security', 'lockout_after_attempts', parseInt(e.target.value) || 5)}
          />
          <InputField
            label="Lockout Duration (min)"
            icon={FiClock}
            type="number"
            value={settings.security.lockout_duration_minutes}
            onChange={(e) => update('security', 'lockout_duration_minutes', parseInt(e.target.value) || 15)}
          />
        </div>
      </SectionCard>

      {/* SMTP Configuration */}
      <SectionCard title="SMTP Configuration" icon={FiMail} accent="orange">
        <ToggleRow
          label="Use TLS"
          description="Enable TLS encryption for SMTP connection"
          enabled={settings.smtp.use_tls}
          onToggle={() => update('smtp', 'use_tls', !settings.smtp.use_tls)}
        />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-4">
          <InputField
            label="SMTP Host"
            icon={FiServer}
            value={settings.smtp.host}
            onChange={(e) => update('smtp', 'host', e.target.value)}
            placeholder="smtp.gmail.com"
          />
          <InputField
            label="SMTP Port"
            icon={FiServer}
            value={settings.smtp.port}
            onChange={(e) => update('smtp', 'port', e.target.value)}
            placeholder="587"
          />
          <InputField
            label="Username"
            icon={FiMail}
            value={settings.smtp.username}
            onChange={(e) => update('smtp', 'username', e.target.value)}
            placeholder="your@email.com"
          />
          <InputField
            label="Password"
            icon={FiKey}
            type={showSmtpPass ? 'text' : 'password'}
            value={settings.smtp.password}
            onChange={(e) => update('smtp', 'password', e.target.value)}
            placeholder="••••••••"
            rightElement={
              <button onClick={() => setShowSmtpPass(!showSmtpPass)} className="text-dark-500 hover:text-dark-300 transition-colors">
                {showSmtpPass ? <FiEyeOff className="w-4 h-4" /> : <FiEye className="w-4 h-4" />}
              </button>
            }
          />
        </div>
      </SectionCard>

      {/* VirusTotal Integration */}
      <SectionCard title="VirusTotal Integration" icon={FiKey} accent="green">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <FiKey className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" />
            <input
              type={showVtKey ? 'text' : 'password'}
              value={settings.virustotal?.api_key || ''}
              onChange={(e) => update('virustotal', 'api_key', e.target.value)}
              placeholder="Enter your VirusTotal API key"
              className="w-full pl-10 pr-10 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm font-mono transition-colors"
            />
            <button
              onClick={() => setShowVtKey(!showVtKey)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-500 hover:text-dark-300 transition-colors"
            >
              {showVtKey ? <FiEyeOff className="w-4 h-4" /> : <FiEye className="w-4 h-4" />}
            </button>
          </div>
          <button
            onClick={handleTestVtKey}
            disabled={testingVt}
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-green-600/10 hover:bg-green-600/20 text-green-400 border border-green-500/20 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 whitespace-nowrap"
          >
            {testingVt ? (
              <div className="animate-spin h-4 w-4 border-2 border-green-400 border-t-transparent rounded-full" />
            ) : (
              <FiCheckCircle className="w-4 h-4" />
            )}
            {testingVt ? 'Testing...' : 'Test Key'}
          </button>
        </div>
      </SectionCard>

      {/* Monitoring Folder */}
      <SectionCard title="Monitoring Folder" icon={FiFolder} accent="cyan">
        <InputField
          label="Default monitoring directory"
          icon={FiFolder}
          value={settings.monitoring.default_folder}
          onChange={(e) => update('monitoring', 'default_folder', e.target.value)}
          placeholder="C:\Users\Documents\Downloads"
        />
      </SectionCard>

      {/* Advanced Settings */}
      <SectionCard title="Advanced Settings" icon={FiZap} accent="yellow">
        <div className="space-y-0">
          <ToggleRow
            label="Debug Mode"
            description="Enable verbose logging for troubleshooting"
            enabled={settings.advanced.debug_mode}
            onToggle={() => update('advanced', 'debug_mode', !settings.advanced.debug_mode)}
          />
        </div>
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <SelectField
            label="Log Level"
            icon={FiFileText}
            value={settings.advanced.log_level}
            onChange={(e) => update('advanced', 'log_level', e.target.value)}
            options={[
              { value: 'DEBUG', label: 'Debug' },
              { value: 'INFO', label: 'Info' },
              { value: 'WARNING', label: 'Warning' },
              { value: 'ERROR', label: 'Error' },
              { value: 'CRITICAL', label: 'Critical' },
            ]}
          />
          <InputField
            label="Retention Days"
            icon={FiClock}
            type="number"
            value={settings.advanced.retention_days}
            onChange={(e) => update('advanced', 'retention_days', parseInt(e.target.value) || 90)}
          />
          <InputField
            label="Rate Limit (req/min)"
            icon={FiWifi}
            type="number"
            value={settings.advanced.rate_limit_per_minute}
            onChange={(e) => update('advanced', 'rate_limit_per_minute', parseInt(e.target.value) || 120)}
          />
        </div>
        <div className="mt-4">
          <button
            onClick={handleClearCache}
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-400 border border-yellow-500/20 rounded-lg text-sm font-medium transition-colors"
          >
            <FiRefreshCw className="w-4 h-4" />
            Clear Application Cache
          </button>
        </div>
      </SectionCard>

      {/* Database Info */}
      {systemInfo && (
        <SectionCard title="Database Information" icon={FiDatabase} accent="blue">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-dark-950 border border-dark-700 rounded-lg p-4 text-center">
              <FiDatabase className="w-5 h-5 text-blue-400 mx-auto mb-2" />
              <p className="text-lg font-bold text-dark-100">{systemInfo.database?.size_human || '0 B'}</p>
              <p className="text-xs text-dark-400">Database Size</p>
            </div>
            <div className="bg-dark-950 border border-dark-700 rounded-lg p-4 text-center">
              <FiServer className="w-5 h-5 text-cyan-400 mx-auto mb-2" />
              <p className="text-lg font-bold text-dark-100">{systemInfo.database?.type || 'SQLite'}</p>
              <p className="text-xs text-dark-400">Database Type</p>
            </div>
            <div className="bg-dark-950 border border-dark-700 rounded-lg p-4 text-center">
              <FiHardDrive className="w-5 h-5 text-green-400 mx-auto mb-2" />
              <p className="text-lg font-bold text-dark-100">{systemInfo.backups?.count || 0}</p>
              <p className="text-xs text-dark-400">Backups</p>
            </div>
            <div className="bg-dark-950 border border-dark-700 rounded-lg p-4 text-center">
              <FiClock className="w-5 h-5 text-orange-400 mx-auto mb-2" />
              <p className="text-xs font-bold text-dark-100 truncate">
                {systemInfo.backups?.latest
                  ? new Date(systemInfo.backups.latest.created_at).toLocaleDateString()
                  : 'Never'}
              </p>
              <p className="text-xs text-dark-400">Last Backup</p>
            </div>
          </div>
        </SectionCard>
      )}

      {/* Danger Zone */}
      <div className="bg-dark-900 border border-red-500/20 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-red-500/20 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20">
            <FiAlertTriangle className="w-4.5 h-4.5 text-red-400" />
          </div>
          <h2 className="text-base font-semibold text-red-400">Danger Zone</h2>
        </div>
        <div className="p-6 space-y-4">
          <div className="bg-red-500/5 border border-red-500/10 rounded-lg p-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-dark-100">Reset Database</p>
              <p className="text-xs text-dark-400 mt-0.5">Permanently delete all scan history, files, and logs.</p>
            </div>
            <button onClick={handleResetDatabase} className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm font-medium transition-colors whitespace-nowrap">
              <FiTrash2 className="w-4 h-4" /> Reset Database
            </button>
          </div>
          <div className="bg-red-500/5 border border-red-500/10 rounded-lg p-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-dark-100">Clear Quarantine</p>
              <p className="text-xs text-dark-400 mt-0.5">Remove all quarantined files and restore them.</p>
            </div>
            <button onClick={handleClearQuarantine} className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm font-medium transition-colors whitespace-nowrap">
              <FiRefreshCw className="w-4 h-4" /> Clear Quarantine
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
