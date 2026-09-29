import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';
import { emailSecurityAPI } from '../services/api';
import {
  FiMail,
  FiShield,
  FiAlertTriangle,
  FiCheckCircle,
  FiActivity,
  FiClock,
  FiEye,
  FiLock,
  FiRefreshCw,
  FiLink,
  FiServer,
  FiSettings,
  FiUpload,
  FiPlay,
  FiPause,
  FiExternalLink,
  FiCheck,
} from 'react-icons/fi';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts';

const REFRESH_INTERVAL = 10000;

const RISK_COLORS = {
  safe: '#22c55e',
  low: '#22c55e',
  low_risk: '#22c55e',
  medium: '#f59e0b',
  suspicious: '#f59e0b',
  high: '#ef4444',
  malicious: '#ef4444',
  critical: '#dc2626',
};

const PIE_COLORS = ['#22c55e', '#f59e0b', '#ef4444', '#dc2626'];

function StatCard({ icon: Icon, label, value, color, subtext }) {
  return (
    <div className="bg-dark-800 border border-dark-700 rounded-lg p-4 flex items-center gap-4 hover:border-dark-600 transition-colors">
      <div
        className={`w-12 h-12 rounded-lg flex items-center justify-center ${color}`}
      >
        <Icon className="w-6 h-6 text-white" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-dark-400 text-sm truncate">{label}</p>
        <p className="text-dark-100 text-2xl font-bold">
          {typeof value === 'number' ? value.toLocaleString() : value}
        </p>
        {subtext && <p className="text-dark-400 text-xs mt-0.5">{subtext}</p>}
      </div>
    </div>
  );
}

function formatTimestamp(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function formatDateLabel(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function getRiskBadge(risk) {
  const r = (risk || '').toLowerCase();
  const map = {
    low: 'bg-green-500/15 text-green-400 border border-green-500/30',
    medium: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
    high: 'bg-red-500/15 text-red-400 border border-red-500/30',
    critical: 'bg-red-700/20 text-red-300 border border-red-500/40',
  };
  return map[r] || 'bg-dark-700 text-dark-400 border border-dark-600';
}

function getSeverityIcon(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical' || s === 'high') {
    return <FiAlertTriangle className="w-3.5 h-3.5 text-red-400" />;
  }
  if (s === 'medium') {
    return <FiAlertTriangle className="w-3.5 h-3.5 text-yellow-400" />;
  }
  return <FiCheckCircle className="w-3.5 h-3.5 text-green-400" />;
}

function getEventIcon(type) {
  switch ((type || '').toLowerCase()) {
    case 'phishing':
      return <FiLink className="w-4 h-4 text-yellow-400" />;
    case 'malware':
    case 'malicious attachment':
      return <FiLock className="w-4 h-4 text-red-400" />;
    case 'spam':
      return <FiMail className="w-4 h-4 text-dark-400" />;
    case 'threat':
      return <FiAlertTriangle className="w-4 h-4 text-red-400" />;
    default:
      return <FiEye className="w-4 h-4 text-cyan-400" />;
  }
}

export default function EmailSecurityDashboard() {
  const { user } = useAuth();
  const fileInputRef = useRef(null);
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [monitoringStatus, setMonitoringStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [uploadingEml, setUploadingEml] = useState(false);
  const [importingSamples, setImportingSamples] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  // Clear state immediately whenever active user account changes
  useEffect(() => {
    setStats(null);
    setEvents([]);
    setMonitoringStatus(null);
  }, [user?.id]);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, eventsRes, statusRes] = await Promise.allSettled([
        emailSecurityAPI.getStats(30),
        emailSecurityAPI.getEvents({ limit: 20 }),
        emailSecurityAPI.getMonitoringStatus(),
      ]);

      if (statsRes.status === 'fulfilled') {
        setStats(statsRes.value?.data || statsRes.value);
      }
      if (eventsRes.status === 'fulfilled') {
        const raw = eventsRes.value?.data || eventsRes.value || [];
        const eventList = raw.events || raw || [];
        setEvents(eventList.map(e => ({
          ...e,
          ...e.event_data,
          type: e.event_type,
        })));
      }
      if (statusRes.status === 'fulfilled') {
        setMonitoringStatus(statusRes.value?.data || statusRes.value);
      }

      setLastRefresh(new Date());
      setError(null);
    } catch (err) {
      console.error('Failed to fetch email security data:', err);
      setError('Failed to load dashboard data. Retrying...');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Precise monitoring calculation for THIS user
  const configured = Boolean(monitoringStatus?.configured || monitoringStatus?.username);
  const isActive = Boolean(monitoringStatus?.is_active);
  const monStatus = (monitoringStatus?.monitoring_status || '').toLowerCase();
  const connStatus = (monitoringStatus?.connection_status || '').toLowerCase();
  const lastError = monitoringStatus?.last_error;

  const isMonitoring = isActive && (monStatus === 'active' || connStatus === 'connected');
  const isConnecting = isActive && (monStatus === 'starting' || (!lastError && connStatus === 'unknown'));
  const isError = monStatus === 'error' || connStatus === 'error' || Boolean(lastError);
  const isPaused = configured && !isActive;
  const isNotConfigured = !configured || monStatus === 'not_configured';
  const monitorLastCheck = monitoringStatus?.last_check || monitoringStatus?.last_check_at || null;

  const handleScanEmlFile = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.eml')) {
      toast.error('Please select an email file (.eml)');
      return;
    }
    const formData = new FormData();
    formData.append('file', file);
    setUploadingEml(true);
    const toastId = toast.loading('Analyzing email headers, attachments, and URLs...');
    try {
      const res = await emailSecurityAPI.scan(formData);
      const classification = res.data?.classification || 'analyzed';
      toast.success(`Email scanned successfully! Classification: ${classification.toUpperCase()}`, { id: toastId });
      fetchData();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to scan email', { id: toastId });
    } finally {
      setUploadingEml(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleImportSamples = async () => {
    if (!window.confirm('Import pre-scanned sample safe and phishing emails to explore this dashboard?')) return;
    setImportingSamples(true);
    const toastId = toast.loading('Importing sample safe and phishing emails...');
    try {
      await emailSecurityAPI.importEmailFolder();
      toast.success('Sample emails imported successfully into your account!', { id: toastId });
      fetchData();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to import sample emails', { id: toastId });
    } finally {
      setImportingSamples(false);
    }
  };

  const handleToggleMonitoring = async () => {
    setActionLoading(true);
    try {
      if (isMonitoring) {
        await emailSecurityAPI.stopMonitoring();
        toast.success('Email monitoring paused');
      } else {
        await emailSecurityAPI.startMonitoring();
        toast.success('Email monitoring started');
      }
      fetchData();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to update monitoring status');
    } finally {
      setActionLoading(false);
    }
  };

  const threatsByDay = (() => {
    if (stats?.threats_by_day && Array.isArray(stats.threats_by_day)) {
      return stats.threats_by_day.map((d) => ({
        date: d.date ? formatDateLabel(d.date) : d.label || d.day || '—',
        threats: d.count ?? d.threats ?? 0,
        phishing: d.phishing ?? 0,
        malware: d.malware ?? 0,
      }));
    }
    if (stats?.daily_threats && Array.isArray(stats.daily_threats)) {
      return stats.daily_threats.map((d) => ({
        date: d.date ? formatDateLabel(d.date) : d.label || '—',
        threats: d.count ?? d.threats ?? 0,
        phishing: d.phishing ?? 0,
        malware: d.malware ?? 0,
      }));
    }
    return [];
  })();

  const riskDistribution = (() => {
    if (stats?.risk_distribution && Array.isArray(stats.risk_distribution)) {
      return stats.risk_distribution.map((d) => ({
        name: d.risk || d.name || d.level || 'unknown',
        value: d.count ?? d.value ?? 0,
      }));
    }
    if (stats?.risk_distribution_map && typeof stats.risk_distribution_map === 'object') {
      return Object.entries(stats.risk_distribution_map).map(([key, val]) => ({
        name: key,
        value: val,
      }));
    }
    return [
      { name: 'safe', value: stats?.safe ?? 0 },
      { name: 'suspicious', value: stats?.suspicious ?? 0 },
      { name: 'malicious', value: stats?.malicious ?? 0 },
      { name: 'critical', value: stats?.critical ?? 0 },
    ].filter((d) => d.value > 0);
  })();

  const topDomains = (() => {
    if (stats?.top_threat_senders && Array.isArray(stats.top_threat_senders)) {
      return stats.top_threat_senders.map(d => ({ domain: d.domain, threats: d.count, risk: 'high' }));
    }
    if (stats?.top_suspicious_domains && Array.isArray(stats.top_suspicious_domains)) {
      return stats.top_suspicious_domains;
    }
    if (stats?.suspicious_domains && Array.isArray(stats.suspicious_domains)) {
      return stats.suspicious_domains;
    }
    return [];
  })();

  const emailsMonitored = stats?.total_scanned ?? stats?.emails_monitored ?? stats?.total_emails ?? 0;
  const attachmentsScanned = stats?.total_attachments ?? stats?.attachments_scanned ?? 0;
  const threatsDetected = stats?.total_threats ?? stats?.threats_detected ?? 0;
  const phishingEmails = stats?.suspicious ?? stats?.phishing_emails ?? stats?.phishing ?? 0;
  const suspiciousUrls = stats?.suspicious_urls ?? stats?.suspicious_links ?? 0;
  const criticalAlerts = stats?.critical ?? stats?.critical_alerts ?? 0;
  const quarantined = stats?.quarantined ?? stats?.quarantined_emails ?? 0;
  const safeEmails = stats?.safe ?? stats?.safe_emails ?? 0;

  if (loading) {
    return (
      <div className="min-h-screen bg-dark-900 flex items-center justify-center">
        <div className="text-center">
          <FiRefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-3" />
          <p className="text-dark-400 text-sm">Loading Email Security Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-dark-900 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
            <FiShield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-dark-100 text-2xl font-bold tracking-tight">
              Email Security Dashboard
            </h1>
            <p className="text-dark-400 text-sm">
              Security Operations Center — Real-time Email Threat Monitoring
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-dark-400 text-xs flex items-center gap-1.5 hidden sm:inline-flex">
              <FiClock className="w-3.5 h-3.5" />
              Updated {formatTimestamp(lastRefresh)}
            </span>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml"
            className="hidden"
            onChange={handleScanEmlFile}
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={uploadingEml}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 text-xs font-semibold transition-colors disabled:opacity-50"
            title="Upload and scan an email (.eml) file"
          >
            <FiUpload className="w-3.5 h-3.5" />
            {uploadingEml ? 'Scanning...' : 'Scan .EML'}
          </button>
          <button
            onClick={fetchData}
            className="p-2 rounded-lg border border-dark-700 bg-dark-800 text-dark-400 hover:text-dark-100 hover:border-dark-600 transition-colors"
            title="Refresh now"
          >
            <FiRefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 flex items-center gap-3">
          <FiAlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {/* Monitoring Status Banner */}
      <div
        className={`rounded-lg px-5 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 border transition-all ${
          isMonitoring
            ? 'bg-green-500/10 border-green-500/30'
            : isError
            ? 'bg-red-500/10 border-red-500/30'
            : isConnecting
            ? 'bg-yellow-500/10 border-yellow-500/30'
            : isPaused
            ? 'bg-amber-500/10 border-amber-500/30'
            : 'bg-cyan-500/10 border-cyan-500/30'
        }`}
      >
        <div className="flex items-center gap-3">
          <div
            className={`relative flex items-center justify-center w-3 h-3 rounded-full shrink-0 ${
              isMonitoring
                ? 'bg-green-400'
                : isError
                ? 'bg-red-500'
                : isConnecting
                ? 'bg-yellow-400'
                : isPaused
                ? 'bg-amber-400'
                : 'bg-cyan-400'
            }`}
          >
            {(isMonitoring || isConnecting) && (
              <span
                className={`absolute inline-flex w-full h-full rounded-full opacity-75 animate-ping ${
                  isMonitoring ? 'bg-green-400' : 'bg-yellow-400'
                }`}
              />
            )}
            <span
              className={`relative inline-flex w-3 h-3 rounded-full ${
                isMonitoring
                  ? 'bg-green-400'
                  : isError
                  ? 'bg-red-500'
                  : isConnecting
                  ? 'bg-yellow-400'
                  : isPaused
                  ? 'bg-amber-400'
                  : 'bg-cyan-400'
              }`}
            />
          </div>
          <FiServer
            className={`w-4 h-4 shrink-0 ${
              isMonitoring
                ? 'text-green-400'
                : isError
                ? 'text-red-400'
                : isConnecting
                ? 'text-yellow-400'
                : isPaused
                ? 'text-amber-400'
                : 'text-cyan-400'
            }`}
          />
          <div>
            <div className="flex items-center gap-2">
              <span
                className={`text-sm font-semibold ${
                  isMonitoring
                    ? 'text-green-400'
                    : isError
                    ? 'text-red-400'
                    : isConnecting
                    ? 'text-yellow-400'
                    : isPaused
                    ? 'text-amber-400'
                    : 'text-cyan-400'
                }`}
              >
                Email Monitoring:{' '}
                {isMonitoring
                  ? 'ACTIVE'
                  : isError
                  ? 'CONNECTION ERROR'
                  : isConnecting
                  ? 'CONNECTING'
                  : isPaused
                  ? 'PAUSED'
                  : 'NOT CONFIGURED'}
              </span>
              {isMonitoring && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-green-500/20 text-green-400 border border-green-500/30">
                  LIVE
                </span>
              )}
            </div>
            <p className="text-dark-400 text-xs mt-0.5">
              {isMonitoring
                ? `Actively monitoring ${monitoringStatus?.username || 'inbox'} — polling every ${monitoringStatus?.polling_interval_seconds || 60}s`
                : isError
                ? (lastError || 'Authentication failed. Please verify your Google App Password in Email Settings.')
                : isConnecting
                ? 'Establishing secure IMAP connection to mail server...'
                : isPaused
                ? 'Monitoring is currently paused for this account.'
                : 'Connect your Gmail account (or IMAP) with a Google App Password to enable automated inbox scanning.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          {monitorLastCheck && isMonitoring && (
            <span className="text-dark-400 text-xs flex items-center gap-1.5 hidden md:inline-flex">
              <FiActivity className="w-3.5 h-3.5" />
              Last check: {formatTimestamp(monitorLastCheck)}
            </span>
          )}
          {isMonitoring ? (
            <div className="flex items-center gap-2">
              <button
                onClick={() => navigate('/email-live-monitor')}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-dark-800 hover:bg-dark-700 text-dark-200 border border-dark-700 rounded-lg text-xs font-medium transition-colors"
              >
                <FiActivity className="w-3.5 h-3.5 text-cyan-400" />
                Live Feed
              </button>
              <button
                onClick={() => navigate('/email-settings')}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-dark-800 hover:bg-dark-700 text-dark-300 border border-dark-700 rounded-lg text-xs font-medium transition-colors"
              >
                <FiSettings className="w-3.5 h-3.5" />
                Settings
              </button>
            </div>
          ) : isPaused ? (
            <div className="flex items-center gap-2">
              <button
                onClick={handleToggleMonitoring}
                disabled={actionLoading}
                className="flex items-center gap-1.5 px-3.5 py-1.5 bg-green-600 hover:bg-green-500 text-white rounded-lg text-xs font-medium transition-colors"
              >
                <FiPlay className="w-3.5 h-3.5" />
                {actionLoading ? 'Starting...' : 'Resume'}
              </button>
              <button
                onClick={() => navigate('/email-settings')}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-dark-800 hover:bg-dark-700 text-dark-300 border border-dark-700 rounded-lg text-xs font-medium transition-colors"
              >
                <FiSettings className="w-3.5 h-3.5" />
                Settings
              </button>
            </div>
          ) : (
            <button
              onClick={() => navigate('/email-settings')}
              className={`flex items-center gap-2 px-4 py-2 text-white rounded-lg text-xs font-semibold transition-colors ${
                isError ? 'bg-red-600 hover:bg-red-700 shadow-md shadow-red-900/30' : 'bg-cyan-600 hover:bg-cyan-700 shadow-md shadow-cyan-900/30'
              }`}
            >
              <FiSettings className="w-3.5 h-3.5" />
              {isError ? 'Fix in Email Settings' : 'Configure Mailbox'}
            </button>
          )}
        </div>
      </div>

      {/* Stat Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-4 gap-4">
        <StatCard
          icon={FiMail}
          label="Emails Monitored"
          value={emailsMonitored}
          color="bg-cyan-500/15 border border-cyan-500/30"
        />
        <StatCard
          icon={FiEye}
          label="Attachments Scanned"
          value={attachmentsScanned}
          color="bg-blue-500/15 border border-blue-500/30"
        />
        <StatCard
          icon={FiAlertTriangle}
          label="Threats Detected"
          value={threatsDetected}
          color="bg-red-500/15 border border-red-500/30"
        />
        <StatCard
          icon={FiLink}
          label="Phishing Emails"
          value={phishingEmails}
          color="bg-yellow-500/15 border border-yellow-500/30"
        />
        <StatCard
          icon={FiLock}
          label="Suspicious URLs"
          value={suspiciousUrls}
          color="bg-orange-500/15 border border-orange-500/30"
        />
        <StatCard
          icon={FiAlertTriangle}
          label="Critical Alerts"
          value={criticalAlerts}
          color="bg-red-600/15 border border-red-600/30"
        />
        <StatCard
          icon={FiShield}
          label="Quarantined"
          value={quarantined}
          color="bg-purple-500/15 border border-purple-500/30"
        />
        <StatCard
          icon={FiCheckCircle}
          label="Safe Emails"
          value={safeEmails}
          color="bg-green-500/15 border border-green-500/30"
        />
      </div>

      {/* Empty-State Action Banner when 0 emails monitored */}
      {emailsMonitored === 0 && (
        <div className="bg-dark-800/80 border border-dark-700 rounded-xl p-6 shadow-lg">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="space-y-2 text-center md:text-left">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <FiShield className="w-3.5 h-3.5" />
                Multi-User Isolated Email Security
              </div>
              <h3 className="text-lg font-bold text-dark-100">
                No Monitored Emails Yet in This Account
              </h3>
              <p className="text-dark-400 text-sm max-w-xl">
                Each account's email security data is strictly separated. To start monitoring and see your safe and suspicious emails:
              </p>
              <ul className="text-xs text-dark-300 space-y-1 list-disc list-inside">
                <li><strong>Automated:</strong> Connect your mailbox in Email Settings with your email and 16-character Google App Password.</li>
                <li><strong>Direct Scan:</strong> Click "Upload & Scan .EML" to scan any exported email file instantly.</li>
                <li><strong>Demo:</strong> Load sample pre-scanned emails into your account to test the dashboard.</li>
              </ul>
            </div>

            <div className="flex flex-col sm:flex-row md:flex-col gap-2.5 w-full md:w-auto shrink-0">
              <button
                onClick={() => navigate('/email-settings')}
                className="flex items-center justify-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-semibold transition-all shadow-md shadow-cyan-900/30"
              >
                <FiSettings className="w-4 h-4" />
                Configure Mailbox
              </button>
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={uploadingEml}
                className="flex items-center justify-center gap-2 px-4 py-2.5 bg-dark-700 hover:bg-dark-600 text-dark-100 border border-dark-600 rounded-lg text-sm font-medium transition-colors"
              >
                <FiUpload className="w-4 h-4 text-cyan-400" />
                {uploadingEml ? 'Scanning Email...' : 'Upload & Scan .EML'}
              </button>
              <button
                onClick={handleImportSamples}
                disabled={importingSamples}
                className="flex items-center justify-center gap-2 px-4 py-2 bg-dark-800 hover:bg-dark-700 text-dark-300 border border-dark-700 rounded-lg text-xs font-medium transition-colors"
              >
                <FiMail className="w-3.5 h-3.5 text-green-400" />
                {importingSamples ? 'Importing Samples...' : 'Load Sample Emails'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threats Over Time - Line Chart */}
        <div className="lg:col-span-2 bg-dark-800 border border-dark-700 rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <FiActivity className="w-4 h-4 text-cyan-400" />
              <h2 className="text-dark-100 font-semibold text-sm">
                Threats Over Time
              </h2>
            </div>
            <span className="text-dark-400 text-xs">Last 30 days</span>
          </div>
          {threatsByDay.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={threatsByDay}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="date"
                  tick={{ fill: '#64748b', fontSize: 11 }}
                  axisLine={{ stroke: '#334155' }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#64748b', fontSize: 11 }}
                  axisLine={{ stroke: '#334155' }}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                    fontSize: 12,
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="threats"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  dot={{ fill: '#06b6d4', r: 3 }}
                  activeDot={{ r: 5, stroke: '#06b6d4', strokeWidth: 2 }}
                  name="Total Threats"
                />
                <Line
                  type="monotone"
                  dataKey="phishing"
                  stroke="#f59e0b"
                  strokeWidth={2}
                  dot={{ fill: '#f59e0b', r: 2 }}
                  activeDot={{ r: 4, stroke: '#f59e0b', strokeWidth: 2 }}
                  name="Phishing"
                />
                <Line
                  type="monotone"
                  dataKey="malware"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={{ fill: '#ef4444', r: 2 }}
                  activeDot={{ r: 4, stroke: '#ef4444', strokeWidth: 2 }}
                  name="Malware"
                />
                <Legend
                  wrapperStyle={{ fontSize: 11, color: '#94a3b8' }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[280px] flex items-center justify-center">
              <p className="text-dark-400 text-sm">No threat data available</p>
            </div>
          )}
        </div>

        {/* Risk Distribution - Pie Chart */}
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-5">
          <div className="flex items-center gap-2 mb-4">
            <FiShield className="w-4 h-4 text-cyan-400" />
            <h2 className="text-dark-100 font-semibold text-sm">
              Risk Distribution
            </h2>
          </div>
          {riskDistribution.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={riskDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={90}
                  paddingAngle={4}
                  dataKey="value"
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                  labelLine={{ stroke: '#64748b' }}
                >
                  {riskDistribution.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={
                        RISK_COLORS[entry.name.toLowerCase()] ||
                        PIE_COLORS[index % PIE_COLORS.length]
                      }
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                    fontSize: 12,
                  }}
                  formatter={(value) => [value.toLocaleString(), 'Count']}
                />
                <Legend
                  wrapperStyle={{ fontSize: 11, color: '#94a3b8' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[280px] flex items-center justify-center">
              <p className="text-dark-400 text-sm">No risk data available</p>
            </div>
          )}
        </div>
      </div>

      {/* Bottom Row: Events Feed + Top Domains */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Live Event Feed */}
        <div className="lg:col-span-3 bg-dark-800 border border-dark-700 rounded-lg">
          <div className="flex items-center justify-between px-5 py-4 border-b border-dark-700">
            <div className="flex items-center gap-2">
              <div className="relative">
                <FiActivity className="w-4 h-4 text-cyan-400" />
                <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-green-400 rounded-full animate-pulse" />
              </div>
              <h2 className="text-dark-100 font-semibold text-sm">
                Live Event Feed
              </h2>
            </div>
            <span className="text-dark-400 text-xs">
              {events.length} events
            </span>
          </div>
          <div className="divide-y divide-dark-700 max-h-[520px] overflow-y-auto">
            {events.length > 0 ? (
              events.map((event, idx) => (
                <div
                  key={event.id || event._id || idx}
                  className="px-5 py-3 flex items-start gap-3 hover:bg-dark-700/40 transition-colors"
                >
                  <div className="mt-0.5 flex-shrink-0">
                    {getEventIcon(event.type || event.event_type || event.category)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-dark-100 text-sm font-medium truncate">
                        {event.subject || event.title || event.message || 'Email Event'}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-medium flex-shrink-0 ${getRiskBadge(
                          event.risk || event.risk_level || event.severity || 'low'
                        )}`}
                      >
                        {(event.risk || event.risk_level || event.severity || 'low').toUpperCase()}
                      </span>
                      {getSeverityIcon(event.severity || event.risk_level || event.risk)}
                    </div>
                    <div className="flex items-center gap-3 text-dark-400 text-xs">
                      <span>{event.sender || event.from || '—'}</span>
                      {event.domain && (
                        <>
                          <span>·</span>
                          <span className="text-dark-300">{event.domain}</span>
                        </>
                      )}
                      {event.type && (
                        <>
                          <span>·</span>
                          <span className="capitalize">{event.type || event.event_type}</span>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="flex-shrink-0 text-right">
                    <span className="text-dark-400 text-xs flex items-center gap-1">
                      <FiClock className="w-3 h-3" />
                      {formatTimestamp(event.timestamp || event.created_at || event.time)}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="px-5 py-12 text-center">
                <FiMail className="w-8 h-8 text-dark-600 mx-auto mb-2" />
                <p className="text-dark-400 text-sm">No events to display</p>
              </div>
            )}
          </div>
        </div>

        {/* Top Suspicious Domains */}
        <div className="lg:col-span-2 bg-dark-800 border border-dark-700 rounded-lg">
          <div className="flex items-center justify-between px-5 py-4 border-b border-dark-700">
            <div className="flex items-center gap-2">
              <FiLink className="w-4 h-4 text-cyan-400" />
              <h2 className="text-dark-100 font-semibold text-sm">
                Top Suspicious Domains
              </h2>
            </div>
            <span className="text-dark-400 text-xs">
              {topDomains.length} domains
            </span>
          </div>
          <div className="overflow-hidden">
            {topDomains.length > 0 ? (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-dark-700">
                    <th className="text-left text-dark-400 text-xs font-medium px-5 py-3 uppercase tracking-wider">
                      Domain
                    </th>
                    <th className="text-right text-dark-400 text-xs font-medium px-5 py-3 uppercase tracking-wider">
                      Threats
                    </th>
                    <th className="text-right text-dark-400 text-xs font-medium px-5 py-3 uppercase tracking-wider">
                      Risk
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-700">
                  {topDomains.map((domain, idx) => (
                    <tr
                      key={domain.domain || domain.name || idx}
                      className="hover:bg-dark-700/40 transition-colors"
                    >
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-dark-500 font-mono w-5">
                            {idx + 1}.
                          </span>
                          <span className="text-dark-100 text-sm font-medium truncate max-w-[180px]">
                            {domain.domain || domain.name || '—'}
                          </span>
                        </div>
                      </td>
                      <td className="px-5 py-3 text-right">
                        <span className="text-dark-100 text-sm font-semibold">
                          {(domain.threats ?? domain.count ?? 0).toLocaleString()}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-right">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-medium ${getRiskBadge(
                            domain.risk || domain.risk_level || 'medium'
                          )}`}
                        >
                          {(domain.risk || domain.risk_level || 'medium').toUpperCase()}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="px-5 py-12 text-center">
                <FiShield className="w-8 h-8 text-dark-600 mx-auto mb-2" />
                <p className="text-dark-400 text-sm">No domain data available</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
