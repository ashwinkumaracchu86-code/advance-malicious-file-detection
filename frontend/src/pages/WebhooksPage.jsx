import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  FiLink, FiCheckCircle, FiXCircle, FiSend,
  FiRefreshCw, FiSave, FiTrash2, FiEye, FiEyeOff,
  FiArrowRight, FiZap, FiShield, FiAlertCircle,
} from 'react-icons/fi';
import { featuresAPI } from '../services/api';

const WEBHOOK_FIELDS = [
  {
    key: 'slack',
    label: 'Slack',
    icon: (
      <svg viewBox="0 0 24 24" className="w-7 h-7" fill="currentColor">
        <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zm1.271 0a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zm0 1.271a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zm-1.27 0a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.163 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.163 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.163 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zm0-1.27a2.527 2.527 0 0 1-2.52-2.523 2.527 2.527 0 0 1 2.52-2.52h6.315A2.528 2.528 0 0 1 24 15.163a2.528 2.528 0 0 1-2.522 2.523h-6.315z" />
      </svg>
    ),
    color: 'purple',
    gradient: 'from-purple-500 to-purple-700',
    bg: 'bg-purple-500/10',
    border: 'border-purple-500/30',
    text: 'text-purple-400',
    badge: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    placeholder: 'https://hooks.slack.com/services/YOUR_TEAM_ID/YOUR_CHANNEL_ID/YOUR_TOKEN',
    desc: 'Get real-time threat alerts in your Slack channels',
    example: 'Slack workspace → Apps → Incoming Webhooks → Add',
  },
  {
    key: 'discord',
    label: 'Discord',
    icon: (
      <svg viewBox="0 0 24 24" className="w-7 h-7" fill="currentColor">
        <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
      </svg>
    ),
    color: 'indigo',
    gradient: 'from-indigo-500 to-indigo-700',
    bg: 'bg-indigo-500/10',
    border: 'border-indigo-500/30',
    text: 'text-indigo-400',
    badge: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
    placeholder: 'https://discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWx',
    desc: 'Monitor threats directly in your Discord server',
    example: 'Server Settings → Integrations → Webhooks → New',
  },
  {
    key: 'custom',
    label: 'Custom HTTP',
    icon: <FiZap className="w-7 h-7" />,
    color: 'cyan',
    gradient: 'from-cyan-500 to-cyan-700',
    bg: 'bg-cyan-500/10',
    border: 'border-cyan-500/30',
    text: 'text-cyan-400',
    badge: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
    placeholder: 'https://your-api.com/webhooks/malicious-file-detection',
    desc: 'POST JSON payloads to any HTTP endpoint',
    example: 'Any URL that accepts POST with JSON body',
  },
];

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState({ slack: '', discord: '', custom: '' });
  const [configured, setConfigured] = useState({ slack: false, discord: false, custom: false });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [showUrls, setShowUrls] = useState({ slack: false, discord: false, custom: false });

  useEffect(() => { fetchStatus(); }, []);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const res = await featuresAPI.getWebhookStatus();
      const data = res.data;
      const urls = { slack: '', discord: '', custom: '' };
      const stats = { slack: false, discord: false, custom: false };
      if (data && typeof data === 'object') {
        for (const [type, info] of Object.entries(data)) {
          if (typeof info === 'object' && 'configured' in info) {
            urls[type] = info.url || '';
            stats[type] = info.configured;
          }
        }
      }
      setWebhooks(urls);
      setConfigured(stats);
    } catch {
      toast.error('Failed to load webhook status');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await featuresAPI.saveWebhookConfig(webhooks);
      toast.success('Webhook configuration saved');
      fetchStatus();
    } catch {
      toast.error('Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    try {
      const res = await featuresAPI.testWebhooks();
      const results = res.data.results || {};
      const sent = Object.entries(results).filter(([, v]) => v).map(([k]) => k);
      if (sent.length > 0) {
        toast.success(`Test alert sent to: ${sent.join(', ')}`);
      } else {
        toast.error('No webhooks have valid URLs configured');
      }
    } catch {
      toast.error('Failed to send test alert');
    } finally {
      setTesting(false);
    }
  };

  const handleClear = (key) => {
    setWebhooks({ ...webhooks, [key]: '' });
  };

  const configuredCount = Object.values(configured).filter(Boolean).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/20">
              <FiLink className="w-6 h-6 text-cyan-400" />
            </div>
            Webhook Management
          </h1>
          <p className="text-dark-400 text-sm mt-1 ml-13">Configure real-time threat alert notifications</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={fetchStatus} disabled={loading}
            className="p-2.5 rounded-xl bg-dark-800 border border-dark-700 text-dark-400 hover:text-dark-100 hover:border-dark-600 transition-all"
            title="Refresh status">
            <FiRefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button onClick={handleSave} disabled={saving || loading}
            className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-green-600 to-green-500 hover:from-green-500 hover:to-green-400 text-white rounded-xl text-sm font-semibold shadow-lg shadow-green-500/20 transition-all disabled:opacity-50">
            <FiSave className="w-4 h-4" />
            {saving ? 'Saving...' : 'Save Configuration'}
          </button>
          <button onClick={handleTest} disabled={testing || configuredCount === 0}
            className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-500 hover:from-cyan-500 hover:to-blue-400 text-white rounded-xl text-sm font-semibold shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50">
            {testing ? (
              <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
            ) : (
              <FiSend className="w-4 h-4" />
            )}
            {testing ? 'Sending...' : 'Send Test Alert'}
          </button>
        </div>
      </div>

      {loading ? (
        <div className="bg-dark-900 border border-dark-700 rounded-2xl flex items-center justify-center h-64">
          <div className="text-center">
            <div className="animate-spin h-10 w-10 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
            <p className="text-dark-400 text-sm font-medium">Loading webhook status...</p>
          </div>
        </div>
      ) : (
        <>
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5 hover:border-dark-600 transition-colors">
              <div className="flex items-center gap-4">
                <div className="p-3 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/20">
                  <FiLink className="w-6 h-6 text-cyan-400" />
                </div>
                <div>
                  <p className="text-3xl font-bold text-dark-100">{WEBHOOK_FIELDS.length}</p>
                  <p className="text-xs text-dark-400 font-medium mt-0.5">Total Endpoints</p>
                </div>
              </div>
            </div>
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5 hover:border-dark-600 transition-colors">
              <div className="flex items-center gap-4">
                <div className="p-3 rounded-xl bg-gradient-to-br from-green-500/20 to-emerald-500/20 border border-green-500/20">
                  <FiCheckCircle className="w-6 h-6 text-green-400" />
                </div>
                <div>
                  <p className="text-3xl font-bold text-green-400">{configuredCount}</p>
                  <p className="text-xs text-dark-400 font-medium mt-0.5">Active</p>
                </div>
              </div>
            </div>
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5 hover:border-dark-600 transition-colors">
              <div className="flex items-center gap-4">
                <div className="p-3 rounded-xl bg-gradient-to-br from-red-500/20 to-orange-500/20 border border-red-500/20">
                  <FiXCircle className="w-6 h-6 text-red-400" />
                </div>
                <div>
                  <p className="text-3xl font-bold text-red-400">{WEBHOOK_FIELDS.length - configuredCount}</p>
                  <p className="text-xs text-dark-400 font-medium mt-0.5">Inactive</p>
                </div>
              </div>
            </div>
          </div>

          {/* Webhook Config Cards */}
          <div className="space-y-4">
            {WEBHOOK_FIELDS.map(({ key, label, icon, gradient, bg, border, text, badge, placeholder, desc, example }) => {
              const isActive = configured[key];
              const hasValue = Boolean(webhooks[key]);
              return (
                <div key={key} className={`bg-dark-900 border rounded-2xl overflow-hidden transition-all hover:border-dark-600 ${isActive ? 'border-dark-600' : 'border-dark-700'}`}>
                  {/* Card Header */}
                  <div className={`px-6 py-4 flex items-center justify-between border-b border-dark-700/50`}>
                    <div className="flex items-center gap-4">
                      <div className={`p-2.5 rounded-xl bg-gradient-to-br ${gradient} bg-opacity-20 ${border} border`}>
                        <div className={`${text}`}>{icon}</div>
                      </div>
                      <div>
                        <h3 className="text-base font-semibold text-dark-100">{label}</h3>
                        <p className="text-xs text-dark-400 mt-0.5">{desc}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {isActive ? (
                        <span className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold ${badge} border`}>
                          <FiCheckCircle className="w-3.5 h-3.5" /> Active
                        </span>
                      ) : hasValue ? (
                        <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
                          <FiAlertCircle className="w-3.5 h-3.5" /> Unsaved
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-dark-700 text-dark-400 border border-dark-600">
                          <FiXCircle className="w-3.5 h-3.5" /> Not Configured
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Card Body */}
                  <div className="px-6 py-4 space-y-3">
                    <div className="relative">
                      <input
                        type={showUrls[key] ? 'text' : 'password'}
                        value={webhooks[key] || ''}
                        onChange={(e) => setWebhooks({ ...webhooks, [key]: e.target.value })}
                        placeholder={placeholder}
                        className="w-full px-4 py-3 pr-24 bg-dark-800 border border-dark-700 rounded-xl text-dark-100 text-sm placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 font-mono transition-all"
                      />
                      <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                        <button
                          onClick={() => setShowUrls({ ...showUrls, [key]: !showUrls[key] })}
                          className="p-1.5 rounded-lg text-dark-400 hover:text-dark-200 hover:bg-dark-700 transition-colors"
                          title={showUrls[key] ? 'Hide URL' : 'Show URL'}
                        >
                          {showUrls[key] ? <FiEyeOff className="w-4 h-4" /> : <FiEye className="w-4 h-4" />}
                        </button>
                        {hasValue && (
                          <button
                            onClick={() => handleClear(key)}
                            className="p-1.5 rounded-lg text-dark-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                            title="Clear URL"
                          >
                            <FiTrash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </div>
                    <p className="text-xs text-dark-500 flex items-center gap-1.5">
                      <FiArrowRight className="w-3 h-3" />
                      {example}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>

          {/* How It Works */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-base font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiShield className="w-5 h-5 text-cyan-400" />
              How Webhooks Work
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="flex items-start gap-3 p-3 rounded-xl bg-dark-800/50 border border-dark-700/50">
                <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 shrink-0">
                  <span className="text-sm font-bold text-cyan-400">1</span>
                </div>
                <div>
                  <p className="text-sm font-medium text-dark-200">Configure URL</p>
                  <p className="text-xs text-dark-400 mt-0.5">Paste your webhook URL from Slack, Discord, or any HTTP endpoint</p>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 rounded-xl bg-dark-800/50 border border-dark-700/50">
                <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 shrink-0">
                  <span className="text-sm font-bold text-cyan-400">2</span>
                </div>
                <div>
                  <p className="text-sm font-medium text-dark-200">Save & Test</p>
                  <p className="text-xs text-dark-400 mt-0.5">Save your configuration and send a test alert to verify it works</p>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 rounded-xl bg-dark-800/50 border border-dark-700/50">
                <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 shrink-0">
                  <span className="text-sm font-bold text-cyan-400">3</span>
                </div>
                <div>
                  <p className="text-sm font-medium text-dark-200">Get Alerts</p>
                  <p className="text-xs text-dark-400 mt-0.5">Receive instant notifications whenever a malicious file is detected</p>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
