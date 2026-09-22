import { useState, useEffect, useRef, useCallback } from 'react';
import {
  FiActivity, FiMail, FiShield, FiAlertTriangle, FiCheckCircle, FiClock,
  FiPlay, FiPause, FiRefreshCw, FiLink, FiLock, FiEye, FiServer, FiWifi, FiWifiOff,
} from 'react-icons/fi';
import toast from 'react-hot-toast';
import { emailSecurityAPI } from '../services/api';

const EVENT_CONFIG = {
  email_received: {
    icon: FiMail,
    color: 'text-dark-300',
    dotColor: 'bg-cyan-400',
    label: 'Email Received',
  },
  scan_started: {
    icon: FiActivity,
    color: 'text-cyan-400',
    dotColor: 'bg-cyan-400',
    label: 'Scan Started',
  },
  attachment_detected: {
    icon: FiEye,
    color: 'text-yellow-400',
    dotColor: 'bg-yellow-400',
    label: 'Attachment Detected',
  },
  hash_generated: {
    icon: FiLink,
    color: 'text-dark-300',
    dotColor: 'bg-cyan-400',
    label: 'Hash Generated',
  },
  risk_calculated: {
    icon: FiShield,
    color: 'text-dark-300',
    dotColor: 'bg-cyan-400',
    label: 'Risk Calculated',
  },
  email_quarantined: {
    icon: FiLock,
    color: 'text-red-400',
    dotColor: 'bg-red-400',
    label: 'Email Quarantined',
  },
  alert_generated: {
    icon: FiAlertTriangle,
    color: 'text-red-400',
    dotColor: 'bg-red-400',
    label: 'Alert Generated',
  },
};

const SEVERITY_CONFIG = {
  safe: { dotColor: 'bg-green-400', bg: 'bg-green-500/15', text: 'text-green-400', border: 'border-green-500/30', label: 'SAFE' },
  suspicious: { dotColor: 'bg-yellow-400', bg: 'bg-yellow-500/15', text: 'text-yellow-400', border: 'border-yellow-500/30', label: 'SUSPICIOUS' },
  malicious: { dotColor: 'bg-red-400', bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/30', label: 'MALICIOUS' },
  critical: { dotColor: 'bg-red-400', bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/30', label: 'CRITICAL' },
  info: { dotColor: 'bg-cyan-400', bg: 'bg-cyan-500/15', text: 'text-cyan-400', border: 'border-cyan-500/30', label: 'INFO' },
};

function formatTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wider border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dotColor}`} />
      {cfg.label}
    </span>
  );
}

function EventRow({ event }) {
  const evtCfg = EVENT_CONFIG[event.event_type] || EVENT_CONFIG.email_received;
  const Icon = evtCfg.icon;
  const sevCfg = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.info;

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 border-b border-dark-700/50 hover:bg-dark-950/80 transition-colors group">
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${sevCfg.dotColor}`} />
      <span className="text-[11px] font-mono text-dark-500 w-[70px] shrink-0 tabular-nums">
        {formatTime(event.timestamp)}
      </span>
      <div className={`shrink-0 ${evtCfg.color}`}>
        <Icon className="w-3.5 h-3.5" />
      </div>
      <span className="text-sm text-dark-200 flex-1 truncate">
        {event.description || evtCfg.label}
      </span>
      {event.email_id && (
        <span className="text-[10px] font-mono text-dark-500 shrink-0 hidden sm:inline">
          {String(event.email_id).slice(0, 8)}
        </span>
      )}
      <SeverityBadge severity={event.severity} />
    </div>
  );
}

function SidebarStat({ icon: Icon, label, value, color, bgColor }) {
  return (
    <div className={`flex items-center gap-3 px-4 py-3 rounded-lg ${bgColor}`}>
      <Icon className={`w-4 h-4 ${color} shrink-0`} />
      <div className="flex-1 min-w-0">
        <div className="text-xs text-dark-400 truncate">{label}</div>
        <div className={`text-lg font-bold tabular-nums ${color}`}>{value}</div>
      </div>
    </div>
  );
}

export default function EmailLiveMonitorPage() {
  const [connected, setConnected] = useState(false);
  const [monitoring, setMonitoring] = useState(false);
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({ total: 0, threats: 0, safe: 0, suspicious: 0 });
  const [loading, setLoading] = useState(true);
  const [polling, setPolling] = useState(false);
  const feedRef = useRef(null);
  const intervalRef = useRef(null);
  const seenIds = useRef(new Set());

  const fetchEvents = useCallback(async () => {
    try {
      const res = await emailSecurityAPI.getEvents({ limit: 100 });
      const data = res.data;
      const eventList = data.events || data || [];
      setEvents(eventList);

      let threats = 0;
      let safe = 0;
      let suspicious = 0;
      eventList.forEach((e) => {
        if (e.severity === 'malicious' || e.severity === 'critical') threats++;
        else if (e.severity === 'suspicious') suspicious++;
        else if (e.severity === 'safe') safe++;
      });
      setStats({
        total: eventList.length,
        threats,
        safe,
        suspicious,
      });
    } catch (err) {
      console.error('Failed to fetch email events:', err);
    }
  }, []);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await emailSecurityAPI.getMonitoringStatus();
      const isMonitoring = res.data?.monitoring ?? res.data?.active ?? false;
      setMonitoring(isMonitoring);
      setConnected(true);
    } catch (err) {
      console.error('Failed to fetch monitoring status:', err);
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      try {
        await Promise.all([fetchEvents(), fetchStatus()]);
      } catch {
        // errors handled inside each fetch function
      } finally {
        setLoading(false);
      }
    };
    init();
  }, [fetchEvents, fetchStatus]);

  useEffect(() => {
    if (monitoring) {
      intervalRef.current = setInterval(() => {
        fetchEvents();
      }, 5000);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [monitoring, fetchEvents]);

  useEffect(() => {
    if (feedRef.current && events.length > 0) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [events]);

  const handleStart = async () => {
    try {
      setPolling(true);
      await emailSecurityAPI.startMonitoring();
      setMonitoring(true);
      setConnected(true);
      toast.success('Email monitoring started');
      fetchEvents();
    } catch (err) {
      toast.error('Failed to start email monitoring');
      setPolling(false);
    }
  };

  const handleStop = async () => {
    try {
      await emailSecurityAPI.stopMonitoring();
      setMonitoring(false);
      toast('Email monitoring stopped', { icon: '⏹' });
    } catch (err) {
      toast.error('Failed to stop email monitoring');
    }
  };

  const handleRefresh = async () => {
    await Promise.all([fetchEvents(), fetchStatus()]);
    toast.success('Events refreshed');
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin h-10 w-10 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-dark-400">Loading email monitor...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-lg">
            <FiActivity className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-dark-100">Email Live Monitor</h1>
            <p className="text-dark-400 text-xs">Real-time email security event feed</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            className="p-2 rounded-lg bg-dark-900 border border-dark-700 text-dark-300 hover:bg-dark-800 hover:text-cyan-400 transition-colors"
            title="Refresh"
          >
            <FiRefreshCw className="w-4 h-4" />
          </button>
          {monitoring ? (
            <button
              onClick={handleStop}
              className="inline-flex items-center gap-2 px-4 py-2 bg-red-600/80 hover:bg-red-500 text-white rounded-lg text-sm font-medium transition-colors"
            >
              <FiPause className="w-4 h-4" />
              Stop Monitoring
            </button>
          ) : (
            <button
              onClick={handleStart}
              className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors"
            >
              <FiPlay className="w-4 h-4" />
              Start Monitoring
            </button>
          )}
        </div>
      </div>

      {/* Connection Status */}
      <div className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium ${
        connected
          ? 'bg-green-500/10 border-green-500/20 text-green-400'
          : 'bg-red-500/10 border-red-500/20 text-red-400'
      }`}>
        {connected ? <FiWifi className="w-4 h-4" /> : <FiWifiOff className="w-4 h-4" />}
        <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
        <span>{connected ? 'Connected — Live feed active' : 'Disconnected — Attempting to reconnect...'}</span>
        {monitoring && (
          <>
            <span className="text-dark-600 mx-1">|</span>
            <FiEye className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-cyan-400">Monitoring active</span>
            <span className="text-dark-500 text-xs">(polling every 5s)</span>
          </>
        )}
      </div>

      {/* Main Layout */}
      <div className="flex gap-4 min-h-[calc(100vh-280px)]">
        {/* Event Feed */}
        <div className="flex-1 bg-dark-900 border border-dark-700 rounded-xl overflow-hidden flex flex-col">
          <div className="px-4 py-3 border-b border-dark-700 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FiServer className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-semibold text-dark-100">Security Event Log</span>
              <span className="text-xs text-dark-500 bg-dark-950 px-2 py-0.5 rounded-full">
                {events.length} events
              </span>
            </div>
            {monitoring && (
              <div className="flex items-center gap-1.5 text-xs text-dark-500">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                LIVE
              </div>
            )}
          </div>

          {/* Column Headers */}
          <div className="flex items-center gap-3 px-4 py-2 border-b border-dark-700/80 bg-dark-950/50 text-[10px] font-semibold text-dark-500 uppercase tracking-wider">
            <span className="w-1.5 shrink-0" />
            <span className="w-[70px] shrink-0">Time</span>
            <span className="w-3.5 shrink-0" />
            <span className="flex-1">Description</span>
            <span className="w-[64px] shrink-0 hidden sm:block">Email ID</span>
            <span className="w-[88px] shrink-0 text-right">Severity</span>
          </div>

          {/* Feed */}
          <div ref={feedRef} className="flex-1 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 380px)' }}>
            {events.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-dark-500">
                <FiMail className="w-8 h-8 mb-3 text-dark-600" />
                <p className="text-sm font-medium">No events yet</p>
                <p className="text-xs text-dark-600 mt-1">Start monitoring to see live email security events</p>
              </div>
            ) : (
              events.map((event, idx) => (
                <EventRow key={event.id || event.timestamp || idx} event={event} />
              ))
            )}
          </div>

          {/* Feed Footer */}
          <div className="px-4 py-2 border-t border-dark-700 bg-dark-950/30 flex items-center justify-between text-[10px] text-dark-500">
            <span>Last updated: {events.length > 0 ? formatTime(events[events.length - 1]?.timestamp) || '—' : '—'}</span>
            <span className="flex items-center gap-1">
              <FiClock className="w-3 h-3" />
              Auto-refresh: {monitoring ? '5s' : 'off'}
            </span>
          </div>
        </div>

        {/* Sidebar */}
        <div className="w-64 shrink-0 space-y-4 hidden lg:block">
          {/* Live Stats */}
          <div className="bg-dark-900 border border-dark-700 rounded-xl p-4 space-y-3">
            <h3 className="text-xs font-semibold text-dark-400 uppercase tracking-wider flex items-center gap-2">
              <FiActivity className="w-3.5 h-3.5 text-cyan-400" />
              Live Statistics
            </h3>
            <SidebarStat icon={FiMail} label="Total Events" value={stats.total} color="text-dark-100" bgColor="bg-dark-950" />
            <SidebarStat icon={FiAlertTriangle} label="Threats" value={stats.threats} color="text-red-400" bgColor="bg-red-500/5" />
            <SidebarStat icon={FiAlertTriangle} label="Suspicious" value={stats.suspicious} color="text-yellow-400" bgColor="bg-yellow-500/5" />
            <SidebarStat icon={FiCheckCircle} label="Safe" value={stats.safe} color="text-green-400" bgColor="bg-green-500/5" />
          </div>

          {/* Event Types Legend */}
          <div className="bg-dark-900 border border-dark-700 rounded-xl p-4">
            <h3 className="text-xs font-semibold text-dark-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <FiEye className="w-3.5 h-3.5 text-cyan-400" />
              Event Types
            </h3>
            <div className="space-y-2">
              {Object.entries(EVENT_CONFIG).map(([key, cfg]) => {
                const Icon = cfg.icon;
                return (
                  <div key={key} className="flex items-center gap-2 text-xs text-dark-300">
                    <Icon className={`w-3 h-3 ${cfg.color} shrink-0`} />
                    <span className="truncate">{cfg.label}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Severity Legend */}
          <div className="bg-dark-900 border border-dark-700 rounded-xl p-4">
            <h3 className="text-xs font-semibold text-dark-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <FiShield className="w-3.5 h-3.5 text-cyan-400" />
              Severity Levels
            </h3>
            <div className="space-y-2">
              {Object.entries(SEVERITY_CONFIG).map(([key, cfg]) => (
                <div key={key} className="flex items-center gap-2 text-xs">
                  <span className={`w-2 h-2 rounded-full ${cfg.dotColor} shrink-0`} />
                  <span className={`font-medium ${cfg.text}`}>{cfg.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Monitoring Info */}
          <div className="bg-dark-900 border border-dark-700 rounded-xl p-4">
            <h3 className="text-xs font-semibold text-dark-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <FiServer className="w-3.5 h-3.5 text-cyan-400" />
              Monitor Status
            </h3>
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-dark-400">Status</span>
                <span className={`font-medium ${monitoring ? 'text-green-400' : 'text-dark-500'}`}>
                  {monitoring ? 'ACTIVE' : 'STOPPED'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-dark-400">Connection</span>
                <span className={`font-medium ${connected ? 'text-green-400' : 'text-red-400'}`}>
                  {connected ? 'ONLINE' : 'OFFLINE'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-dark-400">Poll Interval</span>
                <span className="text-dark-200 font-mono">5s</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-dark-400">Feed Limit</span>
                <span className="text-dark-200 font-mono">100</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
