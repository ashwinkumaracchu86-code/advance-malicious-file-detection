import { useState, useEffect, useCallback } from 'react';
import {
  FiCpu, FiHardDrive, FiActivity, FiServer, FiCheckCircle, FiAlertTriangle,
  FiRefreshCw, FiMonitor, FiWifi, FiClock, FiZap, FiDatabase, FiShield,
  FiGlobe, FiInfo, FiArrowUp, FiArrowDown, FiRadio, FiCpu as FiCpuIcon,
  FiLayers, FiBox, FiTerminal,
} from 'react-icons/fi';
import { featuresAPI } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';

const CircularGauge = ({ value, max = 100, size = 120, label, sublabel, color }) => {
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.min(value / max, 1);
  const offset = circumference - pct * circumference;
  const getColor = (v) => {
    if (v > 90) return '#ef4444';
    if (v > 70) return '#eab308';
    return color || '#22c55e';
  };
  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="w-full h-full -rotate-90" viewBox={`0 0 ${size} ${size}`}>
          <circle cx={size / 2} cy={size / 2} r={radius} stroke="#1e293b" strokeWidth="8" fill="none" />
          <circle cx={size / 2} cy={size / 2} r={radius} stroke={getColor(value)} strokeWidth="8" fill="none"
            strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
            className="transition-all duration-700" />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-dark-100">{value}%</span>
          <span className="text-[10px] text-dark-400">{sublabel}</span>
        </div>
      </div>
      <p className="text-xs font-semibold text-dark-200 mt-2">{label}</p>
    </div>
  );
};

const MiniBar = ({ value, max = 100, color }) => {
  const pct = Math.min(value / max, 100);
  const getColor = (v) => {
    if (v > 90) return 'bg-red-500';
    if (v > 70) return 'bg-yellow-500';
    return color || 'bg-green-500';
  };
  return (
    <div className="w-full h-2 bg-dark-800 rounded-full overflow-hidden">
      <div className={`h-full rounded-full transition-all duration-500 ${getColor(pct)}`} style={{ width: `${pct}%` }} />
    </div>
  );
};

const formatBytes = (mb) => {
  if (mb >= 1024) return (mb / 1024).toFixed(1) + ' GB';
  return mb.toFixed(0) + ' MB';
};

export default function SystemHealthPage() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [activeSection, setActiveSection] = useState('overview');

  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'health_update') {
      setHealth(msg.data);
      setLastRefresh(new Date());
      setLoading(false);
    }
  }, []);

  const { connected } = useWebSocket(handleWsMessage);

  const fetchHealth = useCallback(async () => {
    try {
      const res = await featuresAPI.getSystemHealth();
      setHealth(res.data);
      setLastRefresh(new Date());
    } catch (err) {
      console.error('Failed to fetch system health:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const fallback = setInterval(fetchHealth, 15000);
    return () => clearInterval(fallback);
  }, [fetchHealth]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-dark-400 font-medium">Loading system health...</p>
        </div>
      </div>
    );
  }

  const statusConfig = {
    healthy: { label: 'All Systems Operational', icon: FiCheckCircle, color: 'text-green-400', bg: 'from-green-500/15 to-emerald-500/5', border: 'border-green-500/20', ring: 'bg-green-500' },
    warning: { label: 'System Warning', icon: FiAlertTriangle, color: 'text-yellow-400', bg: 'from-yellow-500/15 to-orange-500/5', border: 'border-yellow-500/20', ring: 'bg-yellow-500' },
    critical: { label: 'Critical Alert', icon: FiAlertTriangle, color: 'text-red-400', bg: 'from-red-500/15 to-pink-500/5', border: 'border-red-500/20', ring: 'bg-red-500' },
  };
  const status = statusConfig[health?.status] || statusConfig.healthy;
  const StatusIcon = status.icon;

  const cpu = health?.resources?.cpu_percent || 0;
  const mem = health?.resources?.memory_percent || 0;
  const disk = health?.resources?.disk_percent || 0;
  const memUsed = health?.resources?.memory_used_mb || 0;
  const memTotal = health?.resources?.memory_total_mb || 0;
  const diskUsed = health?.resources?.disk_used_gb || 0;
  const diskTotal = health?.resources?.disk_total_gb || 0;
  const services = health?.services || {};
  const system = health?.system || {};
  const network = health?.network || {};
  const processes = health?.processes || {};
  const uptime = health?.uptime || {};
  const cpuInfo = health?.cpu_info || {};
  const memDetail = health?.memory_detail || {};
  const diskParts = health?.disk_partitions || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/20">
              <FiActivity className="w-6 h-6 text-cyan-400" />
            </div>
            System Health
          </h1>
          <p className="text-dark-400 text-sm mt-1 ml-13">Real-time system resource monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold ${
            connected ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'
          }`}>
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
            {connected ? 'LIVE' : 'OFFLINE'}
          </span>
          {lastRefresh && (
            <span className="text-xs text-dark-500 flex items-center gap-1.5">
              <FiClock className="w-3 h-3" /> {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button onClick={fetchHealth} disabled={loading}
            className="p-2.5 rounded-xl bg-dark-800 border border-dark-700 text-dark-300 hover:text-dark-100 hover:border-dark-600 disabled:opacity-40 transition-all">
            <FiRefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Status Banner */}
      <div className={`rounded-2xl p-6 border bg-gradient-to-r ${status.bg} ${status.border}`}>
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <div className={`relative p-4 rounded-2xl ${status.ring}/20`}>
              <StatusIcon className={`w-10 h-10 ${status.color}`} />
              <span className={`absolute -top-1 -right-1 w-4 h-4 ${status.ring} rounded-full border-2 border-dark-900 animate-pulse`} />
            </div>
            <div>
              <h2 className={`text-xl font-bold ${status.color}`}>{status.label}</h2>
              <p className="text-dark-400 text-sm mt-0.5">
                Uptime: <span className="text-dark-200 font-medium">{uptime.uptime_human || '—'}</span> &bull;
                Boot: {uptime.boot_time ? new Date(uptime.boot_time).toLocaleString() : '—'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 rounded-xl bg-dark-900/50 border border-dark-700/50">
            <FiRefreshCw className={`w-3 h-3 ${connected ? 'text-green-400 animate-spin' : 'text-dark-400'}`} />
            <span className="text-xs text-dark-400">{connected ? 'Real-time: 3s updates' : 'Connecting...'}</span>
          </div>
        </div>
      </div>

      {/* Section Tabs */}
      <div className="flex gap-2 bg-dark-900 border border-dark-700 rounded-xl p-1.5">
        {[
          { id: 'overview', label: 'Overview', icon: FiActivity },
          { id: 'cpu', label: 'CPU', icon: FiCpu },
          { id: 'memory', label: 'Memory', icon: FiLayers },
          { id: 'disk', label: 'Disk', icon: FiHardDrive },
          { id: 'network', label: 'Network', icon: FiWifi },
          { id: 'processes', label: 'Processes', icon: FiTerminal },
        ].map((tab) => (
          <button key={tab.id} onClick={() => setActiveSection(tab.id)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all flex-1 justify-center ${
              activeSection === tab.id
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm'
                : 'text-dark-400 hover:text-dark-100 hover:bg-dark-800 border border-transparent'
            }`}>
            <tab.icon className="w-3.5 h-3.5" /> {tab.label}
          </button>
        ))}
      </div>

      {/* Overview */}
      {activeSection === 'overview' && (
        <div className="space-y-6">
          {/* Resource Gauges */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-6 flex items-center gap-2">
              <FiZap className="w-4 h-4 text-cyan-400" /> Resource Usage
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              <div className="flex flex-col items-center">
                <CircularGauge value={cpu} label="CPU Usage" sublabel={`${cpu}%`} color="#06b6d4" />
                <div className="mt-3 w-full max-w-[200px]"><MiniBar value={cpu} color="bg-cyan-500" /></div>
              </div>
              <div className="flex flex-col items-center">
                <CircularGauge value={mem} label="Memory" sublabel={`${memUsed}MB / ${memTotal}MB`} color="#a78bfa" />
                <div className="mt-3 w-full max-w-[200px]"><MiniBar value={mem} color="bg-purple-500" /></div>
              </div>
              <div className="flex flex-col items-center">
                <CircularGauge value={disk} label="Disk" sublabel={`${diskUsed}GB / ${diskTotal}GB`} color="#22c55e" />
                <div className="mt-3 w-full max-w-[200px]"><MiniBar value={disk} color="bg-green-500" /></div>
              </div>
            </div>
          </div>

          {/* Service Status */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiServer className="w-4 h-4 text-cyan-400" /> Service Status
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {Object.entries(services).map(([key, value]) => {
                const isActive = value === 'active';
                const isWarn = value === 'unavailable';
                return (
                  <div key={key} className={`rounded-xl p-4 border transition-all ${
                    isActive ? 'bg-green-500/5 border-green-500/20' : isWarn ? 'bg-yellow-500/5 border-yellow-500/20' : 'bg-red-500/5 border-red-500/20'
                  }`}>
                    <div className="flex items-center gap-3">
                      <div className={`relative p-2 rounded-lg ${isActive ? 'bg-green-500/20' : isWarn ? 'bg-yellow-500/20' : 'bg-red-500/20'}`}>
                         {key === 'database' ? <FiDatabase className={`w-4 h-4 ${isActive ? 'text-green-400' : 'text-red-400'}`} /> :
                          <FiActivity className={`w-4 h-4 ${isActive ? 'text-green-400' : isWarn ? 'text-yellow-400' : 'text-red-400'}`} />}
                        <span className={`absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full ${isActive ? 'bg-green-400 animate-pulse' : isWarn ? 'bg-yellow-400' : 'bg-red-400'}`} />
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-dark-100 capitalize">{key.replace(/_/g, ' ')}</p>
                        <p className={`text-xs font-medium capitalize ${isActive ? 'text-green-400' : isWarn ? 'text-yellow-400' : 'text-red-400'}`}>{value}</p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { icon: FiClock, label: 'Uptime', value: uptime.uptime_human || '—', color: 'text-cyan-400', bg: 'from-cyan-500/20 to-blue-500/20' },
              { icon: FiLayers, label: 'Processes', value: processes.total_count || 0, color: 'text-purple-400', bg: 'from-purple-500/20 to-pink-500/20' },
              { icon: FiArrowUp, label: 'Net Sent', value: `${network.bytes_sent_mb || 0} MB`, color: 'text-green-400', bg: 'from-green-500/20 to-emerald-500/20' },
              { icon: FiArrowDown, label: 'Net Recv', value: `${network.bytes_recv_mb || 0} MB`, color: 'text-orange-400', bg: 'from-orange-500/20 to-amber-500/20' },
            ].map(({ icon: Icon, label, value, color, bg }, i) => (
              <div key={i} className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-4 flex items-center gap-3">
                <div className={`p-2.5 rounded-xl bg-gradient-to-br ${bg} border border-dark-700/30`}>
                  <Icon className={`w-4 h-4 ${color}`} />
                </div>
                <div>
                  <p className="text-lg font-bold text-dark-100">{value}</p>
                  <p className="text-[10px] text-dark-400 font-medium">{label}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CPU Section */}
      {activeSection === 'cpu' && (
        <div className="space-y-6">
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiCpu className="w-4 h-4 text-cyan-400" /> CPU Information
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Physical Cores', value: cpuInfo.physical_cores || 0 },
                { label: 'Logical Cores', value: cpuInfo.logical_cores || 0 },
                { label: 'Current Freq', value: `${cpuInfo.frequency_current || 0} MHz` },
                { label: 'Max Freq', value: `${cpuInfo.frequency_max || 0} MHz` },
              ].map(({ label, value }, i) => (
                <div key={i} className="bg-dark-800/50 rounded-xl p-4 border border-dark-700/50 text-center">
                  <p className="text-xl font-bold text-cyan-400">{value}</p>
                  <p className="text-xs text-dark-400 font-medium mt-1">{label}</p>
                </div>
              ))}
            </div>
          </div>
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiActivity className="w-4 h-4 text-cyan-400" /> Load Average
            </h3>
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: '1 Minute', value: cpuInfo.load_avg_1m || 0 },
                { label: '5 Minutes', value: cpuInfo.load_avg_5m || 0 },
                { label: '15 Minutes', value: cpuInfo.load_avg_15m || 0 },
              ].map(({ label, value }, i) => (
                <div key={i} className="bg-dark-800/50 rounded-xl p-4 border border-dark-700/50 text-center">
                  <p className="text-xl font-bold text-dark-100">{value}</p>
                  <p className="text-xs text-dark-400 font-medium mt-1">{label}</p>
                </div>
              ))}
            </div>
          </div>
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiZap className="w-4 h-4 text-cyan-400" /> CPU Usage
            </h3>
            <div className="flex items-center gap-6">
              <CircularGauge value={cpu} size={140} label="Current" sublabel={`${cpu}%`} color="#06b6d4" />
              <div className="flex-1 space-y-3">
                <div className="flex justify-between text-sm"><span className="text-dark-400">Context Switches</span><span className="text-dark-100 font-medium">{(cpuInfo.ctx_switches || 0).toLocaleString()}</span></div>
                <div className="flex justify-between text-sm"><span className="text-dark-400">Interrupts</span><span className="text-dark-100 font-medium">{(cpuInfo.interrupts || 0).toLocaleString()}</span></div>
                <MiniBar value={cpu} color="bg-cyan-500" />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Memory Section */}
      {activeSection === 'memory' && (
        <div className="space-y-6">
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-6 flex items-center gap-2">
              <FiLayers className="w-4 h-4 text-purple-400" /> Memory Usage
            </h3>
            <div className="flex items-center gap-8">
              <CircularGauge value={mem} size={140} label="RAM" sublabel={`${mem}%`} color="#a78bfa" />
              <div className="flex-1 space-y-3">
                {[
                  { label: 'Used', value: `${memUsed} MB`, color: 'text-purple-400' },
                  { label: 'Total', value: `${memTotal} MB`, color: 'text-dark-100' },
                  { label: 'Available', value: `${memDetail.available_mb || 0} MB`, color: 'text-green-400' },
                  { label: 'Cached', value: `${memDetail.cached_mb || 0} MB`, color: 'text-cyan-400' },
                ].map(({ label, value, color }, i) => (
                  <div key={i} className="flex justify-between text-sm">
                    <span className="text-dark-400">{label}</span>
                    <span className={`font-medium ${color}`}>{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiBox className="w-4 h-4 text-purple-400" /> Swap Memory
            </h3>
            <div className="flex items-center gap-6">
              <CircularGauge value={memDetail.swap_percent || 0} size={120} label="Swap" sublabel={`${memDetail.swap_percent || 0}%`} color="#f472b6" />
              <div className="flex-1 space-y-3">
                {[
                  { label: 'Swap Used', value: `${memDetail.swap_used_mb || 0} MB` },
                  { label: 'Swap Total', value: `${memDetail.swap_total_mb || 0} MB` },
                ].map(({ label, value }, i) => (
                  <div key={i} className="flex justify-between text-sm">
                    <span className="text-dark-400">{label}</span>
                    <span className="text-dark-100 font-medium">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Disk Section */}
      {activeSection === 'disk' && (
        <div className="space-y-6">
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-6 flex items-center gap-2">
              <FiHardDrive className="w-4 h-4 text-green-400" /> Disk Usage
            </h3>
            <div className="flex items-center gap-8">
              <CircularGauge value={disk} size={140} label="Disk" sublabel={`${diskUsed}GB / ${diskTotal}GB`} color="#22c55e" />
              <div className="flex-1 space-y-3">
                {[
                  { label: 'Used', value: `${diskUsed} GB`, color: 'text-green-400' },
                  { label: 'Total', value: `${diskTotal} GB`, color: 'text-dark-100' },
                  { label: 'Free', value: `${(diskTotal - diskUsed).toFixed(2)} GB`, color: 'text-cyan-400' },
                ].map(({ label, value, color }, i) => (
                  <div key={i} className="flex justify-between text-sm">
                    <span className="text-dark-400">{label}</span>
                    <span className={`font-medium ${color}`}>{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          {diskParts.length > 0 && (
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <FiLayers className="w-4 h-4 text-green-400" /> Partitions ({diskParts.length})
              </h3>
              <div className="space-y-3">
                {diskParts.map((part, i) => (
                  <div key={i} className="bg-dark-800/50 rounded-xl p-4 border border-dark-700/50">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <FiHardDrive className="w-4 h-4 text-green-400" />
                        <div>
                          <p className="text-sm font-semibold text-dark-100">{part.device}</p>
                          <p className="text-[10px] text-dark-400">{part.mountpoint} &bull; {part.fstype}</p>
                        </div>
                      </div>
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded-lg ${
                        part.percent > 90 ? 'bg-red-500/20 text-red-400' : part.percent > 70 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'
                      }`}>{part.percent}%</span>
                    </div>
                    <MiniBar value={part.percent} color="bg-green-500" />
                    <div className="flex justify-between mt-2 text-[10px] text-dark-500">
                      <span>{part.used_gb} GB used</span>
                      <span>{part.free_gb} GB free</span>
                      <span>{part.total_gb} GB total</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Network Section */}
      {activeSection === 'network' && (
        <div className="space-y-6">
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiWifi className="w-4 h-4 text-cyan-400" /> Network I/O
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Sent', value: `${network.bytes_sent_mb || 0} MB`, icon: FiArrowUp, color: 'text-green-400', bg: 'from-green-500/20 to-emerald-500/20' },
                { label: 'Received', value: `${network.bytes_recv_mb || 0} MB`, icon: FiArrowDown, color: 'text-orange-400', bg: 'from-orange-500/20 to-amber-500/20' },
                { label: 'Packets Sent', value: (network.packets_sent || 0).toLocaleString(), icon: FiArrowUp, color: 'text-cyan-400', bg: 'from-cyan-500/20 to-blue-500/20' },
                { label: 'Packets Recv', value: (network.packets_recv || 0).toLocaleString(), icon: FiArrowDown, color: 'text-purple-400', bg: 'from-purple-500/20 to-pink-500/20' },
              ].map(({ label, value, icon: Icon, color, bg }, i) => (
                <div key={i} className="bg-dark-800/50 rounded-xl p-4 border border-dark-700/50 text-center">
                  <div className={`p-2 rounded-lg bg-gradient-to-br ${bg} border border-dark-700/30 inline-block mb-2`}>
                    <Icon className={`w-4 h-4 ${color}`} />
                  </div>
                  <p className="text-lg font-bold text-dark-100">{value}</p>
                  <p className="text-[10px] text-dark-400 font-medium">{label}</p>
                </div>
              ))}
            </div>
          </div>
          {network.interfaces && network.interfaces.length > 0 && (
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <FiGlobe className="w-4 h-4 text-cyan-400" /> Network Interfaces ({network.interfaces.length})
              </h3>
              <div className="space-y-2">
                {network.interfaces.map((iface, i) => (
                  <div key={i} className="flex items-center justify-between bg-dark-800/50 rounded-xl px-4 py-3 border border-dark-700/50">
                    <div className="flex items-center gap-3">
                      <FiWifi className="w-4 h-4 text-cyan-400" />
                      <div>
                        <p className="text-sm font-semibold text-dark-100">{iface.name}</p>
                        <p className="text-[10px] text-dark-400">Mask: {iface.netmask || '—'}</p>
                      </div>
                    </div>
                    <span className="text-sm text-dark-200 font-mono">{iface.ip}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Processes Section */}
      {activeSection === 'processes' && (
        <div className="space-y-6">
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiTerminal className="w-4 h-4 text-cyan-400" /> Process Overview
            </h3>
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: 'Total', value: processes.total_count || 0, color: 'text-cyan-400', bg: 'from-cyan-500/20 to-blue-500/20' },
                { label: 'Running', value: processes.running || 0, color: 'text-green-400', bg: 'from-green-500/20 to-emerald-500/20' },
                { label: 'Sleeping', value: processes.sleeping || 0, color: 'text-yellow-400', bg: 'from-yellow-500/20 to-orange-500/20' },
              ].map(({ label, value, color, bg }, i) => (
                <div key={i} className={`bg-gradient-to-br ${bg} border border-dark-700/50 rounded-xl p-4 text-center`}>
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                  <p className="text-xs text-dark-400 font-medium mt-1">{label}</p>
                </div>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <FiCpu className="w-4 h-4 text-red-400" /> Top CPU Processes
              </h3>
              <div className="space-y-2">
                {(processes.top_cpu || []).map((p, i) => (
                  <div key={i} className="flex items-center justify-between bg-dark-800/50 rounded-xl px-4 py-3 border border-dark-700/50">
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-dark-500 w-6">#{i + 1}</span>
                      <div>
                        <p className="text-sm font-medium text-dark-100">{p.name}</p>
                        <p className="text-[10px] text-dark-400">PID: {p.pid}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs font-semibold text-red-400">{p.cpu}%</span>
                      <span className="text-xs text-dark-400">{p.memory}%</span>
                    </div>
                  </div>
                ))}
                {(!processes.top_cpu || processes.top_cpu.length === 0) && (
                  <p className="text-dark-500 text-sm text-center py-4">No data available</p>
                )}
              </div>
            </div>
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <FiLayers className="w-4 h-4 text-purple-400" /> Top Memory Processes
              </h3>
              <div className="space-y-2">
                {(processes.top_memory || []).map((p, i) => (
                  <div key={i} className="flex items-center justify-between bg-dark-800/50 rounded-xl px-4 py-3 border border-dark-700/50">
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-dark-500 w-6">#{i + 1}</span>
                      <div>
                        <p className="text-sm font-medium text-dark-100">{p.name}</p>
                        <p className="text-[10px] text-dark-400">PID: {p.pid}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-dark-400">{p.cpu}%</span>
                      <span className="text-xs font-semibold text-purple-400">{p.memory}%</span>
                    </div>
                  </div>
                ))}
                {(!processes.top_memory || processes.top_memory.length === 0) && (
                  <p className="text-dark-500 text-sm text-center py-4">No data available</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* System Info (always visible) */}
      <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
          <FiInfo className="w-4 h-4 text-cyan-400" /> System Information
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {Object.entries(system).map(([key, value]) => {
            const icons = { os: FiMonitor, os_version: FiMonitor, platform: FiGlobe, architecture: FiCpu, python_version: FiZap, hostname: FiServer, processor: FiCpu };
            const Icon = icons[key] || FiInfo;
            return (
              <div key={key} className="flex items-center gap-3 bg-dark-800/50 rounded-xl px-4 py-3 border border-dark-700/50 hover:border-dark-600 transition-all">
                <div className="p-2 rounded-lg bg-dark-700 border border-dark-600">
                  <Icon className="w-3.5 h-3.5 text-dark-400" />
                </div>
                <div className="min-w-0">
                  <p className="text-[10px] text-dark-500 uppercase tracking-wider">{key.replace(/_/g, ' ')}</p>
                  <p className="text-sm text-dark-100 font-medium truncate">{value || 'N/A'}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
