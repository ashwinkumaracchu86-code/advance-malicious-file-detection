import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  FiCpu, FiHardDrive, FiActivity, FiServer, FiCheckCircle, FiAlertTriangle,
  FiRefreshCw, FiMonitor, FiWifi, FiClock, FiZap, FiDatabase, FiShield,
  FiGlobe, FiInfo, FiArrowUp, FiArrowDown, FiTerminal, FiLayers, FiBox,
  FiSearch, FiXOctagon, FiX, FiPlay, FiPause, FiFilter, FiCheck, FiSliders
} from 'react-icons/fi';
import toast from 'react-hot-toast';
import { featuresAPI } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';

const CircularGauge = ({ value, max = 100, size = 120, label, sublabel, color }) => {
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.min(Math.max(value, 0) / max, 1);
  const offset = circumference - pct * circumference;
  const getColor = (v) => {
    if (v > 90) return '#ef4444';
    if (v > 75) return '#eab308';
    return color || '#06b6d4';
  };
  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="w-full h-full -rotate-90" viewBox={`0 0 ${size} ${size}`}>
          <circle cx={size / 2} cy={size / 2} r={radius} stroke="#1e293b" strokeWidth="8" fill="none" />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={getColor(value)}
            strokeWidth="8"
            fill="none"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-700"
          />
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
  const pct = Math.min(Math.max(value, 0) / max * 100, 100);
  const getColor = (v) => {
    if (v > 90) return 'bg-red-500';
    if (v > 75) return 'bg-yellow-500';
    return color || 'bg-cyan-500';
  };
  return (
    <div className="w-full h-2 bg-dark-800 rounded-full overflow-hidden">
      <div className={`h-full rounded-full transition-all duration-500 ${getColor(pct)}`} style={{ width: `${pct}%` }} />
    </div>
  );
};

const MiniAreaChart = ({ data, color = '#06b6d4', height = 65, label, currentVal, unit = '%' }) => {
  if (!data || data.length < 2) {
    return (
      <div className="h-[65px] flex items-center justify-center text-xs text-dark-500 bg-dark-950/40 rounded-xl border border-dark-800">
        Awaiting telemetry data...
      </div>
    );
  }
  const max = 100;
  const width = 280;
  const points = data.map((d, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - (Math.min(100, Math.max(0, d.value)) / max) * (height - 10) - 5;
    return `${x},${y}`;
  });
  const pathD = `M 0,${height} L ${points.join(' L ')} L ${width},${height} Z`;
  const lineD = `M ${points.join(' L ')}`;
  const gradId = `grad-${color.replace('#', '')}`;

  return (
    <div className="w-full">
      <div className="flex justify-between items-center mb-1 text-xs">
        <span className="text-dark-400 font-medium">{label}</span>
        <span className="font-bold text-dark-100">{currentVal} {unit}</span>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-[65px] overflow-hidden rounded-xl bg-dark-950/70 border border-dark-800">
        <defs>
          <linearGradient id={gradId} x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor={color} stopOpacity="0.45" />
            <stop offset="100%" stopColor={color} stopOpacity="0.05" />
          </linearGradient>
        </defs>
        <path d={pathD} fill={`url(#${gradId})`} />
        <path d={lineD} fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" />
      </svg>
    </div>
  );
};

export default function SystemHealthPage() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [activeSection, setActiveSection] = useState('processes'); // Default to Task Manager Processes!

  // Task Manager controls
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('all'); // all, apps, high_cpu, system
  const [sortBy, setSortBy] = useState('cpu'); // cpu, memory, name, pid
  const [sortOrder, setSortOrder] = useState('desc'); // desc, asc
  const [refreshInterval, setRefreshInterval] = useState(2000); // 2s default
  const [targetProcess, setTargetProcess] = useState(null); // Process to kill in modal
  const [forceKill, setForceKill] = useState(false);
  const [killing, setKilling] = useState(false);

  // WebSocket real-time stream
  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'health_update' && refreshInterval > 0) {
      setHealth(msg.data);
      setLastRefresh(new Date());
      setLoading(false);
    }
  }, [refreshInterval]);

  const { connected } = useWebSocket(handleWsMessage);

  // Fallback REST fetch
  const fetchHealth = useCallback(async (isSilent = false) => {
    if (!isSilent) setLoading(true);
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
  }, [fetchHealth]);

  // Polling timer
  useEffect(() => {
    if (refreshInterval <= 0) return;
    const interval = setInterval(() => {
      fetchHealth(true);
    }, refreshInterval);
    return () => clearInterval(interval);
  }, [fetchHealth, refreshInterval]);

  // Kill Process Handler
  const handleKillProcess = async () => {
    if (!targetProcess) return;
    setKilling(true);
    try {
      const res = await featuresAPI.killProcess(targetProcess.pid, forceKill);
      toast.success(res.data?.message || `Process ${targetProcess.name} terminated`);
      setTargetProcess(null);
      setForceKill(false);
      // Immediate refresh
      fetchHealth(true);
    } catch (err) {
      const detail = err.response?.data?.detail || 'Failed to terminate process';
      toast.error(detail);
    } finally {
      setKilling(false);
    }
  };

  const statusConfig = {
    healthy: { label: 'All Systems Operational', icon: FiCheckCircle, color: 'text-green-400', bg: 'from-green-500/15 to-emerald-500/5', border: 'border-green-500/20', ring: 'bg-green-500' },
    warning: { label: 'System Warning / High Resource', icon: FiAlertTriangle, color: 'text-yellow-400', bg: 'from-yellow-500/15 to-orange-500/5', border: 'border-yellow-500/20', ring: 'bg-yellow-500' },
    critical: { label: 'Critical Resource Alert', icon: FiAlertTriangle, color: 'text-red-400', bg: 'from-red-500/15 to-pink-500/5', border: 'border-red-500/20', ring: 'bg-red-500' },
  };
  const status = statusConfig[health?.status] || statusConfig.healthy;
  const StatusIcon = status.icon;

  const cpu = health?.resources?.cpu_percent || 0;
  const mem = health?.resources?.memory_percent || 0;
  const disk = health?.resources?.disk_percent || 0;
  const memUsed = health?.resources?.memory_used_mb || 0;
  const memTotal = health?.resources?.memory_total_mb || 0;
  const memAvail = health?.resources?.memory_available_mb || 0;
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
  const history = health?.history || [];

  // Filtered & Sorted Processes for Task Manager
  const rawProcessList = processes.all_processes || processes.top_cpu || [];
  const filteredProcesses = useMemo(() => {
    let list = [...rawProcessList];

    // Search filter
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase().trim();
      list = list.filter(p => p.name.toLowerCase().includes(q) || String(p.pid).includes(q));
    }

    // Type filter
    if (filterType === 'apps') {
      list = list.filter(p => p.memory_mb > 25.0 || p.cpu > 0.5);
    } else if (filterType === 'high_cpu') {
      list = list.filter(p => p.cpu > 0.1);
    } else if (filterType === 'system') {
      list = list.filter(p => p.pid <= 100 || p.name.toLowerCase().includes('svchost') || p.name.toLowerCase().includes('system'));
    }

    // Sorting
    list.sort((a, b) => {
      let valA = a[sortBy];
      let valB = b[sortBy];
      if (sortBy === 'memory') {
        valA = a.memory_mb || 0;
        valB = b.memory_mb || 0;
      }
      if (typeof valA === 'string') {
        return sortOrder === 'desc' ? valB.localeCompare(valA) : valA.localeCompare(valB);
      }
      return sortOrder === 'desc' ? (valB - valA) : (valA - valB);
    });

    return list;
  }, [rawProcessList, searchTerm, filterType, sortBy, sortOrder]);

  const toggleSort = (col) => {
    if (sortBy === col) {
      setSortOrder(prev => prev === 'desc' ? 'asc' : 'desc');
    } else {
      setSortBy(col);
      setSortOrder('desc');
    }
  };

  if (loading && !health) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-dark-300 font-medium">Gathering real-time system telemetry & tasks...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/20 shadow-sm">
              <FiMonitor className="w-6 h-6 text-cyan-400" />
            </div>
            System Information & Task Manager
          </h1>
          <p className="text-dark-400 text-sm mt-1 ml-13">
            Real-time process telemetry, performance analytics, and host diagnostics
          </p>
        </div>

        {/* Action Bar */}
        <div className="flex items-center gap-3 flex-wrap">
          {/* Refresh Speed Controller */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-dark-900 border border-dark-700 text-xs">
            <span className="text-dark-400 font-medium flex items-center gap-1">
              <FiSliders className="w-3.5 h-3.5 text-cyan-400" /> Speed:
            </span>
            {[
              { label: '1s', val: 1000 },
              { label: '2s', val: 2000 },
              { label: '5s', val: 5000 },
              { label: 'Pause', val: 0 },
            ].map(({ label, val }) => (
              <button
                key={label}
                onClick={() => setRefreshInterval(val)}
                className={`px-2 py-0.5 rounded-md font-semibold transition-all ${
                  refreshInterval === val
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-dark-400 hover:text-dark-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Live indicator */}
          <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold ${
            refreshInterval === 0
              ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
              : connected
                ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
          }`}>
            <span className={`w-2 h-2 rounded-full ${
              refreshInterval === 0 ? 'bg-yellow-400' : 'bg-green-400 animate-pulse'
            }`} />
            {refreshInterval === 0 ? 'PAUSED' : connected ? 'WEBSOCKET LIVE' : 'AUTO-POLLING'}
          </span>

          {lastRefresh && (
            <span className="text-xs text-dark-500 flex items-center gap-1.5">
              <FiClock className="w-3.5 h-3.5" /> {lastRefresh.toLocaleTimeString()}
            </span>
          )}

          <button
            onClick={() => fetchHealth(false)}
            disabled={loading}
            title="Manual refresh"
            className="p-2.5 rounded-xl bg-dark-800 border border-dark-700 text-dark-300 hover:text-dark-100 hover:border-dark-600 disabled:opacity-40 transition-all"
          >
            <FiRefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Status Banner */}
      <div className={`rounded-2xl p-5 border bg-gradient-to-r ${status.bg} ${status.border} shadow-lg backdrop-blur-sm`}>
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <div className={`relative p-3.5 rounded-2xl ${status.ring}/20 border border-dark-700/40`}>
              <StatusIcon className={`w-8 h-8 ${status.color}`} />
              <span className={`absolute -top-1 -right-1 w-3.5 h-3.5 ${status.ring} rounded-full border-2 border-dark-900 animate-pulse`} />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h2 className={`text-lg font-bold ${status.color}`}>{status.label}</h2>
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-dark-900/60 text-dark-300 border border-dark-700 font-mono">
                  {system.hostname || 'Host'} &bull; {system.os} {system.architecture}
                </span>
              </div>
              <p className="text-dark-400 text-xs mt-1">
                System Uptime: <span className="text-dark-200 font-medium">{uptime.uptime_human || '—'}</span> &bull;
                Booted: {uptime.boot_time ? new Date(uptime.boot_time).toLocaleString() : '—'} &bull;
                Python: <span className="text-cyan-400 font-mono">{system.python_version}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-xs text-dark-400">Total Running Tasks</p>
              <p className="text-xl font-bold text-dark-100">{processes.total_count || 0}</p>
            </div>
            <div className="h-8 w-px bg-dark-700" />
            <div className="text-right">
              <p className="text-xs text-dark-400">Net Upload / Download</p>
              <p className="text-sm font-bold text-dark-200 font-mono">
                ↑ {network.upload_kbps || 0} KB/s &bull; ↓ {network.download_kbps || 0} KB/s
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex gap-2 bg-dark-900 border border-dark-700 rounded-xl p-1.5 shadow-sm">
        {[
          { id: 'processes', label: `Task Manager (${processes.total_count || 0})`, icon: FiTerminal },
          { id: 'performance', label: 'Performance & Gauges', icon: FiActivity },
          { id: 'system_info', label: 'System Information & Specs', icon: FiInfo },
          { id: 'services', label: 'Security Services & Engines', icon: FiShield },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveSection(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-medium transition-all flex-1 justify-center ${
              activeSection === tab.id
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/25 shadow-sm font-semibold'
                : 'text-dark-400 hover:text-dark-100 hover:bg-dark-800 border border-transparent'
            }`}
          >
            <tab.icon className="w-4 h-4" /> {tab.label}
          </button>
        ))}
      </div>

      {/* ================= TAB 1: TASK MANAGER (PROCESSES) ================= */}
      {activeSection === 'processes' && (
        <div className="space-y-4">
          {/* Quick Metrics Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-dark-400 font-medium">Overall CPU Load</p>
                <p className="text-2xl font-bold text-cyan-400 mt-1">{cpu}%</p>
                <p className="text-[10px] text-dark-500 mt-0.5">{cpuInfo.logical_cores || 1} Logical Processors</p>
              </div>
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                <FiCpu className="w-6 h-6 text-cyan-400" />
              </div>
            </div>

            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-dark-400 font-medium">Memory Allocation</p>
                <p className="text-2xl font-bold text-purple-400 mt-1">{mem}%</p>
                <p className="text-[10px] text-dark-500 mt-0.5">{memUsed} MB / {memTotal} MB</p>
              </div>
              <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
                <FiLayers className="w-6 h-6 text-purple-400" />
              </div>
            </div>

            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-dark-400 font-medium">Disk Primary Drive</p>
                <p className="text-2xl font-bold text-green-400 mt-1">{disk}%</p>
                <p className="text-[10px] text-dark-500 mt-0.5">{diskUsed} GB / {diskTotal} GB</p>
              </div>
              <div className="w-12 h-12 rounded-xl bg-green-500/10 border border-green-500/20 flex items-center justify-center">
                <FiHardDrive className="w-6 h-6 text-green-400" />
              </div>
            </div>

            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-4 flex items-center justify-between">
              <div>
                <p className="text-xs text-dark-400 font-medium">Processes Active</p>
                <p className="text-2xl font-bold text-orange-400 mt-1">{processes.total_count || 0}</p>
                <p className="text-[10px] text-dark-500 mt-0.5">{processes.running || 0} Running &bull; {processes.sleeping || 0} Idle</p>
              </div>
              <div className="w-12 h-12 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
                <FiTerminal className="w-6 h-6 text-orange-400" />
              </div>
            </div>
          </div>

          {/* Search, Filters, and Table Controls */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-4">
            <div className="flex flex-col md:flex-row items-center justify-between gap-3 mb-4">
              {/* Search Bar */}
              <div className="relative w-full md:w-80">
                <FiSearch className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Filter processes by name or PID..."
                  className="w-full pl-10 pr-4 py-2 bg-dark-800/80 border border-dark-700 rounded-xl text-xs text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 transition-all"
                />
                {searchTerm && (
                  <button
                    onClick={() => setSearchTerm('')}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-400 hover:text-dark-200"
                  >
                    <FiX className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {/* Filter Chips */}
              <div className="flex items-center gap-1.5 flex-wrap w-full md:w-auto">
                {[
                  { id: 'all', label: 'All Tasks' },
                  { id: 'apps', label: 'Active Apps (>25MB)' },
                  { id: 'high_cpu', label: 'CPU Consumers' },
                  { id: 'system', label: 'System Services' },
                ].map(({ id, label }) => (
                  <button
                    key={id}
                    onClick={() => setFilterType(id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                      filterType === id
                        ? 'bg-cyan-500 text-dark-950 font-bold shadow-sm'
                        : 'bg-dark-800 text-dark-400 hover:text-dark-200 hover:bg-dark-700'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {/* Task Manager Table */}
            <div className="overflow-x-auto rounded-xl border border-dark-800">
              <table className="w-full text-left text-xs">
                <thead className="bg-dark-950/80 border-b border-dark-800 text-dark-400 uppercase tracking-wider font-semibold">
                  <tr>
                    <th className="py-3 px-4 cursor-pointer hover:text-dark-200" onClick={() => toggleSort('name')}>
                      Process Name {sortBy === 'name' ? (sortOrder === 'desc' ? '▼' : '▲') : ''}
                    </th>
                    <th className="py-3 px-4 cursor-pointer hover:text-dark-200 w-24" onClick={() => toggleSort('pid')}>
                      PID {sortBy === 'pid' ? (sortOrder === 'desc' ? '▼' : '▲') : ''}
                    </th>
                    <th className="py-3 px-4 cursor-pointer hover:text-dark-200 w-28" onClick={() => toggleSort('status')}>
                      Status {sortBy === 'status' ? (sortOrder === 'desc' ? '▼' : '▲') : ''}
                    </th>
                    <th className="py-3 px-4 cursor-pointer hover:text-dark-200 w-36" onClick={() => toggleSort('cpu')}>
                      CPU Usage {sortBy === 'cpu' ? (sortOrder === 'desc' ? '▼' : '▲') : ''}
                    </th>
                    <th className="py-3 px-4 cursor-pointer hover:text-dark-200 w-44" onClick={() => toggleSort('memory')}>
                      Memory (RAM) {sortBy === 'memory' ? (sortOrder === 'desc' ? '▼' : '▲') : ''}
                    </th>
                    <th className="py-3 px-4 text-right w-28">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-800/60 font-mono">
                  {filteredProcesses.map((p) => {
                    const isSystem = p.is_critical || p.pid <= 4;
                    const cpuColor = p.cpu > 25 ? 'text-red-400 font-bold' : p.cpu > 5 ? 'text-yellow-400 font-bold' : 'text-dark-200';
                    const memColor = p.memory_mb > 500 ? 'text-purple-400 font-bold' : p.memory_mb > 100 ? 'text-cyan-400' : 'text-dark-300';

                    return (
                      <tr key={p.pid} className="hover:bg-dark-800/40 transition-colors">
                        <td className="py-2.5 px-4 font-sans font-medium text-dark-100 flex items-center gap-2.5 min-w-[200px]">
                          <div className={`p-1.5 rounded-lg ${isSystem ? 'bg-dark-800 text-dark-400' : 'bg-cyan-500/10 text-cyan-400'}`}>
                            {isSystem ? <FiShield className="w-3.5 h-3.5" /> : <FiBox className="w-3.5 h-3.5" />}
                          </div>
                          <span className="truncate max-w-xs" title={p.name}>{p.name}</span>
                          {isSystem && (
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-dark-800 text-dark-400 font-mono">SYSTEM</span>
                          )}
                        </td>
                        <td className="py-2.5 px-4 text-dark-400 font-mono">{p.pid}</td>
                        <td className="py-2.5 px-4">
                          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-sans font-semibold capitalize ${
                            p.status === 'running'
                              ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                              : 'bg-dark-800 text-dark-400'
                          }`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${p.status === 'running' ? 'bg-green-400' : 'bg-dark-500'}`} />
                            {p.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-4">
                          <div className="flex items-center gap-2">
                            <span className={`w-12 text-right ${cpuColor}`}>{p.cpu}%</span>
                            <div className="w-16 bg-dark-800 rounded-full h-1.5 overflow-hidden">
                              <div className={`h-full ${p.cpu > 25 ? 'bg-red-500' : p.cpu > 5 ? 'bg-yellow-500' : 'bg-cyan-500'}`} style={{ width: `${Math.min(p.cpu * 2, 100)}%` }} />
                            </div>
                          </div>
                        </td>
                        <td className="py-2.5 px-4">
                          <div className="flex items-center gap-2">
                            <span className={`w-24 ${memColor}`}>{p.memory_mb} MB</span>
                            <span className="text-dark-500 text-[10px]">({p.memory_percent}%)</span>
                          </div>
                        </td>
                        <td className="py-2.5 px-4 text-right">
                          <button
                            onClick={() => setTargetProcess(p)}
                            disabled={isSystem}
                            title={isSystem ? 'System protected process cannot be terminated' : `End process ${p.name}`}
                            className={`px-2.5 py-1 rounded-lg text-[11px] font-sans font-medium transition-all ${
                              isSystem
                                ? 'opacity-30 cursor-not-allowed text-dark-500'
                                : 'bg-red-500/10 hover:bg-red-500 hover:text-white text-red-400 border border-red-500/20 hover:border-red-500'
                            }`}
                          >
                            End Task
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                  {filteredProcesses.length === 0 && (
                    <tr>
                      <td colSpan="6" className="py-8 text-center text-dark-400 font-sans">
                        No processes matched your filter criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between mt-3 text-xs text-dark-500 font-sans px-1">
              <span>Showing {filteredProcesses.length} of {processes.total_count || 0} active processes</span>
              <span>Sorted by <strong className="text-dark-300 capitalize">{sortBy} ({sortOrder})</strong></span>
            </div>
          </div>
        </div>
      )}

      {/* ================= TAB 2: PERFORMANCE & GAUGES ================= */}
      {activeSection === 'performance' && (
        <div className="space-y-6">
          {/* Real-Time Area Charts */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiActivity className="w-4 h-4 text-cyan-400" /> Live Resource Graphs (History Buffer)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <MiniAreaChart
                data={history.map(h => ({ value: h.cpu }))}
                color="#06b6d4"
                label="CPU Utilization History"
                currentVal={cpu}
                unit="%"
              />
              <MiniAreaChart
                data={history.map(h => ({ value: h.memory }))}
                color="#a78bfa"
                label="RAM Allocation History"
                currentVal={mem}
                unit="%"
              />
              <MiniAreaChart
                data={history.map(h => ({ value: Math.min(100, (h.download_kbps || 0) / 10) }))}
                color="#22c55e"
                label="Network Throughput (Download)"
                currentVal={network.download_kbps || 0}
                unit="KB/s"
              />
            </div>
          </div>

          {/* Resource Gauges */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-6 flex items-center gap-2">
              <FiZap className="w-4 h-4 text-cyan-400" /> Resource Gauges & Allocations
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
              <div className="flex flex-col items-center">
                <CircularGauge value={cpu} label="CPU Overall" sublabel={`${cpu}%`} color="#06b6d4" />
                <div className="mt-3 w-full max-w-[180px]"><MiniBar value={cpu} color="bg-cyan-500" /></div>
              </div>
              <div className="flex flex-col items-center">
                <CircularGauge value={mem} label="Physical RAM" sublabel={`${memUsed}MB / ${memTotal}MB`} color="#a78bfa" />
                <div className="mt-3 w-full max-w-[180px]"><MiniBar value={mem} color="bg-purple-500" /></div>
              </div>
              <div className="flex flex-col items-center">
                <CircularGauge value={disk} label="Disk Storage" sublabel={`${diskUsed}GB / ${diskTotal}GB`} color="#22c55e" />
                <div className="mt-3 w-full max-w-[180px]"><MiniBar value={disk} color="bg-green-500" /></div>
              </div>
              <div className="flex flex-col items-center">
                <CircularGauge value={memDetail.swap_percent || 0} label="Swap / Pagefile" sublabel={`${memDetail.swap_used_mb || 0}MB`} color="#f472b6" />
                <div className="mt-3 w-full max-w-[180px]"><MiniBar value={memDetail.swap_percent || 0} color="bg-pink-500" /></div>
              </div>
            </div>
          </div>

          {/* CPU & Memory Hardware Details */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* CPU Details */}
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <FiCpu className="w-4 h-4 text-cyan-400" /> Processor Architecture
              </h3>
              <div className="space-y-3">
                {[
                  { label: 'Processor Name', value: system.processor || 'Unknown' },
                  { label: 'Physical Cores', value: cpuInfo.physical_cores || 0 },
                  { label: 'Logical Cores / Threads', value: cpuInfo.logical_cores || 0 },
                  { label: 'Current Clock Speed', value: `${cpuInfo.frequency_current || 0} MHz` },
                  { label: 'Max Base Frequency', value: `${cpuInfo.frequency_max || 0} MHz` },
                  { label: 'Context Switches', value: (cpuInfo.ctx_switches || 0).toLocaleString() },
                  { label: 'System Interrupts', value: (cpuInfo.interrupts || 0).toLocaleString() },
                ].map(({ label, value }, i) => (
                  <div key={i} className="flex justify-between items-center text-xs py-1.5 border-b border-dark-800 last:border-0">
                    <span className="text-dark-400">{label}</span>
                    <span className="text-dark-100 font-mono font-medium truncate max-w-xs">{value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Memory Details */}
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <FiLayers className="w-4 h-4 text-purple-400" /> Memory Breakdown
              </h3>
              <div className="space-y-3">
                {[
                  { label: 'Total Physical Memory', value: `${memTotal} MB (${(memTotal/1024).toFixed(1)} GB)` },
                  { label: 'In Use (Allocated)', value: `${memUsed} MB (${(memUsed/1024).toFixed(1)} GB)`, color: 'text-purple-400' },
                  { label: 'Available (Free)', value: `${memAvail} MB (${(memAvail/1024).toFixed(1)} GB)`, color: 'text-green-400' },
                  { label: 'Cached System Memory', value: `${memDetail.cached_mb || 0} MB` },
                  { label: 'Swap Total', value: `${memDetail.swap_total_mb || 0} MB` },
                  { label: 'Swap In Use', value: `${memDetail.swap_used_mb || 0} MB (${memDetail.swap_percent || 0}%)` },
                ].map(({ label, value, color }, i) => (
                  <div key={i} className="flex justify-between items-center text-xs py-1.5 border-b border-dark-800 last:border-0">
                    <span className="text-dark-400">{label}</span>
                    <span className={`font-mono font-medium ${color || 'text-dark-100'}`}>{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Disk Partitions & Network Interfaces */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Disk Partitions */}
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <FiHardDrive className="w-4 h-4 text-green-400" /> Storage Partitions ({diskParts.length})
              </h3>
              <div className="space-y-3">
                {diskParts.map((part, i) => (
                  <div key={i} className="bg-dark-800/50 rounded-xl p-3.5 border border-dark-700/50">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2.5">
                        <FiHardDrive className="w-4 h-4 text-green-400" />
                        <div>
                          <p className="text-xs font-semibold text-dark-100">{part.device} ({part.fstype})</p>
                          <p className="text-[10px] text-dark-400">Mount: {part.mountpoint}</p>
                        </div>
                      </div>
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded-lg ${
                        part.percent > 90 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                      }`}>{part.percent}%</span>
                    </div>
                    <MiniBar value={part.percent} color="bg-green-500" />
                    <div className="flex justify-between mt-1.5 text-[10px] text-dark-500 font-mono">
                      <span>{part.used_gb} GB used</span>
                      <span>{part.free_gb} GB free</span>
                      <span>{part.total_gb} GB total</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Network Adapters */}
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <FiWifi className="w-4 h-4 text-cyan-400" /> Network Adapters (IPv4)
              </h3>
              <div className="space-y-2">
                {(network.interfaces || []).map((iface, i) => (
                  <div key={i} className="flex items-center justify-between bg-dark-800/50 rounded-xl px-4 py-2.5 border border-dark-700/50 text-xs">
                    <div className="flex items-center gap-2.5">
                      <FiGlobe className="w-4 h-4 text-cyan-400" />
                      <div>
                        <p className="font-semibold text-dark-100">{iface.name}</p>
                        <p className="text-[10px] text-dark-500">Mask: {iface.netmask || '—'}</p>
                      </div>
                    </div>
                    <span className="font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                      {iface.ip}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ================= TAB 3: SYSTEM INFORMATION & SPECS ================= */}
      {activeSection === 'system_info' && (
        <div className="space-y-6">
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-base font-bold text-dark-100 mb-4 flex items-center gap-2.5">
              <FiInfo className="w-5 h-5 text-cyan-400" /> Host & Environment Specifications
            </h3>
            <p className="text-xs text-dark-400 mb-6">
              Comprehensive hardware, operating system, and runtime execution profile of the host server.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[
                { label: 'Operating System', value: system.os, icon: FiMonitor },
                { label: 'OS Build / Version', value: system.os_version, icon: FiMonitor },
                { label: 'Platform String', value: system.platform, icon: FiGlobe },
                { label: 'Architecture', value: system.architecture, icon: FiCpu },
                { label: 'Processor Spec', value: system.processor, icon: FiCpu },
                { label: 'Python Runtime', value: system.python_version, icon: FiZap },
                { label: 'Host Machine Node', value: system.hostname, icon: FiServer },
                { label: 'System Boot Time', value: uptime.boot_time ? new Date(uptime.boot_time).toLocaleString() : 'N/A', icon: FiClock },
                { label: 'Cumulative Uptime', value: uptime.uptime_human || 'N/A', icon: FiClock },
                { label: 'ThreatShield Version', value: 'v2.4.0 (Enterprise Defense)', icon: FiShield },
                { label: 'Database Storage', value: 'SQLite Local Store (Secured)', icon: FiDatabase },
                { label: 'Real-time Inspector', value: 'FastAPI ASGI Asynchronous Loop', icon: FiActivity },
              ].map(({ label, value, icon: Icon }, idx) => (
                <div key={idx} className="bg-dark-800/60 rounded-xl p-4 border border-dark-700/60 hover:border-dark-600 transition-all flex items-start gap-3.5">
                  <div className="p-2.5 rounded-lg bg-dark-700 border border-dark-600 shrink-0">
                    <Icon className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-[10px] text-dark-400 uppercase tracking-wider font-semibold">{label}</p>
                    <p className="text-xs text-dark-100 font-medium font-mono mt-0.5 truncate" title={String(value)}>
                      {String(value || 'N/A')}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ================= TAB 4: SECURITY SERVICES & ENGINES ================= */}
      {activeSection === 'services' && (
        <div className="space-y-6">
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-base font-bold text-dark-100 mb-2 flex items-center gap-2.5">
              <FiShield className="w-5 h-5 text-cyan-400" /> Core Cyber Defense Engines Status
            </h3>
            <p className="text-xs text-dark-400 mb-6">
              Telemetry and connectivity verification for ThreatShield's defensive subsystems.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {[
                { name: 'Database Store', key: 'database', desc: 'SQLite relational persistence for scans, reports, and accounts' },
                { name: 'DMZ Network Firewall', key: 'firewall', desc: '4-zone stateful packet filtering and live traffic injection' },
                { name: 'Real-time Antivirus Guard', key: 'realtime_protection', desc: 'Continuous directory and heuristic file inspection' },
                { name: 'Email Monitor (IMAP)', key: 'email_monitor', desc: 'Automated mailbox stream ingest & attachment scanning' },
                { name: 'ClamAV Antivirus Daemon', key: 'clamav', desc: 'Local daemon signature scanner integration' },
              ].map(({ name, key, desc }) => {
                const val = services[key] || 'active';
                const isActive = val === 'active';
                return (
                  <div key={key} className={`rounded-xl p-5 border transition-all ${
                    isActive ? 'bg-green-500/5 border-green-500/20' : 'bg-yellow-500/5 border-yellow-500/20'
                  }`}>
                    <div className="flex items-center gap-3 mb-2">
                      <div className={`p-2.5 rounded-lg ${isActive ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                        <FiShield className="w-5 h-5" />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-dark-100">{name}</h4>
                        <span className={`text-[10px] font-bold uppercase tracking-wider ${isActive ? 'text-green-400' : 'text-yellow-400'}`}>
                          ● {val}
                        </span>
                      </div>
                    </div>
                    <p className="text-xs text-dark-400 mt-2">{desc}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ================= KILL PROCESS CONFIRMATION MODAL ================= */}
      {targetProcess && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
          <div className="bg-dark-900 border border-dark-700 rounded-2xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-red-400">
              <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20">
                <FiXOctagon className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-dark-100">End Process (Kill Task)</h3>
                <p className="text-xs text-dark-400">Task Manager Process Termination</p>
              </div>
            </div>

            <div className="bg-dark-950/80 rounded-xl p-4 border border-dark-800 space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-dark-400">Process Name:</span>
                <span className="text-dark-100 font-bold font-mono">{targetProcess.name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-dark-400">Process ID (PID):</span>
                <span className="text-cyan-400 font-mono font-bold">{targetProcess.pid}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-dark-400">Current CPU:</span>
                <span className="text-dark-200 font-mono">{targetProcess.cpu}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-dark-400">Memory Usage:</span>
                <span className="text-dark-200 font-mono">{targetProcess.memory_mb} MB ({targetProcess.memory_percent}%)</span>
              </div>
            </div>

            <p className="text-xs text-yellow-400/90 bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-3">
              ⚠️ Warning: Ending an active application process will immediately close the program and any unsaved state will be lost.
            </p>

            <label className="flex items-center gap-2 text-xs text-dark-300 cursor-pointer">
              <input
                type="checkbox"
                checked={forceKill}
                onChange={(e) => setForceKill(e.target.checked)}
                className="rounded border-dark-700 text-red-500 focus:ring-0 bg-dark-800"
              />
              <span>Force termination immediately (SIGKILL / forced exit)</span>
            </label>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => { setTargetProcess(null); setForceKill(false); }}
                disabled={killing}
                className="px-4 py-2 rounded-xl bg-dark-800 hover:bg-dark-700 text-dark-300 text-xs font-semibold transition-all"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleKillProcess}
                disabled={killing}
                className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold shadow-md transition-all flex items-center gap-2"
              >
                {killing && <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />}
                {killing ? 'Terminating...' : 'End Task'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
