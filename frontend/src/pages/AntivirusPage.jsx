import { useState, useEffect, useRef, useCallback } from 'react';
import toast from 'react-hot-toast';
import {
  FiShield, FiShieldOff, FiPlay, FiSquare, FiUpload, FiFile,
  FiCheckCircle, FiAlertTriangle, FiXOctagon, FiRefreshCw, FiInfo,
  FiSettings, FiFolder, FiLock, FiUnlock, FiBell,
  FiTrash2, FiSearch, FiCpu, FiActivity, FiZap, FiRadio,
  FiEye, FiGlobe, FiHardDrive, FiWifi, FiClock, FiTrendingUp,
  FiAlertCircle, FiServer, FiArrowRight, FiToggleLeft, FiToggleRight,
  FiTerminal, FiMinus, FiLink,
} from 'react-icons/fi';
import { antivirusAPI, realtimeAPI } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';

const ENGINES = [
  { name: 'Hash Lookup', desc: 'Known malware DB', icon: FiSearch, status: 'active' },
  { name: 'Entropy Analysis', desc: 'Packing detection', icon: FiActivity, status: 'active' },
  { name: 'String Analysis', desc: 'Suspicious strings', icon: FiFile, status: 'active' },
  { name: 'PE Analysis', desc: 'Executable inspection', icon: FiCpu, status: 'active' },
  { name: 'Risk Scoring', desc: 'ML-based scoring', icon: FiTrendingUp, status: 'active' },
  { name: 'Network Scanner', desc: 'Connection analysis', icon: FiGlobe, status: 'active' },
  { name: 'Firewall Integration', desc: 'Auto-block threats', icon: FiShield, status: 'active' },
  { name: 'Zone Protection', desc: 'DMZ zone monitoring', icon: FiServer, status: 'active' },
];

const ZONE_COLORS = { Public: '#ef4444', DMZ: '#f59e0b', Internal: '#22c55e', Management: '#8b5cf6', Unknown: '#6b7280' };

const ThreatLevelBar = ({ score }) => {
  const getLevel = (s) => {
    if (s <= 20) return { label: 'Secure', color: 'bg-green-500', text: 'text-green-400', width: '20%' };
    if (s <= 40) return { label: 'Low Risk', color: 'bg-emerald-500', text: 'text-emerald-400', width: '40%' };
    if (s <= 60) return { label: 'Moderate', color: 'bg-yellow-500', text: 'text-yellow-400', width: '60%' };
    if (s <= 80) return { label: 'Elevated', color: 'bg-orange-500', text: 'text-orange-400', width: '80%' };
    return { label: 'Critical', color: 'bg-red-500', text: 'text-red-400', width: '100%' };
  };
  const level = getLevel(score);
  return (
    <div>
      <div className="flex justify-between items-center mb-2">
        <span className="text-xs text-dark-400">System Threat Level</span>
        <span className={`text-xs font-semibold ${level.text}`}>{level.label} ({score}%)</span>
      </div>
      <div className="w-full h-2.5 bg-dark-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${level.color} transition-all duration-500`} style={{ width: level.width }} />
      </div>
    </div>
  );
};

export default function AntivirusPage() {
  const [status, setStatus] = useState(null);
  const [stats, setStats] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);
  const [protectionEnabled, setProtectionEnabled] = useState(true);
  const [autoScanEnabled, setAutoScanEnabled] = useState(true);
  const [autoQuarantineEnabled, setAutoQuarantineEnabled] = useState(true);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [activeTab, setActiveTab] = useState('overview');
  const [folderPath, setFolderPath] = useState('');
  const [monitoredPaths, setMonitoredPaths] = useState([]);
  const [liveScanResults, setLiveScanResults] = useState([]);
  const [scanSpeed, setScanSpeed] = useState(0);
  const [filesPerMin, setFilesPerMin] = useState(0);
  const [fwStatus, setFwStatus] = useState(null);
  const [fwIntegrationEnabled, setFwIntegrationEnabled] = useState(true);
  const [threatBlockedIps, setThreatBlockedIps] = useState([]);
  const [threatLog, setThreatLog] = useState([]);
  const [blockIp, setBlockIp] = useState('');
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);
  const refreshInterval = useRef(null);

  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'scan_result') {
      const result = msg.data;
      setLiveScanResults((prev) => [result, ...prev].slice(0, 50));
      setScanHistory((prev) => [result, ...prev].slice(0, 200));
      setStats((prev) => {
        if (!prev) return prev;
        const newStats = { ...prev, total_scans: (prev.total_scans || 0) + 1 };
        if (result.classification === 'safe') newStats.safe = (prev.safe || 0) + 1;
        else if (result.classification === 'suspicious') newStats.suspicious = (prev.suspicious || 0) + 1;
        else if (result.classification === 'malicious') newStats.malicious = (prev.malicious || 0) + 1;
        return newStats;
      });
      if (result.classification === 'malicious') {
        toast.error(`MALICIOUS: "${result.filename}" (Score: ${result.risk_score})`);
        if (result.firewall_blocked) {
          toast.success(`IP ${result.source_ip} blocked by firewall`);
          fetchFirewallData();
        }
      } else if (result.classification === 'suspicious') {
        toast(`Suspicious: "${result.filename}" (Score: ${result.risk_score})`, { icon: '⚠️' });
      }
    } else if (msg.type === 'notification') {
      setNotifications((prev) => [msg.data, ...prev].slice(0, 100));
      if (msg.data.type === 'threat') toast.error(msg.data.message);
    }
  }, []);

  const { connected } = useWebSocket(handleWsMessage);

  const fetchData = useCallback(async () => {
    try {
      const [statusRes, statsRes, notifRes, histRes] = await Promise.all([
        antivirusAPI.getStatus(),
        antivirusAPI.getStats(),
        antivirusAPI.getNotifications(),
        antivirusAPI.getScanHistory(),
      ]);
      setStatus(statusRes.data);
      setStats(statsRes.data);
      setNotifications(notifRes.data.notifications || []);
      setScanHistory(histRes.data.history || []);
      setProtectionEnabled(statusRes.data.protection_enabled);
      setAutoScanEnabled(statusRes.data.auto_scan_enabled);
      setAutoQuarantineEnabled(statusRes.data.auto_quarantine_enabled);
      setMonitoredPaths(statusRes.data.monitored_paths || []);
    } catch {
      console.error('Failed to fetch antivirus data');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchFirewallData = useCallback(async () => {
    try {
      const res = await antivirusAPI.getFirewallStatus();
      setFwStatus(res.data);
      setFwIntegrationEnabled(res.data.firewall_enabled);
      setThreatBlockedIps(res.data.threat_blocked_ips || []);
      setThreatLog(res.data.threat_log || []);
    } catch {
      console.error('Failed to fetch firewall data');
    }
  }, []);

  useEffect(() => {
    fetchData();
    fetchFirewallData();
    refreshInterval.current = setInterval(() => { fetchData(); fetchFirewallData(); }, 15000);
    return () => clearInterval(refreshInterval.current);
  }, [fetchData, fetchFirewallData]);

  useEffect(() => {
    if (liveScanResults.length > 1) {
      const recent = liveScanResults.slice(0, 10);
      setFilesPerMin(Math.round(recent.length * 6));
    }
  }, [liveScanResults]);

  const toggleProtection = async () => {
    try {
      if (protectionEnabled) { await antivirusAPI.disableProtection(); setProtectionEnabled(false); toast.success('Real-time protection disabled'); }
      else { await antivirusAPI.enableProtection(); setProtectionEnabled(true); toast.success('Real-time protection enabled'); }
    } catch { toast.error('Failed to toggle protection'); }
  };

  const toggleAutoScan = async () => {
    try {
      if (autoScanEnabled) { await antivirusAPI.disableAutoScan(); setAutoScanEnabled(false); toast.success('Auto-scan disabled'); }
      else { await antivirusAPI.enableAutoScan(); setAutoScanEnabled(true); toast.success('Auto-scan enabled'); }
    } catch { toast.error('Failed to toggle auto-scan'); }
  };

  const toggleAutoQuarantine = async () => {
    try {
      if (autoQuarantineEnabled) { await antivirusAPI.disableAutoQuarantine(); setAutoQuarantineEnabled(false); toast.success('Auto-quarantine disabled'); }
      else { await antivirusAPI.enableAutoQuarantine(); setAutoQuarantineEnabled(true); toast.success('Auto-quarantine enabled'); }
    } catch { toast.error('Failed to toggle auto-quarantine'); }
  };

  const toggleFwIntegration = async () => {
    try {
      if (fwIntegrationEnabled) { await antivirusAPI.disableFirewallIntegration(); setFwIntegrationEnabled(false); toast.success('Firewall integration disabled'); }
      else { await antivirusAPI.enableFirewallIntegration(); setFwIntegrationEnabled(true); toast.success('Firewall integration enabled'); }
      fetchFirewallData();
    } catch { toast.error('Failed to toggle firewall integration'); }
  };

  const handleStartAutoScan = async () => {
    try { await realtimeAPI.startAutoScan(); setAutoScanEnabled(true); toast.success('Auto-scan started'); }
    catch { toast.error('Failed to start auto-scan'); }
  };

  const handleStopAutoScan = async () => {
    try { await realtimeAPI.stopAutoScan(); setAutoScanEnabled(false); toast.success('Auto-scan stopped'); }
    catch { toast.error('Failed to stop auto-scan'); }
  };

  const handleScanFile = async (e) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;
    setScanning(true);
    setUploadProgress(0);
    try {
      const formData = new FormData();
      for (let i = 0; i < fileList.length; i++) formData.append('file', fileList[i]);
      const result = await antivirusAPI.scanShared(formData, (e) => {
        if (e.total) setUploadProgress(Math.round((e.loaded / e.total) * 100));
      });
      const data = result.data;
      if (data.classification === 'safe') toast.success(`"${data.filename}" is safe!`);
      else if (data.classification === 'suspicious') toast(`"${data.filename}" suspicious (Score: ${data.risk_score})`, { icon: '⚠️' });
      else if (data.classification === 'malicious') toast.error(`"${data.filename}" MALICIOUS! (Score: ${data.risk_score})`);
      fetchData();
      fetchFirewallData();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Scan failed');
    } finally {
      setScanning(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleScanFolder = async (e) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;
    setScanning(true);
    try {
      const formData = new FormData();
      for (let i = 0; i < fileList.length; i++) formData.append('files', fileList[i]);
      const result = await antivirusAPI.scanFolder(formData);
      const data = result.data;
      const scanned = data.results || [];
      const threats = scanned.filter((r) => r.classification !== 'safe');
      if (threats.length === 0) toast.success(`All ${scanned.length} files are safe!`);
      else toast(`Detected ${threats.length} threat(s) in ${scanned.length} files.`, { icon: '⚠️' });
      fetchData();
      fetchFirewallData();
    } catch { toast.error('Folder scan failed'); }
    finally { setScanning(false); if (folderInputRef.current) folderInputRef.current.value = ''; }
  };

  const handleAddMonitoredPath = async () => {
    if (!folderPath.trim()) { toast.error('Enter a folder path'); return; }
    try { await antivirusAPI.addMonitoredPath(folderPath); setFolderPath(''); toast.success('Folder added to monitoring'); fetchData(); }
    catch { toast.error('Failed to add folder'); }
  };

  const handleRemoveMonitoredPath = async (path) => {
    try { await antivirusAPI.removeMonitoredPath(path); toast.success('Folder removed'); fetchData(); }
    catch { toast.error('Failed to remove folder'); }
  };

  const handleBlockIp = async () => {
    if (!blockIp.trim()) { toast.error('Enter an IP address'); return; }
    try { await antivirusAPI.blockThreatIp(blockIp, 'Manual block from Antivirus'); setBlockIp(''); toast.success(`IP ${blockIp} blocked`); fetchFirewallData(); }
    catch { toast.error('Failed to block IP'); }
  };

  const handleUnblockIp = async (ip) => {
    try { await antivirusAPI.unblockThreatIp(ip); toast.success(`IP ${ip} unblocked`); fetchFirewallData(); }
    catch { toast.error('Failed to unblock IP'); }
  };

  const clearNotifications = async () => {
    try { await antivirusAPI.clearNotifications(); setNotifications([]); toast.success('Notifications cleared'); }
    catch { toast.error('Failed to clear'); }
  };

  const getRiskColor = (score) => score <= 30 ? 'text-green-400' : score <= 70 ? 'text-yellow-400' : 'text-red-400';
  const getClassBadge = (cls) => ({
    safe: 'bg-green-500/20 text-green-400 border-green-500/30',
    suspicious: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    malicious: 'bg-red-500/20 text-red-400 border-red-500/30',
  }[cls?.toLowerCase()] || 'bg-dark-700 text-dark-300 border-dark-600');

  const formatTime = (ts) => ts ? new Date(ts).toLocaleTimeString() : '';

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-dark-400 font-medium">Loading antivirus protection...</p>
        </div>
      </div>
    );
  }

  const totalScans = stats?.total_scans || 0;
  const safeCount = stats?.safe || 0;
  const suspiciousCount = stats?.suspicious || 0;
  const maliciousCount = stats?.malicious || 0;
  const threatLevel = totalScans > 0 ? Math.min(100, Math.round(((maliciousCount * 100 + suspiciousCount * 50) / totalScans))) : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-3">
            <div className={`p-2 rounded-xl ${protectionEnabled ? 'bg-gradient-to-br from-green-500/20 to-emerald-500/20 border border-green-500/20' : 'bg-gradient-to-br from-red-500/20 to-pink-500/20 border border-red-500/20'}`}>
              {protectionEnabled ? <FiShield className="w-6 h-6 text-green-400" /> : <FiShieldOff className="w-6 h-6 text-red-400" />}
            </div>
            Antivirus Protection
          </h1>
          <p className="text-dark-400 text-sm mt-1 ml-13">Real-time defense with DMZ firewall integration</p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold ${connected ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
            {connected ? 'LIVE' : 'OFFLINE'}
          </span>
          {autoScanEnabled ? (
            <button onClick={handleStopAutoScan} className="px-4 py-2.5 bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white rounded-xl text-sm font-semibold shadow-lg shadow-red-500/20 transition-all flex items-center gap-2">
              <FiSquare className="w-4 h-4" /> Stop Auto-Scan
            </button>
          ) : (
            <button onClick={handleStartAutoScan} className="px-4 py-2.5 bg-gradient-to-r from-green-600 to-green-500 hover:from-green-500 hover:to-green-400 text-white rounded-xl text-sm font-semibold shadow-lg shadow-green-500/20 transition-all flex items-center gap-2">
              <FiPlay className="w-4 h-4" /> Start Auto-Scan
            </button>
          )}
        </div>
      </div>

      {/* Protection Status Banner */}
      <div className={`rounded-2xl p-6 border ${protectionEnabled ? 'bg-gradient-to-r from-green-500/10 to-emerald-500/5 border-green-500/20' : 'bg-gradient-to-r from-red-500/10 to-pink-500/5 border-red-500/20'}`}>
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <div className={`relative p-4 rounded-2xl ${protectionEnabled ? 'bg-green-500/20' : 'bg-red-500/20'}`}>
              {protectionEnabled ? <FiShield className="w-10 h-10 text-green-400" /> : <FiShieldOff className="w-10 h-10 text-red-400" />}
              {protectionEnabled && <span className="absolute -top-1 -right-1 w-4 h-4 bg-green-400 rounded-full border-2 border-dark-900 animate-pulse" />}
            </div>
            <div>
              <h2 className={`text-xl font-bold ${protectionEnabled ? 'text-green-400' : 'text-red-400'}`}>
                {protectionEnabled ? 'Protection Active' : 'Protection Disabled'}
              </h2>
              <p className="text-dark-400 text-sm mt-0.5">
                {ENGINES.length} detection engines &bull; {fwIntegrationEnabled ? 'Firewall integrated' : 'Firewall disconnected'}
              </p>
            </div>
          </div>
          <button onClick={toggleProtection} className={`px-6 py-3 rounded-xl font-semibold text-sm transition-all flex items-center gap-2 shadow-lg ${protectionEnabled ? 'bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white shadow-red-500/20' : 'bg-gradient-to-r from-green-600 to-green-500 hover:from-green-500 hover:to-green-400 text-white shadow-green-500/20'}`}>
            {protectionEnabled ? <><FiShieldOff className="w-4 h-4" /> Disable</> : <><FiShield className="w-4 h-4" /> Enable</>}
          </button>
        </div>
      </div>

      {/* Combined Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5">
          <ThreatLevelBar score={threatLevel} />
          <div className="grid grid-cols-4 gap-4 mt-4">
            {[
              { label: 'Total Scans', value: totalScans, color: 'text-cyan-400', bg: 'from-cyan-500/20 to-blue-500/20' },
              { label: 'Safe', value: safeCount, color: 'text-green-400', bg: 'from-green-500/20 to-emerald-500/20' },
              { label: 'Suspicious', value: suspiciousCount, color: 'text-yellow-400', bg: 'from-yellow-500/20 to-orange-500/20' },
              { label: 'Malicious', value: maliciousCount, color: 'text-red-400', bg: 'from-red-500/20 to-pink-500/20' },
            ].map(({ label, value, color, bg }, i) => (
              <div key={i} className={`bg-gradient-to-br ${bg} border border-dark-700/50 rounded-xl p-3 text-center`}>
                <p className={`text-xl font-bold ${color}`}>{value}</p>
                <p className="text-[10px] text-dark-400 font-medium">{label}</p>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5">
          <h4 className="text-xs font-semibold text-dark-400 uppercase tracking-wider mb-3">Live Metrics</h4>
          <div className="space-y-3">
            {[
              { label: 'Scan Speed', value: `${filesPerMin} files/min`, color: 'text-cyan-400' },
              { label: 'Monitored Paths', value: monitoredPaths.length, color: 'text-cyan-400' },
              { label: 'Threat IPs Blocked', value: threatBlockedIps.length, color: 'text-red-400' },
              { label: 'Firewall Rules', value: fwStatus?.active_rules || 0, color: 'text-cyan-400' },
              { label: 'Unread Alerts', value: notifications.filter(n => !n.read).length, color: 'text-yellow-400' },
            ].map(({ label, value, color }, i) => (
              <div key={i} className="flex items-center justify-between">
                <span className="text-xs text-dark-400">{label}</span>
                <span className={`text-sm font-bold ${color}`}>{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Protection Settings */}
      <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
          <FiSettings className="w-4 h-4 text-cyan-400" /> Protection Settings
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: 'Real-Time Auto-Scan', desc: 'Scan files on access', enabled: autoScanEnabled, toggle: toggleAutoScan, icon: FiZap },
            { label: 'Auto-Quarantine', desc: 'Isolate threats instantly', enabled: autoQuarantineEnabled, toggle: toggleAutoQuarantine, icon: FiLock },
            { label: 'Firewall Integration', desc: 'Auto-block threat IPs', enabled: fwIntegrationEnabled, toggle: toggleFwIntegration, icon: FiShield },
            { label: 'Notifications', desc: `${notifications.filter(n => !n.read).length} unread alerts`, action: clearNotifications, icon: FiBell, isButton: true },
          ].map(({ label, desc, enabled, toggle, icon: Icon, action, isButton }, i) => (
            <div key={i} className="flex items-center justify-between bg-dark-800/50 rounded-xl p-4 border border-dark-700/50">
              <div className="flex items-center gap-3">
                <Icon className={`w-5 h-5 ${enabled ? 'text-cyan-400' : 'text-dark-500'}`} />
                <div>
                  <p className="text-sm font-medium text-dark-100">{label}</p>
                  <p className="text-xs text-dark-400">{desc}</p>
                </div>
              </div>
              {isButton ? (
                <button onClick={action} className="px-3 py-1.5 text-xs bg-dark-700 hover:bg-dark-600 text-dark-300 rounded-lg transition-colors">Clear</button>
              ) : (
                <button onClick={toggle} className={`w-12 h-6 rounded-full transition-colors relative ${enabled ? 'bg-cyan-600' : 'bg-dark-700'}`}>
                  <div className={`w-5 h-5 rounded-full bg-white absolute top-0.5 transition-all ${enabled ? 'left-6' : 'left-0.5'}`} />
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Detection Engines */}
      <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
        <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
          <FiCpu className="w-4 h-4 text-cyan-400" /> Detection Engines ({ENGINES.length})
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {ENGINES.map((engine, i) => (
            <div key={i} className="flex items-center gap-3 bg-dark-800/50 rounded-xl p-3 border border-dark-700/50 hover:border-dark-600 transition-all">
              <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                <engine.icon className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-dark-100 truncate">{engine.name}</p>
                <p className="text-[10px] text-dark-400">{engine.desc}</p>
              </div>
              <span className="w-2 h-2 rounded-full bg-green-400 shrink-0" />
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 bg-dark-900 border border-dark-700 rounded-xl p-1.5 overflow-x-auto">
        {[
          { id: 'overview', label: 'Live Feed', icon: FiRadio },
          { id: 'scan', label: 'Scan Files', icon: FiSearch },
          { id: 'firewall', label: 'Firewall', icon: FiShield },
          { id: 'threats', label: 'Threat IPs', icon: FiXOctagon },
          { id: 'notifications', label: 'Alerts', icon: FiBell },
          { id: 'history', label: 'History', icon: FiClock },
          { id: 'monitor', label: 'Folders', icon: FiFolder },
        ].map((tab) => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-3 py-2.5 rounded-lg text-xs font-medium transition-all justify-center whitespace-nowrap ${
              activeTab === tab.id ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm' : 'text-dark-400 hover:text-dark-100 hover:bg-dark-800 border border-transparent'
            }`}>
            <tab.icon className="w-3.5 h-3.5" /> {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-4">
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiInfo className="w-4 h-4 text-cyan-400" /> How Protection Works
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { icon: FiCpu, title: '8 Detection Engines', desc: 'Hash, entropy, strings, PE, ML scoring, network, firewall integration, and zone protection.', color: 'text-cyan-400', bg: 'from-cyan-500/20 to-blue-500/20' },
                { icon: FiShield, title: 'DMZ Firewall', desc: 'Zone-based protection. Threat IPs auto-blocked across Public, DMZ, Internal zones.', color: 'text-green-400', bg: 'from-green-500/20 to-emerald-500/20' },
                { icon: FiLock, title: 'Auto-Quarantine', desc: 'Malicious files isolated instantly. Source IPs blocked via firewall integration.', color: 'text-yellow-400', bg: 'from-yellow-500/20 to-orange-500/20' },
                { icon: FiBell, title: 'Instant Alerts', desc: 'WebSocket notifications for every scan result, threat detection, and IP block.', color: 'text-red-400', bg: 'from-red-500/20 to-pink-500/20' },
              ].map((item, i) => (
                <div key={i} className="bg-dark-800/50 rounded-xl p-4 border border-dark-700/50 hover:border-dark-600 transition-all">
                  <div className={`p-2 rounded-lg bg-gradient-to-br ${item.bg} border border-dark-700/30 inline-block mb-3`}>
                    <item.icon className={`w-5 h-5 ${item.color}`} />
                  </div>
                  <p className="text-sm font-semibold text-dark-100 mb-1">{item.title}</p>
                  <p className="text-xs text-dark-400 leading-relaxed">{item.desc}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Live Scan Feed */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-dark-700/50 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FiRadio className="w-4 h-4 text-cyan-400 animate-pulse" />
                <h3 className="text-sm font-semibold text-dark-100">Live Scan Feed</h3>
              </div>
              <span className="text-xs text-dark-500">{liveScanResults.length} recent</span>
            </div>
            <div className="max-h-80 overflow-y-auto">
              {liveScanResults.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-dark-500">
                  <FiRadio className="w-8 h-8 mb-2 opacity-30" />
                  <p className="text-sm">Waiting for scan activity...</p>
                </div>
              ) : (
                liveScanResults.slice(0, 15).map((result, idx) => (
                  <div key={idx} className="px-6 py-3 border-b border-dark-700/30 hover:bg-dark-800/50 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3 min-w-0">
                        {result.classification === 'safe' ? <FiCheckCircle className="w-4 h-4 text-green-400 shrink-0" /> :
                         result.classification === 'suspicious' ? <FiAlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" /> :
                         <FiXOctagon className="w-4 h-4 text-red-400 shrink-0" />}
                        <span className="text-sm text-dark-100 truncate">{result.filename}</span>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        {result.source_ip && (
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-dark-800 text-dark-400">{result.source_ip}</span>
                        )}
                        {result.source_zone && result.source_zone !== 'Unknown' && (
                          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: (ZONE_COLORS[result.source_zone] || '#6b7280') + '20', color: ZONE_COLORS[result.source_zone] || '#9ca3af' }}>{result.source_zone}</span>
                        )}
                        <span className={`text-xs font-mono font-bold ${getRiskColor(result.risk_score)}`}>{result.risk_score}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getClassBadge(result.classification)}`}>{result.classification?.toUpperCase()}</span>
                        {result.firewall_blocked && <FiShield className="w-3.5 h-3.5 text-red-400" title="IP blocked by firewall" />}
                        {result.quarantined && <FiLock className="w-3.5 h-3.5 text-red-400" />}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'scan' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiUpload className="w-4 h-4 text-cyan-400" /> Scan Files
            </h3>
            <p className="text-xs text-dark-400 mb-4">Upload files for multi-engine analysis + firewall zone check</p>
            <div onClick={() => fileInputRef.current?.click()} className="border-2 border-dashed border-dark-600 hover:border-cyan-500/50 rounded-2xl p-10 text-center cursor-pointer transition-all group">
              <div className="p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 inline-block mb-4 group-hover:scale-110 transition-transform">
                <FiUpload className="w-8 h-8 text-cyan-400" />
              </div>
              <p className="text-dark-200 font-semibold">Click to select files</p>
              <p className="text-dark-500 text-xs mt-1">or drag and drop</p>
            </div>
            <input ref={fileInputRef} type="file" multiple onChange={handleScanFile} className="hidden" />
            {scanning && (
              <div className="mt-4 space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-dark-300 flex items-center gap-2">
                    <span className="animate-spin h-4 w-4 border-2 border-cyan-500 border-t-transparent rounded-full inline-block" />
                    Scanning...
                  </span>
                  <span className="text-cyan-400 font-semibold">{uploadProgress}%</span>
                </div>
                <div className="w-full bg-dark-800 rounded-full h-2.5 overflow-hidden">
                  <div className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all" style={{ width: `${uploadProgress}%` }} />
                </div>
              </div>
            )}
          </div>
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiFolder className="w-4 h-4 text-cyan-400" /> Scan Folder
            </h3>
            <p className="text-xs text-dark-400 mb-4">Select multiple files from a folder to scan</p>
            <div onClick={() => folderInputRef.current?.click()} className="border-2 border-dashed border-dark-600 hover:border-cyan-500/50 rounded-2xl p-10 text-center cursor-pointer transition-all group">
              <div className="p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 inline-block mb-4 group-hover:scale-110 transition-transform">
                <FiFolder className="w-8 h-8 text-cyan-400" />
              </div>
              <p className="text-dark-200 font-semibold">Click to select folder</p>
              <p className="text-dark-500 text-xs mt-1">Select all files from a shared folder</p>
            </div>
            <input ref={folderInputRef} type="file" multiple onChange={handleScanFolder} className="hidden" />
          </div>
        </div>
      )}

      {activeTab === 'firewall' && (
        <div className="space-y-6">
          {/* Firewall Status */}
          <div className={`rounded-2xl p-6 border ${fwStatus?.firewall_active ? 'bg-gradient-to-r from-cyan-500/10 to-blue-500/5 border-cyan-500/20' : 'bg-gradient-to-r from-red-500/10 to-orange-500/5 border-red-500/20'}`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={`p-3 rounded-2xl ${fwStatus?.firewall_active ? 'bg-cyan-500/20' : 'bg-red-500/20'}`}>
                  <FiShield className={`w-8 h-8 ${fwStatus?.firewall_active ? 'text-cyan-400' : 'text-red-400'}`} />
                </div>
                <div>
                  <h3 className={`text-lg font-bold ${fwStatus?.firewall_active ? 'text-cyan-400' : 'text-red-400'}`}>
                    DMZ Firewall {fwStatus?.firewall_active ? 'Active' : 'Inactive'}
                  </h3>
                  <p className="text-dark-400 text-xs">{fwStatus?.active_rules || 0} active rules &bull; {fwStatus?.zones?.length || 0} zones</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs font-semibold px-3 py-1.5 rounded-xl ${fwIntegrationEnabled ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-dark-700 text-dark-400 border border-dark-600'}`}>
                  <FiLink className="w-3 h-3 inline mr-1" />
                  {fwIntegrationEnabled ? 'Integrated' : 'Disconnected'}
                </span>
              </div>
            </div>
          </div>

          {/* Zone Overview */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiGlobe className="w-4 h-4 text-cyan-400" /> Network Zones
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {fwStatus?.zones?.map((zone) => (
                <div key={zone.id} className="rounded-xl p-4 border" style={{ borderColor: (zone.color || '#6b7280') + '30', backgroundColor: (zone.color || '#6b7280') + '08' }}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="w-3 h-3 rounded-full" style={{ backgroundColor: zone.color }} />
                    <span className="text-sm font-bold" style={{ color: zone.color }}>{zone.name}</span>
                    <span className={`ml-auto text-[10px] px-1.5 py-0.5 rounded ${zone.enabled ? 'bg-green-500/20 text-green-400' : 'bg-dark-700 text-dark-500'}`}>{zone.enabled ? 'ON' : 'OFF'}</span>
                  </div>
                  <p className="text-[10px] text-dark-500 mb-2">{zone.description}</p>
                  <div className="flex justify-between text-[10px]">
                    <span className="text-dark-400">Services: {zone.service_count || 0}</span>
                    <span className={`font-semibold ${zone.default_policy === 'allow' ? 'text-green-400' : 'text-red-400'}`}>{zone.default_policy?.toUpperCase()}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Block IP Input */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiXOctagon className="w-4 h-4 text-red-400" /> Manual IP Block
            </h3>
            <div className="flex gap-3">
              <input type="text" value={blockIp} onChange={(e) => setBlockIp(e.target.value)} placeholder="Enter IP to block (e.g., 192.168.1.100)"
                className="flex-1 px-4 py-3 bg-dark-800 border border-dark-700 rounded-xl text-dark-100 placeholder-dark-500 focus:outline-none focus:border-red-500/50 text-sm font-mono" />
              <button onClick={handleBlockIp} className="px-6 py-3 bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white rounded-xl text-sm font-semibold shadow-lg shadow-red-500/20 transition-all flex items-center gap-2">
                <FiXOctagon className="w-4 h-4" /> Block IP
              </button>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'threats' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiXOctagon className="w-4 h-4 text-red-400" /> Threat IPs Blocked ({threatBlockedIps.length})
            </h3>
          </div>
          <div className="space-y-2">
            {threatBlockedIps.length === 0 ? (
              <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-12 text-center">
                <FiCheckCircle className="w-12 h-12 text-green-400/30 mx-auto mb-3" />
                <p className="text-dark-500 text-sm">No threat IPs blocked yet</p>
              </div>
            ) : (
              threatBlockedIps.map((threat, i) => (
                <div key={i} className="bg-gradient-to-br from-dark-900 to-dark-950 border border-red-500/20 rounded-2xl p-4 flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="p-2 rounded-lg bg-red-500/20"><FiXOctagon className="w-4 h-4 text-red-400" /></div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-dark-100 font-mono">{threat.ip}</span>
                        <span className="text-[10px] font-semibold px-2 py-0.5 rounded" style={{ backgroundColor: (ZONE_COLORS[threat.zone] || '#6b7280') + '20', color: ZONE_COLORS[threat.zone] || '#9ca3af' }}>{threat.zone}</span>
                      </div>
                      <p className="text-[10px] text-dark-500 mt-0.5">{threat.threats} threat(s) &bull; {threat.reason}</p>
                    </div>
                  </div>
                  <button onClick={() => handleUnblockIp(threat.ip)} className="px-3 py-1.5 bg-green-500/10 text-green-400 border border-green-500/20 rounded-lg text-xs font-medium hover:bg-green-500/20 transition-colors flex items-center gap-1.5">
                    <FiUnlock className="w-3 h-3" /> Unblock
                  </button>
                </div>
              ))
            )}
          </div>

          {/* Threat Log */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-dark-700/50 flex items-center gap-2">
              <FiTerminal className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-dark-100">Threat Log ({threatLog.length})</h3>
            </div>
            <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 bg-dark-900">
                  <tr className="border-b border-dark-700">
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Time</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">IP</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Zone</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">File</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Score</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {threatLog.map((log) => (
                    <tr key={log.id} className="border-b border-dark-700/50 hover:bg-dark-800/50 transition-colors">
                      <td className="px-4 py-2 text-xs text-dark-400 font-mono">{new Date(log.timestamp).toLocaleTimeString()}</td>
                      <td className="px-4 py-2 text-xs text-dark-100 font-mono">{log.ip}</td>
                      <td className="px-4 py-2"><span className="text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: (ZONE_COLORS[log.zone] || '#6b7280') + '20', color: ZONE_COLORS[log.zone] || '#9ca3af' }}>{log.zone}</span></td>
                      <td className="px-4 py-2 text-xs text-dark-300 truncate max-w-[120px]">{log.filename || '-'}</td>
                      <td className="px-4 py-2"><span className={`text-xs font-mono font-bold ${getRiskColor(log.risk_score)}`}>{log.risk_score || '-'}</span></td>
                      <td className="px-4 py-2"><span className="text-xs font-semibold px-2 py-0.5 rounded bg-red-500/20 text-red-400">{log.action}</span></td>
                    </tr>
                  ))}
                  {threatLog.length === 0 && <tr><td colSpan="6" className="px-6 py-8 text-center text-dark-500 text-sm">No threat logs</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'notifications' && (
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-dark-700/50 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FiBell className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-dark-100">Alert Notifications ({notifications.length})</h3>
            </div>
            <button onClick={clearNotifications} className="text-xs text-dark-400 hover:text-red-400 transition-colors font-medium">Clear All</button>
          </div>
          <div className="max-h-96 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-dark-500">
                <FiBell className="w-8 h-8 mb-2 opacity-30" />
                <p className="text-sm">No alerts</p>
              </div>
            ) : (
              notifications.map((notif) => (
                <div key={notif.id} className={`px-6 py-3 border-b border-dark-700/30 hover:bg-dark-800/50 transition-colors ${!notif.read ? 'bg-dark-800/30' : ''}`}>
                  <div className="flex items-start gap-3">
                    <div className={`mt-0.5 shrink-0 ${notif.type === 'threat' ? 'text-red-400' : notif.type === 'success' ? 'text-green-400' : notif.type === 'warning' ? 'text-yellow-400' : 'text-cyan-400'}`}>
                      {notif.type === 'threat' ? <FiAlertTriangle className="w-4 h-4" /> : notif.type === 'success' ? <FiCheckCircle className="w-4 h-4" /> : notif.type === 'warning' ? <FiAlertTriangle className="w-4 h-4" /> : <FiActivity className="w-4 h-4" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-sm ${!notif.read ? 'text-dark-100 font-medium' : 'text-dark-300'}`}>{notif.message}</p>
                      <p className="text-[11px] text-dark-500 mt-0.5">{formatTime(notif.timestamp)}</p>
                    </div>
                    {!notif.read && <span className="w-2 h-2 rounded-full bg-cyan-400 shrink-0 mt-1.5" />}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {activeTab === 'history' && (
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-dark-700/50 flex items-center gap-2">
            <FiClock className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-dark-100">Scan History</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700/50">
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">File</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Classification</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Risk</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Zone</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">FW</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Time</th>
                </tr>
              </thead>
              <tbody>
                {scanHistory.length === 0 ? (
                  <tr><td colSpan="6" className="px-6 py-12 text-center text-dark-500 text-sm">No scan history</td></tr>
                ) : (
                  scanHistory.map((entry, idx) => (
                    <tr key={idx} className="border-b border-dark-700/30 hover:bg-dark-800/50 transition-colors">
                      <td className="px-6 py-3 text-dark-100 flex items-center gap-2">
                        <FiFile className="w-3.5 h-3.5 text-dark-400 shrink-0" />
                        <span className="truncate max-w-[160px]">{entry.filename}</span>
                      </td>
                      <td className="px-6 py-3">
                        <span className={`px-2.5 py-1 rounded-lg text-xs font-semibold border ${getClassBadge(entry.classification)}`}>{entry.classification?.toUpperCase()}</span>
                      </td>
                      <td className="px-6 py-3"><span className={`text-xs font-mono font-bold ${getRiskColor(entry.risk_score)}`}>{entry.risk_score}</span></td>
                      <td className="px-6 py-3">
                        {entry.source_zone && entry.source_zone !== 'Unknown' ? (
                          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: (ZONE_COLORS[entry.source_zone] || '#6b7280') + '20', color: ZONE_COLORS[entry.source_zone] || '#9ca3af' }}>{entry.source_zone}</span>
                        ) : <span className="text-dark-500 text-xs">-</span>}
                      </td>
                      <td className="px-6 py-3">
                        {entry.firewall_blocked ? <FiShield className="w-4 h-4 text-red-400" /> : <FiMinus className="w-4 h-4 text-dark-500" />}
                      </td>
                      <td className="px-6 py-3 text-dark-400 text-xs">{formatTime(entry.timestamp)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'monitor' && (
        <div className="space-y-4">
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiFolder className="w-4 h-4 text-cyan-400" /> Add Monitored Folder
            </h3>
            <div className="flex gap-3">
              <input type="text" value={folderPath} onChange={(e) => setFolderPath(e.target.value)} placeholder="Enter folder path (e.g., C:\Users\Downloads)"
                className="flex-1 px-4 py-3 bg-dark-800 border border-dark-700 rounded-xl text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm font-mono" />
              <button onClick={handleAddMonitoredPath} className="px-6 py-3 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white rounded-xl text-sm font-semibold shadow-lg shadow-cyan-500/20 transition-all flex items-center gap-2">
                <FiFolder className="w-4 h-4" /> Add
              </button>
            </div>
          </div>
          {monitoredPaths.length > 0 && (
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
              <div className="px-6 py-4 border-b border-dark-700/50 flex items-center gap-2">
                <FiActivity className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-dark-100">Monitored Folders ({monitoredPaths.length})</h3>
              </div>
              <div className="p-4 space-y-2">
                {monitoredPaths.map((path, idx) => (
                  <div key={idx} className="flex items-center justify-between bg-dark-800/50 rounded-xl px-4 py-3 border border-dark-700/50 hover:border-dark-600 transition-all">
                    <div className="flex items-center gap-3">
                      <FiFolder className="w-4 h-4 text-cyan-400" />
                      <span className="text-sm text-dark-100 font-mono">{path}</span>
                    </div>
                    <button onClick={() => handleRemoveMonitoredPath(path)} className="text-dark-500 hover:text-red-400 transition-colors p-1.5 rounded-lg hover:bg-red-500/10">
                      <FiTrash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
