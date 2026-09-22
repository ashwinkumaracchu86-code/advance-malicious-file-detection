import { useState, useEffect, useCallback } from 'react';
import {
  FiShield, FiShieldOff, FiLock, FiUnlock, FiPlus, FiTrash2, FiRefreshCw,
  FiGlobe, FiServer, FiTerminal, FiActivity, FiCheckCircle, FiXOctagon,
  FiArrowRight, FiArrowLeft, FiMinus, FiEye, FiEdit2, FiPower, FiWifi,
  FiDatabase, FiMail, FiCpu, FiShuffle, FiCircle, FiX, FiToggleLeft, FiToggleRight,
} from 'react-icons/fi';
import toast from 'react-hot-toast';
import { firewallAPI } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';

const ZONE_ICONS = { globe: FiGlobe, shield: FiShield, server: FiServer, terminal: FiTerminal, database: FiDatabase, mail: FiMail, folder: FiServer, activity: FiActivity, shuffle: FiShuffle, circle: FiCircle };

const MiniBar = ({ value, max = 100, color }) => {
  const pct = Math.min(value / Math.max(max, 1), 100);
  const getColor = (v) => { if (v > 90) return 'bg-red-500'; if (v > 70) return 'bg-yellow-500'; return color || 'bg-green-500'; };
  return (
    <div className="w-full h-1.5 bg-dark-800 rounded-full overflow-hidden">
      <div className={`h-full rounded-full transition-all duration-500 ${getColor(pct)}`} style={{ width: `${pct}%` }} />
    </div>
  );
};

function TrafficFlowDiagram({ zones, traffic }) {
  const W = 800, H = 320;
  const zonePos = {
    'Public':      { x: 400, y: 40 },
    'DMZ':         { x: 200, y: 160 },
    'Internal':    { x: 400, y: 280 },
    'Management':  { x: 600, y: 160 },
  };
  const zoneColor = {};
  zones.forEach((z) => { zoneColor[z.name] = z.color || '#6b7280'; });

  const lines = [];
  Object.entries(traffic).forEach(([src, dests]) => {
    Object.entries(dests).forEach(([dst, count]) => {
      if (src === dst || count === 0) return;
      const from = zonePos[src];
      const to = zonePos[dst];
      if (!from || !to) return;
      const dx = to.x - from.x, dy = to.y - from.y;
      const len = Math.sqrt(dx * dx + dy * dy);
      const nx = dx / len, ny = dy / len;
      const sx = from.x + nx * 55, sy = from.y + ny * 25;
      const ex = to.x - nx * 55, ey = to.y - ny * 25;
      const mx = (sx + ex) / 2, my = (sy + ey) / 2;
      const w = Math.min(1 + count * 0.8, 6);
      const op = Math.min(0.3 + count * 0.1, 1);
      lines.push({ key: `${src}-${dst}`, sx, sy, ex, ey, mx, my, count, w, op, src, dst });
    });
  });

  return (
    <div className="bg-dark-950 rounded-2xl border border-dark-700 p-4">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ maxHeight: '320px' }}>
        <defs>
          <marker id="arrow" viewBox="0 0 10 6" refX="10" refY="3" markerWidth="8" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 3 L 0 6 z" fill="#06b6d4" />
          </marker>
        </defs>

        {lines.map((l) => (
          <g key={l.key}>
            <line x1={l.sx} y1={l.sy} x2={l.ex} y2={l.ey} stroke="#06b6d4" strokeWidth={l.w} opacity={l.op} markerEnd="url(#arrow)" strokeLinecap="round" />
            <rect x={l.mx - 16} y={l.my - 10} width="32" height="18" rx="4" fill="#0f172a" stroke="#334155" strokeWidth="0.5" />
            <text x={l.mx} y={l.my + 3} textAnchor="middle" fill="#22d3ee" fontSize="11" fontWeight="700">{l.count}</text>
          </g>
        ))}

        {zones.map((zone) => {
          const pos = zonePos[zone.name];
          if (!pos) return null;
          const c = zone.color || '#6b7280';
          return (
            <g key={zone.id}>
              <rect x={pos.x - 52} y={pos.y - 20} width="104" height="40" rx="12" fill={c + '20'} stroke={c + '60'} strokeWidth="1.5" />
              <circle cx={pos.x - 34} cy={pos.y} r="4" fill={c} />
              <text x={pos.x + 2} y={pos.y + 4} textAnchor="middle" fill={c} fontSize="12" fontWeight="700">{zone.name}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export default function FirewallPage() {
  const [status, setStatus] = useState(null);
  const [zones, setZones] = useState([]);
  const [rules, setRules] = useState([]);
  const [services, setServices] = useState([]);
  const [connections, setConnections] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [showAddModal, setShowAddModal] = useState(null);
  const [editingItem, setEditingItem] = useState(null);
  const [formData, setFormData] = useState({});
  const [logFilter, setLogFilter] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchAll = useCallback(async () => {
    try {
      const [statusRes, zonesRes, rulesRes, svcRes, blockedRes, logsRes] = await Promise.all([
        firewallAPI.getStatus(),
        firewallAPI.getZones(),
        firewallAPI.getRules(),
        firewallAPI.getServices(),
        firewallAPI.getBlockedIps(),
        firewallAPI.getLogs({ limit: 200 }),
      ]);
      setStatus(statusRes.data);
      setZones(zonesRes.data.zones || []);
      setRules(rulesRes.data.rules || []);
      setServices(svcRes.data.services || []);
      setBlockedIps(blockedRes.data.blocked_ips || []);
      setLogs(logsRes.data.logs || []);

      firewallAPI.getConnections().then((connRes) => {
        setConnections(connRes.data.connections || []);
      }).catch(() => {});
    } catch (err) {
      console.error('Failed to fetch firewall data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleWsMessage = useCallback((msg) => { if (msg.type === 'firewall_event') fetchAll(); }, [fetchAll]);
  const { connected } = useWebSocket(handleWsMessage);

  useEffect(() => {
    fetchAll();
    let interval;
    if (autoRefresh) interval = setInterval(fetchAll, 10000);
    return () => { if (interval) clearInterval(interval); };
  }, [fetchAll, autoRefresh]);

  const handleToggleFirewall = async () => {
    const newState = !status?.enabled;
    setStatus((prev) => ({ ...prev, enabled: newState }));
    toast.success(newState ? 'Firewall enabled' : 'Firewall disabled');
    try {
      if (newState) await firewallAPI.enable();
      else await firewallAPI.disable();
    } catch {
      setStatus((prev) => ({ ...prev, enabled: !newState }));
      toast.error('Failed to toggle firewall');
    }
  };

  const handleToggleZone = async (id) => {
    setZones((prev) => prev.map((z) => z.id === id ? { ...z, enabled: !z.enabled } : z));
    try { await firewallAPI.toggleZone(id); } catch { setZones((prev) => prev.map((z) => z.id === id ? { ...z, enabled: !z.enabled } : z)); toast.error('Failed'); }
  };

  const handleToggleRule = async (id) => {
    setRules((prev) => prev.map((r) => r.id === id ? { ...r, enabled: !r.enabled } : r));
    try { await firewallAPI.toggleRule(id); } catch { setRules((prev) => prev.map((r) => r.id === id ? { ...r, enabled: !r.enabled } : r)); toast.error('Failed'); }
  };

  const handleDelete = async (type, id) => {
    if (!confirm(`Delete this ${type}?`)) return;
    const backup = { zones: [...zones], rules: [...rules], services: [...services] };
    if (type === 'zone') setZones((prev) => prev.filter((z) => z.id !== id));
    else if (type === 'rule') setRules((prev) => prev.filter((r) => r.id !== id));
    else if (type === 'service') setServices((prev) => prev.filter((s) => s.id !== id));
    toast.success(`${type} deleted`);
    try {
      if (type === 'zone') await firewallAPI.deleteZone(id);
      else if (type === 'rule') await firewallAPI.deleteRule(id);
      else if (type === 'service') await firewallAPI.deleteService(id);
    } catch {
      setZones(backup.zones); setRules(backup.rules); setServices(backup.services);
      toast.error(`Failed to delete ${type}`);
    }
  };

  const handleSave = async () => {
    try {
      const type = showAddModal;
      let res;
      if (editingItem) {
        if (type === 'zone') res = await firewallAPI.updateZone(editingItem.id, formData);
        else if (type === 'rule') res = await firewallAPI.updateRule(editingItem.id, formData);
        else if (type === 'service') res = await firewallAPI.updateService(editingItem.id, formData);
        if (type === 'zone') setZones((prev) => prev.map((z) => z.id === editingItem.id ? res.data.zone : z));
        else if (type === 'rule') setRules((prev) => prev.map((r) => r.id === editingItem.id ? res.data.rule : r));
        else if (type === 'service') setServices((prev) => prev.map((s) => s.id === editingItem.id ? res.data.service : s));
        toast.success(`${type} updated`);
      } else {
        if (type === 'zone') res = await firewallAPI.createZone(formData);
        else if (type === 'rule') res = await firewallAPI.createRule(formData);
        else if (type === 'service') res = await firewallAPI.createService(formData);
        if (type === 'zone') setZones((prev) => [...prev, res.data.zone]);
        else if (type === 'rule') setRules((prev) => [...prev, res.data.rule]);
        else if (type === 'service') setServices((prev) => [...prev, res.data.service]);
        toast.success(`${type} created`);
      }
      setShowAddModal(null);
      setEditingItem(null);
      setFormData({});
    } catch { toast.error('Failed to save'); }
  };

  const openAdd = (type) => { setEditingItem(null); setFormData(type === 'zone' ? { name: '', type: 'custom', color: '#6b7280', cidrs: [''], default_policy: 'deny', description: '' } : type === 'rule' ? { name: '', source_zone: 'Public', dest_zone: 'Internal', protocol: 'tcp', ports: [], action: 'block', priority: 50, description: '' } : { name: '', zone: 'DMZ', ip: '', ports: [], protocol: 'tcp', icon: 'server' }); setShowAddModal(type); };
  const openEdit = (type, item) => { setEditingItem(item); setFormData({ ...item }); setShowAddModal(type); };

  const handleUnblockIp = async (ip) => {
    setBlockedIps((prev) => prev.filter((b) => b.ip !== ip));
    toast.success(`Unblocked ${ip}`);
    try { await firewallAPI.unblockIp(ip); } catch { toast.error('Failed to unblock'); fetchAll(); }
  };

  const handleClearLogs = async () => {
    setLogs([]);
    toast.success('Logs cleared');
    try { await firewallAPI.clearLogs(); } catch { toast.error('Failed to clear logs'); fetchAll(); }
  };

  const filteredLogs = logs.filter(l => !logFilter || l.action === logFilter);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-dark-400 font-medium">Loading DMZ Firewall...</p>
        </div>
      </div>
    );
  }

  const stats = status?.stats || {};
  const zoneTraffic = status?.zone_traffic || {};

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-3">
            <div className={`p-2 rounded-xl border ${status?.enabled ? 'bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border-cyan-500/20' : 'bg-gradient-to-br from-red-500/20 to-orange-500/20 border-red-500/20'}`}>
              {status?.enabled ? <FiShield className="w-6 h-6 text-cyan-400" /> : <FiShieldOff className="w-6 h-6 text-red-400" />}
            </div>
            DMZ Firewall
          </h1>
          <p className="text-dark-400 text-sm mt-1 ml-13">Network zone protection and traffic monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold ${connected ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
            {connected ? 'LIVE' : 'OFFLINE'}
          </span>
          <button onClick={() => setAutoRefresh(!autoRefresh)} className={`p-2.5 rounded-xl border transition-all ${autoRefresh ? 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400' : 'bg-dark-800 border-dark-700 text-dark-400'}`}>
            <FiRefreshCw className={`w-4 h-4 ${autoRefresh ? 'animate-spin' : ''}`} />
          </button>
          <button onClick={handleToggleFirewall} className={`px-4 py-2.5 rounded-xl font-medium text-sm flex items-center gap-2 transition-all ${status?.enabled ? 'bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20 hover:bg-green-500/20'}`}>
            <FiPower className="w-4 h-4" />
            {status?.enabled ? 'Disable' : 'Enable'}
          </button>
        </div>
      </div>

      {/* Status Banner */}
      <div className={`rounded-2xl p-6 border bg-gradient-to-r ${status?.enabled ? 'from-cyan-500/10 to-blue-500/5 border-cyan-500/20' : 'from-red-500/10 to-orange-500/5 border-red-500/20'}`}>
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <div className={`relative p-4 rounded-2xl ${status?.enabled ? 'bg-cyan-500/20' : 'bg-red-500/20'}`}>
              {status?.enabled ? <FiShield className="w-10 h-10 text-cyan-400" /> : <FiShieldOff className="w-10 h-10 text-red-400" />}
              <span className={`absolute -top-1 -right-1 w-4 h-4 ${status?.enabled ? 'bg-green-500' : 'bg-red-500'} rounded-full border-2 border-dark-900 animate-pulse`} />
            </div>
            <div>
              <h2 className={`text-xl font-bold ${status?.enabled ? 'text-cyan-400' : 'text-red-400'}`}>
                {status?.enabled ? 'DMZ Firewall Active' : 'DMZ Firewall Disabled'}
              </h2>
              <p className="text-dark-400 text-sm mt-0.5">
                {zones.filter(z => z.enabled).length} active zones &bull; {status?.active_rules || 0} inter-zone rules &bull; {stats.total_blocked || 0} blocked
              </p>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: 'Connections', value: stats.total_connections || 0, icon: FiActivity, color: 'text-cyan-400' },
              { label: 'Allowed', value: stats.total_allowed || 0, icon: FiCheckCircle, color: 'text-green-400' },
              { label: 'Blocked', value: stats.total_blocked || 0, icon: FiXOctagon, color: 'text-red-400' },
              { label: 'Blocked IPs', value: blockedIps.length, icon: FiLock, color: 'text-yellow-400' },
            ].map(({ label, value, icon: Icon, color }, i) => (
              <div key={i} className="bg-dark-900/50 rounded-xl px-4 py-3 border border-dark-700/50 text-center">
                <Icon className={`w-4 h-4 ${color} mx-auto mb-1`} />
                <p className="text-lg font-bold text-dark-100">{value.toLocaleString()}</p>
                <p className="text-[10px] text-dark-500 font-medium">{label}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 bg-dark-900 border border-dark-700 rounded-xl p-1.5">
        {[
          { id: 'overview', label: 'Overview', icon: FiEye },
          { id: 'zones', label: 'Zones', icon: FiGlobe },
          { id: 'rules', label: 'Rules', icon: FiLock },
          { id: 'services', label: 'Services', icon: FiServer },
          { id: 'connections', label: 'Connections', icon: FiWifi },
          { id: 'logs', label: 'Logs', icon: FiTerminal },
          { id: 'blocked', label: 'Blocked IPs', icon: FiXOctagon },
        ].map((tab) => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all flex-1 justify-center ${activeTab === tab.id ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm' : 'text-dark-400 hover:text-dark-100 hover:bg-dark-800 border border-transparent'}`}>
            <tab.icon className="w-3.5 h-3.5" /> {tab.label}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Traffic Flow Diagram */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiActivity className="w-4 h-4 text-cyan-400" /> Traffic Flow Between Zones
            </h3>
            <TrafficFlowDiagram zones={zones} traffic={zoneTraffic} />
          </div>

          {/* Zone Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {zones.map((zone) => {
              const Icon = ZONE_ICONS[zone.icon] || FiCircle;
              const zoneConns = connections.filter(c => c.source_zone === zone.name || c.dest_zone === zone.name);
              const zoneSvc = services.filter(s => s.zone === zone.name);
              return (
                <div key={zone.id} className="bg-gradient-to-br from-dark-900 to-dark-950 rounded-2xl p-5 border transition-all" style={{ borderColor: zone.color + '30' }}>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <div className="p-2 rounded-xl" style={{ backgroundColor: zone.color + '20' }}>
                        <Icon className="w-5 h-5" style={{ color: zone.color }} />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold" style={{ color: zone.color }}>{zone.name}</h4>
                        <p className="text-[10px] text-dark-500">{zone.type}</p>
                      </div>
                    </div>
                    <button onClick={() => handleToggleZone(zone.id)} className={`p-1 rounded ${zone.enabled ? 'text-green-400' : 'text-dark-500'}`}>
                      {zone.enabled ? <FiToggleRight className="w-5 h-5" /> : <FiToggleLeft className="w-5 h-5" />}
                    </button>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-xs">
                      <span className="text-dark-400">Connections</span>
                      <span className="text-dark-100 font-medium">{zoneConns.length}</span>
                    </div>
                    <MiniBar value={zoneConns.length} max={Math.max(connections.length, 1)} color={`bg-[${zone.color}]`} />
                    <div className="flex justify-between text-xs">
                      <span className="text-dark-400">Services</span>
                      <span className="text-dark-100 font-medium">{zoneSvc.length}</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-dark-400">Policy</span>
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded ${zone.default_policy === 'allow' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                        {zone.default_policy.toUpperCase()}
                      </span>
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1">
                    {zone.cidrs?.slice(0, 2).map((cidr, i) => (
                      <span key={i} className="text-[10px] bg-dark-800 px-2 py-0.5 rounded text-dark-400 font-mono">{cidr}</span>
                    ))}
                    {zone.cidrs?.length > 2 && <span className="text-[10px] text-dark-500">+{zone.cidrs.length - 2}</span>}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Block Rate */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiActivity className="w-4 h-4 text-cyan-400" /> Inter-Zone Traffic Analysis
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { label: 'Public → Internal', value: stats.public_to_internal_blocked || 0, color: 'text-red-400', bg: 'from-red-500/20 to-orange-500/20' },
                { label: 'Public → DMZ', value: stats.public_to_dmz_blocked || 0, color: 'text-yellow-400', bg: 'from-yellow-500/20 to-orange-500/20' },
                { label: 'DMZ → Internal', value: stats.dmz_to_internal_blocked || 0, color: 'text-purple-400', bg: 'from-purple-500/20 to-pink-500/20' },
              ].map(({ label, value, color, bg }, i) => (
                <div key={i} className={`bg-gradient-to-br ${bg} rounded-xl p-4 border border-dark-700/50`}>
                  <p className="text-xs text-dark-400 mb-1">{label}</p>
                  <p className={`text-2xl font-bold ${color}`}>{value.toLocaleString()}</p>
                  <p className="text-[10px] text-dark-500 mt-1">blocked connections</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Zones Tab */}
      {activeTab === 'zones' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiGlobe className="w-4 h-4 text-cyan-400" /> Network Zones ({zones.length})
            </h3>
            <button onClick={() => openAdd('zone')} className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
              <FiPlus className="w-4 h-4" /> Add Zone
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {zones.map((zone) => {
              const Icon = ZONE_ICONS[zone.icon] || FiCircle;
              return (
                <div key={zone.id} className="bg-gradient-to-br from-dark-900 to-dark-950 rounded-2xl p-5 border" style={{ borderColor: zone.color + '30' }}>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 rounded-xl" style={{ backgroundColor: zone.color + '20' }}>
                        <Icon className="w-5 h-5" style={{ color: zone.color }} />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold" style={{ color: zone.color }}>{zone.name}</h4>
                        <p className="text-[10px] text-dark-500">{zone.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      <button onClick={() => handleToggleZone(zone.id)} className={`p-1.5 rounded-lg ${zone.enabled ? 'text-green-400 hover:bg-green-500/10' : 'text-dark-500 hover:bg-dark-800'}`}>
                        {zone.enabled ? <FiToggleRight className="w-5 h-5" /> : <FiToggleLeft className="w-5 h-5" />}
                      </button>
                      <button onClick={() => openEdit('zone', zone)} className="p-1.5 rounded-lg text-dark-400 hover:text-cyan-400 hover:bg-cyan-500/10"><FiEdit2 className="w-4 h-4" /></button>
                      <button onClick={() => handleDelete('zone', zone.id)} className="p-1.5 rounded-lg text-dark-400 hover:text-red-400 hover:bg-red-500/10"><FiTrash2 className="w-4 h-4" /></button>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-dark-400">Policy:</span>
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded ${zone.default_policy === 'allow' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                        {zone.default_policy.toUpperCase()}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {zone.cidrs?.map((cidr, i) => (
                        <span key={i} className="text-[10px] bg-dark-800 px-2 py-0.5 rounded text-dark-400 font-mono">{cidr}</span>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Rules Tab */}
      {activeTab === 'rules' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiLock className="w-4 h-4 text-cyan-400" /> Inter-Zone Rules ({rules.length})
            </h3>
            <button onClick={() => openAdd('rule')} className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
              <FiPlus className="w-4 h-4" /> Add Rule
            </button>
          </div>
          <div className="space-y-2">
            {rules.sort((a, b) => (a.priority || 50) - (b.priority || 50)).map((rule) => (
              <div key={rule.id} className={`bg-gradient-to-br from-dark-900 to-dark-950 border rounded-2xl p-4 ${rule.enabled ? 'border-dark-700' : 'border-dark-700/50 opacity-60'}`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <button onClick={() => handleToggleRule(rule.id)} className={`p-1 rounded-lg ${rule.enabled ? 'text-green-400' : 'text-dark-500'}`}>
                      {rule.enabled ? <FiToggleRight className="w-6 h-6" /> : <FiToggleLeft className="w-6 h-6" />}
                    </button>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded ${rule.action === 'block' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                          {rule.action.toUpperCase()}
                        </span>
                        <span className="text-sm font-semibold text-dark-100">{rule.name}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-1 text-[10px] text-dark-500">
                        <span className="px-1.5 py-0.5 rounded bg-dark-800 text-cyan-400">{rule.source_zone}</span>
                        <FiArrowRight className="w-3 h-3" />
                        <span className="px-1.5 py-0.5 rounded bg-dark-800 text-green-400">{rule.dest_zone}</span>
                        <span className="ml-1">{rule.protocol.toUpperCase()} {rule.ports?.length > 0 ? `:${rule.ports.join(',')}` : '*'}</span>
                      </div>
                      {rule.description && <p className="text-[10px] text-dark-400 mt-1">{rule.description}</p>}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <button onClick={() => openEdit('rule', rule)} className="p-1.5 rounded-lg text-dark-400 hover:text-cyan-400 hover:bg-cyan-500/10"><FiEdit2 className="w-4 h-4" /></button>
                    <button onClick={() => handleDelete('rule', rule.id)} className="p-1.5 rounded-lg text-dark-400 hover:text-red-400 hover:bg-red-500/10"><FiTrash2 className="w-4 h-4" /></button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Services Tab */}
      {activeTab === 'services' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiServer className="w-4 h-4 text-cyan-400" /> Services ({services.length})
            </h3>
            <button onClick={() => openAdd('service')} className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
              <FiPlus className="w-4 h-4" /> Add Service
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {services.map((svc) => {
              const zone = zones.find(z => z.name === svc.zone);
              const Icon = ZONE_ICONS[svc.icon] || FiServer;
              return (
                <div key={svc.id} className="bg-gradient-to-br from-dark-900 to-dark-950 rounded-2xl p-4 border border-dark-700">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Icon className="w-4 h-4" style={{ color: zone?.color || '#6b7280' }} />
                      <span className="text-sm font-semibold text-dark-100">{svc.name}</span>
                    </div>
                    <span className={`w-2.5 h-2.5 rounded-full ${svc.status === 'running' ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-xs">
                      <span className="text-dark-400">IP</span>
                      <span className="text-dark-100 font-mono">{svc.ip}</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-dark-400">Zone</span>
                      <span className="text-xs font-semibold px-2 py-0.5 rounded" style={{ backgroundColor: zone?.color + '20', color: zone?.color }}>{svc.zone}</span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-dark-400">Ports</span>
                      <span className="text-dark-100 font-mono text-[10px]">{svc.ports?.join(', ')}</span>
                    </div>
                  </div>
                  <div className="flex justify-end gap-1 mt-3">
                    <button onClick={() => openEdit('service', svc)} className="p-1.5 rounded-lg text-dark-400 hover:text-cyan-400 hover:bg-cyan-500/10"><FiEdit2 className="w-3.5 h-3.5" /></button>
                    <button onClick={() => handleDelete('service', svc.id)} className="p-1.5 rounded-lg text-dark-400 hover:text-red-400 hover:bg-red-500/10"><FiTrash2 className="w-3.5 h-3.5" /></button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Connections Tab */}
      {activeTab === 'connections' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiWifi className="w-4 h-4 text-cyan-400" /> Active Connections ({connections.length})
            </h3>
            <button onClick={fetchAll} className="p-2 rounded-xl bg-dark-800 border border-dark-700 text-dark-300 hover:text-dark-100 transition-all">
              <FiRefreshCw className="w-4 h-4" />
            </button>
          </div>
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-dark-700">
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Source Zone</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Remote</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Dest Zone</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Local</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Proto</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Process</th>
                  </tr>
                </thead>
                <tbody>
                  {connections.slice(0, 100).map((conn, i) => {
                    const srcZone = zones.find(z => z.name === conn.source_zone);
                    const dstZone = zones.find(z => z.name === conn.dest_zone);
                    return (
                      <tr key={i} className="border-b border-dark-700/50 hover:bg-dark-800/50 transition-colors">
                        <td className="px-4 py-2"><span className="text-xs font-semibold px-2 py-0.5 rounded" style={{ backgroundColor: (srcZone?.color || '#6b7280') + '20', color: srcZone?.color || '#9ca3af' }}>{conn.source_zone || '?'}</span></td>
                        <td className="px-4 py-2 text-xs text-dark-100 font-mono">{conn.remote_ip}:{conn.remote_port}</td>
                        <td className="px-4 py-2"><span className="text-xs font-semibold px-2 py-0.5 rounded" style={{ backgroundColor: (dstZone?.color || '#6b7280') + '20', color: dstZone?.color || '#9ca3af' }}>{conn.dest_zone || '?'}</span></td>
                        <td className="px-4 py-2 text-xs text-dark-100 font-mono">{conn.local_ip}:{conn.local_port}</td>
                        <td className="px-4 py-2"><span className="text-xs font-semibold px-2 py-0.5 rounded bg-dark-800 text-dark-300">{conn.protocol}</span></td>
                        <td className="px-4 py-2 text-xs text-dark-300">{conn.process_name || `PID:${conn.pid || '?'}`}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {connections.length === 0 && <p className="text-dark-500 text-sm text-center py-8">No active connections</p>}
          </div>
        </div>
      )}

      {/* Logs Tab */}
      {activeTab === 'logs' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiTerminal className="w-4 h-4 text-cyan-400" /> Logs ({filteredLogs.length})
            </h3>
            <div className="flex items-center gap-2">
              <select value={logFilter} onChange={(e) => setLogFilter(e.target.value)} className="bg-dark-800 border border-dark-700 rounded-lg px-3 py-1.5 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50">
                <option value="">All</option>
                <option value="blocked">Blocked</option>
                <option value="allowed">Allowed</option>
              </select>
              <button onClick={handleClearLogs} className="px-3 py-1.5 bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg text-xs font-medium hover:bg-red-500/20 transition-colors">Clear</button>
            </div>
          </div>
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
            <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 bg-dark-900">
                  <tr className="border-b border-dark-700">
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Time</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Action</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Source</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Route</th>
                    <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-dark-500">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((log) => {
                    const srcZone = zones.find(z => z.name === log.source_zone);
                    const dstZone = zones.find(z => z.name === log.dest_zone);
                    return (
                      <tr key={log.id} className="border-b border-dark-700/50 hover:bg-dark-800/50 transition-colors">
                        <td className="px-4 py-2 text-xs text-dark-400 font-mono">{new Date(log.timestamp).toLocaleTimeString()}</td>
                        <td className="px-4 py-2">
                          <span className={`text-xs font-semibold px-2 py-0.5 rounded ${log.action === 'blocked' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>{log.action}</span>
                        </td>
                        <td className="px-4 py-2 text-xs text-dark-100 font-mono">{log.remote_ip}:{log.remote_port}</td>
                        <td className="px-4 py-2">
                          <div className="flex items-center gap-1">
                            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: (srcZone?.color || '#6b7280') + '20', color: srcZone?.color || '#9ca3af' }}>{log.source_zone || '?'}</span>
                            <FiArrowRight className="w-3 h-3 text-dark-500" />
                            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: (dstZone?.color || '#6b7280') + '20', color: dstZone?.color || '#9ca3af' }}>{log.dest_zone || '?'}</span>
                          </div>
                        </td>
                        <td className="px-4 py-2 text-xs text-dark-400">{log.reason}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {filteredLogs.length === 0 && <p className="text-dark-500 text-sm text-center py-8">No logs found</p>}
          </div>
        </div>
      )}

      {/* Blocked IPs Tab */}
      {activeTab === 'blocked' && (
        <div className="space-y-6">
          <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
            <FiXOctagon className="w-4 h-4 text-red-400" /> Blocked IPs ({blockedIps.length})
          </h3>
          <div className="space-y-2">
            {blockedIps.map((item, i) => (
              <div key={i} className="bg-gradient-to-br from-dark-900 to-dark-950 border border-red-500/20 rounded-2xl p-4 flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="p-2 rounded-lg bg-red-500/20"><FiXOctagon className="w-4 h-4 text-red-400" /></div>
                  <div>
                    <p className="text-sm font-semibold text-dark-100 font-mono">{item.ip}</p>
                    <p className="text-[10px] text-dark-500">{item.attempts} blocked attempts</p>
                  </div>
                </div>
                <button onClick={() => handleUnblockIp(item.ip)} className="px-3 py-1.5 bg-green-500/10 text-green-400 border border-green-500/20 rounded-lg text-xs font-medium hover:bg-green-500/20 transition-colors flex items-center gap-1.5">
                  <FiUnlock className="w-3 h-3" /> Unblock
                </button>
              </div>
            ))}
            {blockedIps.length === 0 && <p className="text-dark-500 text-sm text-center py-8">No blocked IPs</p>}
          </div>
        </div>
      )}

      {/* Add/Edit Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-dark-900 border border-dark-700 rounded-2xl w-full max-w-lg shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b border-dark-700 flex items-center justify-between sticky top-0 bg-dark-900 z-10">
              <h3 className="text-lg font-semibold text-dark-100">{editingItem ? `Edit ${showAddModal}` : `Add ${showAddModal}`}</h3>
              <button onClick={() => { setShowAddModal(null); setEditingItem(null); }} className="p-1.5 rounded-lg text-dark-400 hover:text-dark-100 hover:bg-dark-800 transition-colors"><FiX className="w-5 h-5" /></button>
            </div>
            <div className="px-6 py-4 space-y-4">
              <div>
                <label className="block text-xs font-medium text-dark-400 mb-1">Name</label>
                <input type="text" value={formData.name || ''} onChange={(e) => setFormData({ ...formData, name: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50" />
              </div>
              {showAddModal === 'zone' && (
                <>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-dark-400 mb-1">Type</label>
                      <select value={formData.type || 'custom'} onChange={(e) => setFormData({ ...formData, type: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50">
                        <option value="public">Public</option><option value="dmz">DMZ</option><option value="internal">Internal</option><option value="management">Management</option><option value="custom">Custom</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-dark-400 mb-1">Default Policy</label>
                      <select value={formData.default_policy || 'deny'} onChange={(e) => setFormData({ ...formData, default_policy: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50">
                        <option value="allow">Allow</option><option value="deny">Deny</option>
                      </select>
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-dark-400 mb-1">Color</label>
                    <input type="color" value={formData.color || '#6b7280'} onChange={(e) => setFormData({ ...formData, color: e.target.value })} className="w-full h-10 bg-dark-800 border border-dark-700 rounded-lg cursor-pointer" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-dark-400 mb-1">CIDRs (comma-separated)</label>
                    <input type="text" value={(formData.cidrs || []).join(', ')} onChange={(e) => setFormData({ ...formData, cidrs: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 font-mono focus:outline-none focus:border-cyan-500/50" placeholder="192.168.0.0/16, 10.0.0.0/8" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-dark-400 mb-1">Description</label>
                    <input type="text" value={formData.description || ''} onChange={(e) => setFormData({ ...formData, description: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50" />
                  </div>
                </>
              )}
              {showAddModal === 'rule' && (
                <>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-dark-400 mb-1">Source Zone</label>
                      <select value={formData.source_zone || 'Public'} onChange={(e) => setFormData({ ...formData, source_zone: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50">
                        {zones.map(z => <option key={z.id} value={z.name}>{z.name}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-dark-400 mb-1">Destination Zone</label>
                      <select value={formData.dest_zone || 'Internal'} onChange={(e) => setFormData({ ...formData, dest_zone: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50">
                        {zones.map(z => <option key={z.id} value={z.name}>{z.name}</option>)}
                      </select>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-dark-400 mb-1">Action</label>
                      <select value={formData.action || 'block'} onChange={(e) => setFormData({ ...formData, action: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50">
                        <option value="block">Block</option><option value="allow">Allow</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-dark-400 mb-1">Protocol</label>
                      <select value={formData.protocol || 'tcp'} onChange={(e) => setFormData({ ...formData, protocol: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50">
                        <option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="*">Any</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-dark-400 mb-1">Priority</label>
                      <input type="number" value={formData.priority || 50} onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 50 })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50" min="0" max="100" />
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-dark-400 mb-1">Ports (comma-separated, empty = any)</label>
                    <input type="text" value={(formData.ports || []).join(', ')} onChange={(e) => setFormData({ ...formData, ports: e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)) })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 font-mono focus:outline-none focus:border-cyan-500/50" placeholder="80, 443, 8080" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-dark-400 mb-1">Description</label>
                    <input type="text" value={formData.description || ''} onChange={(e) => setFormData({ ...formData, description: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50" />
                  </div>
                </>
              )}
              {showAddModal === 'service' && (
                <>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-dark-400 mb-1">Zone</label>
                      <select value={formData.zone || 'DMZ'} onChange={(e) => setFormData({ ...formData, zone: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50">
                        {zones.map(z => <option key={z.id} value={z.name}>{z.name}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-dark-400 mb-1">IP Address</label>
                      <input type="text" value={formData.ip || ''} onChange={(e) => setFormData({ ...formData, ip: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 font-mono focus:outline-none focus:border-cyan-500/50" placeholder="172.16.0.10" />
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-dark-400 mb-1">Ports (comma-separated)</label>
                    <input type="text" value={(formData.ports || []).join(', ')} onChange={(e) => setFormData({ ...formData, ports: e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)) })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 font-mono focus:outline-none focus:border-cyan-500/50" placeholder="80, 443" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-dark-400 mb-1">Protocol</label>
                    <select value={formData.protocol || 'tcp'} onChange={(e) => setFormData({ ...formData, protocol: e.target.value })} className="w-full bg-dark-800 border border-dark-700 rounded-lg px-3 py-2 text-sm text-dark-100 focus:outline-none focus:border-cyan-500/50">
                      <option value="tcp">TCP</option><option value="udp">UDP</option>
                    </select>
                  </div>
                </>
              )}
            </div>
            <div className="px-6 py-4 border-t border-dark-700 flex justify-end gap-3 sticky bottom-0 bg-dark-900">
              <button onClick={() => { setShowAddModal(null); setEditingItem(null); }} className="px-4 py-2 bg-dark-800 text-dark-300 rounded-lg text-sm font-medium hover:bg-dark-700 transition-colors">Cancel</button>
              <button onClick={handleSave} className="px-4 py-2 bg-cyan-600 text-white rounded-lg text-sm font-medium hover:bg-cyan-500 transition-colors">{editingItem ? 'Update' : 'Create'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
