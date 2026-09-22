import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  FiFile, FiCheckCircle, FiAlertTriangle, FiShield, FiXOctagon, FiActivity,
  FiRefreshCw, FiPlay, FiSquare, FiTrendingUp, FiClock, FiArrowRight,
  FiAlertCircle, FiEye, FiZap, FiServer,
} from 'react-icons/fi';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
  AreaChart, Area,
} from 'recharts';
import toast from 'react-hot-toast';
import { dashboardAPI, antivirusAPI, realtimeAPI } from '../services/api';

const COLORS = {
  safe: '#22c55e',
  suspicious: '#eab308',
  malicious: '#ef4444',
  neutral: '#64748b',
  cyan: '#06b6d4',
};

const PIE_COLORS = [COLORS.safe, COLORS.suspicious, COLORS.malicious];
const FILE_COLORS = ['#06b6d4', '#a78bfa', '#f472b6', '#fb923c', '#34d399', '#f87171'];

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-dark-950 border border-dark-700 rounded-xl px-4 py-3 shadow-2xl">
      <p className="text-dark-100 text-sm font-semibold">{payload[0].name || payload[0].payload?.name}</p>
      <p className="text-dark-300 text-xs mt-1">Count: <span className="text-dark-100 font-medium">{payload[0].value}</span></p>
    </div>
  );
};

const getRiskLevel = (score) => {
  if (score <= 20) return { label: 'Excellent', color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/20', bar: 'bg-green-500' };
  if (score <= 40) return { label: 'Good', color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', bar: 'bg-emerald-500' };
  if (score <= 60) return { label: 'Moderate', color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', bar: 'bg-yellow-500' };
  if (score <= 80) return { label: 'Elevated', color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', bar: 'bg-orange-500' };
  return { label: 'Critical', color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', bar: 'bg-red-500' };
};

export default function DashboardPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [autoScanEnabled, setAutoScanEnabled] = useState(true);

  const fetchStats = useCallback(async () => {
    setLoading(true);
    try {
      const res = await dashboardAPI.getStats();
      setStats(res.data);
    } catch {
      console.error('Failed to fetch dashboard stats');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchAutoScanStatus = useCallback(async () => {
    try {
      const res = await antivirusAPI.getStatus();
      setAutoScanEnabled(res.data.auto_scan_enabled);
    } catch {
      console.error('Failed to fetch auto-scan status');
    }
  }, []);

  const handleStopAutoScan = async () => {
    try {
      await realtimeAPI.stopAutoScan();
      setAutoScanEnabled(false);
      toast.success('Auto-scan stopped');
    } catch {
      toast.error('Failed to stop auto-scan');
    }
  };

  const handleStartAutoScan = async () => {
    try {
      await realtimeAPI.startAutoScan();
      setAutoScanEnabled(true);
      toast.success('Auto-scan started');
    } catch {
      toast.error('Failed to start auto-scan');
    }
  };

  useEffect(() => {
    fetchStats();
    fetchAutoScanStatus();
  }, [fetchStats, fetchAutoScanStatus, location.pathname]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-dark-400 font-medium">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  const total = stats?.total_scans || 0;
  const safe = stats?.safe_count || 0;
  const suspicious = stats?.suspicious_count || 0;
  const malicious = stats?.malicious_count || 0;
  const quarantined = stats?.quarantined_count || 0;
  const detectionRate = stats?.detection_percentage ?? (total > 0 ? (((suspicious + malicious) / total) * 100).toFixed(1) : 0);

  const threatCount = suspicious + malicious;
  const safeRate = total > 0 ? ((safe / total) * 100).toFixed(1) : 100;
  const riskScore = total > 0 ? Math.min(100, ((malicious * 100 + suspicious * 50) / total)).toFixed(0) : 0;
  const riskLevel = getRiskLevel(Number(riskScore));

  const riskPieData = [
    { name: 'Safe', value: safe },
    { name: 'Suspicious', value: suspicious },
    { name: 'Malicious', value: malicious },
  ].filter((d) => d.value > 0);

  const dailyData = (() => {
    const backend = stats?.daily_scans || [];
    const map = {};
    backend.forEach(d => { map[d.date] = d.count; });
    const days = [];
    for (let i = 6; i >= 0; i--) {
      const dt = new Date();
      dt.setDate(dt.getDate() - i);
      const key = dt.toISOString().slice(0, 10);
      const label = dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      days.push({ name: label, scans: map[key] || 0 });
    }
    return days;
  })();

  const fileTypeData = Object.entries(stats?.file_type_distribution || {}).map(([type, count]) => ({
    name: type,
    value: count,
  }));

  const recentScans = stats?.recent_scans || [];
  const recentThreats = recentScans.filter((s) => ['suspicious', 'malicious'].includes(s.classification));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/20">
              <FiShield className="w-6 h-6 text-cyan-400" />
            </div>
            Security Dashboard
          </h1>
          <p className="text-dark-400 text-sm mt-1 ml-13">Real-time threat detection overview</p>
        </div>
        <div className="flex items-center gap-3">
          {/* Security Score Badge */}
          <div className={`flex items-center gap-2 px-4 py-2 rounded-xl ${riskLevel.bg} border ${riskLevel.border}`}>
            <FiShield className={`w-4 h-4 ${riskLevel.color}`} />
            <span className={`text-sm font-semibold ${riskLevel.color}`}>Risk: {riskLevel.label}</span>
          </div>
          {/* Auto-Scan Toggle */}
          {autoScanEnabled ? (
            <button onClick={handleStopAutoScan}
              className="px-4 py-2.5 bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white rounded-xl text-sm font-semibold shadow-lg shadow-red-500/20 transition-all flex items-center gap-2">
              <FiSquare className="w-4 h-4" /> Stop Auto-Scan
            </button>
          ) : (
            <button onClick={handleStartAutoScan}
              className="px-4 py-2.5 bg-gradient-to-r from-green-600 to-green-500 hover:from-green-500 hover:to-green-400 text-white rounded-xl text-sm font-semibold shadow-lg shadow-green-500/20 transition-all flex items-center gap-2">
              <FiPlay className="w-4 h-4" /> Start Auto-Scan
            </button>
          )}
          <button onClick={fetchStats} disabled={loading} title="Refresh"
            className="p-2.5 rounded-xl bg-dark-800 border border-dark-700 text-dark-300 hover:text-dark-100 hover:border-dark-600 disabled:opacity-40 transition-all">
            <FiRefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Security Score Bar */}
      <div className="bg-gradient-to-r from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-xl ${riskLevel.bg} border ${riskLevel.border}`}>
              <FiZap className={`w-5 h-5 ${riskLevel.color}`} />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-dark-100">System Security Score</h3>
              <p className="text-xs text-dark-400">Based on scan results and threat detection</p>
            </div>
          </div>
          <div className="text-right">
            <span className={`text-3xl font-bold ${riskLevel.color}`}>{riskScore}</span>
            <span className="text-dark-400 text-sm">/100</span>
          </div>
        </div>
        <div className="w-full h-3 bg-dark-800 rounded-full overflow-hidden">
          <div className={`h-full rounded-full ${riskLevel.bar} transition-all duration-700`} style={{ width: `${riskScore}%` }} />
        </div>
        <div className="flex justify-between mt-2 text-xs text-dark-500">
          <span>Excellent</span>
          <span>Good</span>
          <span>Moderate</span>
          <span>Elevated</span>
          <span>Critical</span>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {[
          { icon: FiFile, count: total, label: 'Total Scanned', color: 'text-cyan-400', bg: 'from-cyan-500/20 to-blue-500/20', border: 'border-cyan-500/20', trend: null },
          { icon: FiCheckCircle, count: safe, label: 'Safe Files', color: 'text-green-400', bg: 'from-green-500/20 to-emerald-500/20', border: 'border-green-500/20', trend: safeRate + '%' },
          { icon: FiAlertTriangle, count: suspicious, label: 'Suspicious', color: 'text-yellow-400', bg: 'from-yellow-500/20 to-orange-500/20', border: 'border-yellow-500/20', trend: null },
          { icon: FiXOctagon, count: malicious, label: 'Malicious', color: 'text-red-400', bg: 'from-red-500/20 to-pink-500/20', border: 'border-red-500/20', trend: null },
          { icon: FiShield, count: quarantined, label: 'Quarantined', color: 'text-orange-400', bg: 'from-orange-500/20 to-amber-500/20', border: 'border-orange-500/20', trend: null },
        ].map(({ icon: Icon, count, label, color, bg, border, trend }, idx) => (
          <div key={idx} className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5 hover:border-dark-600 transition-all group">
            <div className="flex items-center justify-between mb-3">
              <div className={`p-3 rounded-xl bg-gradient-to-br ${bg} ${border} border`}>
                <Icon className={`w-5 h-5 ${color}`} />
              </div>
              {trend && (
                <span className="text-xs font-semibold text-green-400 bg-green-500/10 px-2 py-0.5 rounded-md">{trend}</span>
              )}
            </div>
            <div className="text-2xl font-bold text-dark-100">{count ?? '—'}</div>
            <div className="text-xs text-dark-400 font-medium mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution */}
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiAlertCircle className="w-4 h-4 text-cyan-400" />
              Risk Distribution
            </h3>
            <span className="text-xs text-dark-500">{riskPieData.length} categories</span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={riskPieData} cx="50%" cy="50%" innerRadius={55} outerRadius={90} paddingAngle={4} dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                  {riskPieData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i]} stroke="transparent" />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Daily Scans */}
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiTrendingUp className="w-4 h-4 text-cyan-400" />
              Daily Scans
            </h3>
            <span className="text-xs text-dark-500">Last 7 days</span>
          </div>
          {/* Mini stats row */}
          <div className="flex items-center gap-4 mb-4">
            {(() => {
              const weekTotal = dailyData.reduce((s, d) => s + d.scans, 0);
              const avg = dailyData.length ? (weekTotal / dailyData.length).toFixed(0) : 0;
              const peak = dailyData.length ? Math.max(...dailyData.map(d => d.scans)) : 0;
              return (
                <>
                  <div className="flex items-center gap-1.5 text-xs">
                    <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                    <span className="text-dark-400">Total:</span>
                    <span className="text-dark-100 font-semibold">{weekTotal}</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs">
                    <div className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                    <span className="text-dark-400">Avg:</span>
                    <span className="text-dark-100 font-semibold">{avg}/day</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs">
                    <div className="w-1.5 h-1.5 rounded-full bg-green-400" />
                    <span className="text-dark-400">Peak:</span>
                    <span className="text-dark-100 font-semibold">{peak}</span>
                  </div>
                </>
              );
            })()}
          </div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={dailyData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.35} />
                    <stop offset="50%" stopColor="#06b6d4" stopOpacity={0.1} />
                    <stop offset="100%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} dy={8} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} dx={-4} />
                <Tooltip content={<CustomTooltip />} cursor={{ stroke: '#06b6d4', strokeWidth: 1, strokeDasharray: '4 4', strokeOpacity: 0.4 }} />
                <Area type="monotone" dataKey="scans" stroke="#06b6d4" strokeWidth={2.5} fill="url(#scanGradient)"
                  dot={{ r: 3, fill: '#06b6d4', stroke: '#0f172a', strokeWidth: 2 }}
                  activeDot={{ r: 5, fill: '#06b6d4', stroke: '#0f172a', strokeWidth: 2, strokeOpacity: 1 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* File Type Distribution */}
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiFile className="w-4 h-4 text-cyan-400" />
              File Types
            </h3>
            <span className="text-xs text-dark-500">{fileTypeData.length} types</span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={fileTypeData} cx="50%" cy="50%" innerRadius={45} outerRadius={85} paddingAngle={4} dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                  {fileTypeData.map((_, i) => (
                    <Cell key={i} fill={FILE_COLORS[i % FILE_COLORS.length]} stroke="transparent" />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-dark-700/50 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiClock className="w-4 h-4 text-cyan-400" />
              Recent Scans
            </h3>
            <span className="text-xs text-dark-500">{recentScans.length} total</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700/50">
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">File</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Risk</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Class</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Date</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-6 py-12 text-dark-500 text-center">
                      <FiEye className="w-8 h-8 mx-auto mb-2 opacity-30" />
                      <p className="text-sm">No scans yet</p>
                    </td>
                  </tr>
                ) : (
                  recentScans.slice(0, 8).map((scan) => (
                    <tr key={scan.id} onClick={() => navigate(`/scan/${scan.id}`)}
                      className="border-b border-dark-700/30 hover:bg-dark-800/50 cursor-pointer transition-colors group">
                      <td className="px-6 py-3">
                        <span className="text-dark-100 truncate max-w-[180px] block group-hover:text-cyan-400 transition-colors">{scan.filename}</span>
                      </td>
                      <td className="px-6 py-3">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold ${
                          scan.risk_score <= 30 ? 'bg-green-500/10 text-green-400 border border-green-500/20' :
                          scan.risk_score <= 70 ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20' :
                          'bg-red-500/10 text-red-400 border border-red-500/20'
                        }`}>
                          {scan.risk_score}
                        </span>
                      </td>
                      <td className="px-6 py-3">
                        <span className="text-dark-300 capitalize">{scan.classification}</span>
                      </td>
                      <td className="px-6 py-3 text-dark-400 text-xs">
                        {scan.scan_date ? new Date(scan.scan_date).toLocaleDateString() : '—'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Threats */}
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-dark-700/50 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiAlertTriangle className="w-4 h-4 text-red-400" />
              Recent Threats
            </h3>
            <span className="text-xs text-dark-500">{recentThreats.length} threats</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700/50">
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">File</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Risk</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Reason</th>
                </tr>
              </thead>
              <tbody>
                {recentThreats.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="px-6 py-12 text-dark-500 text-center">
                      <FiShield className="w-8 h-8 mx-auto mb-2 opacity-30" />
                      <p className="text-sm">No threats detected</p>
                    </td>
                  </tr>
                ) : (
                  recentThreats.slice(0, 8).map((threat) => (
                    <tr key={threat.id} onClick={() => navigate(`/scan/${threat.id}`)}
                      className="border-b border-dark-700/30 hover:bg-dark-800/50 cursor-pointer transition-colors group">
                      <td className="px-6 py-3">
                        <span className="text-dark-100 truncate max-w-[160px] block group-hover:text-red-400 transition-colors">{threat.filename}</span>
                      </td>
                      <td className="px-6 py-3">
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/20">
                          {threat.risk_score}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-dark-400 text-xs truncate max-w-[200px]">
                        {threat.detection_reasons?.[0] || 'Threat detected'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Quick Stats Footer */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5 flex items-center gap-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-green-500/20 to-emerald-500/20 border border-green-500/20">
            <FiCheckCircle className="w-6 h-6 text-green-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-dark-100">{safeRate}%</p>
            <p className="text-xs text-dark-400 font-medium">Safe File Rate</p>
          </div>
        </div>
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5 flex items-center gap-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/20">
            <FiActivity className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-dark-100">{detectionRate}%</p>
            <p className="text-xs text-dark-400 font-medium">Detection Rate</p>
          </div>
        </div>
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5 flex items-center gap-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-orange-500/20 to-amber-500/20 border border-orange-500/20">
            <FiServer className="w-6 h-6 text-orange-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-dark-100">{autoScanEnabled ? 'Active' : 'Paused'}</p>
            <p className="text-xs text-dark-400 font-medium">Auto-Scan Status</p>
          </div>
        </div>
      </div>
    </div>
  );
}
