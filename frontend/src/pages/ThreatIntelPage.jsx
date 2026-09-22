import { useState, useEffect, useCallback } from 'react';
import {
  FiShield, FiAlertTriangle, FiActivity, FiTrendingUp, FiFile,
  FiClock, FiBarChart2, FiRefreshCw, FiTarget, FiZap, FiEye,
} from 'react-icons/fi';
import {
  PieChart, Pie, Cell, BarChart, Bar, LineChart, Line,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, AreaChart, Area,
} from 'recharts';
import toast from 'react-hot-toast';
import { threatIntelAPI } from '../services/api';

const COLORS = {
  safe: '#10b981',
  suspicious: '#f59e0b',
  malicious: '#f43f5e',
  unknown: '#64748b',
  cyan: '#06b6d4',
  purple: '#a78bfa',
  pink: '#f472b6',
  orange: '#fb923c',
  blue: '#3b82f6',
};

const PIE_COLORS = [COLORS.safe, COLORS.suspicious, COLORS.malicious, COLORS.unknown];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-dark-950 border border-dark-700 rounded-xl px-4 py-3 shadow-2xl">
      <p className="text-dark-100 text-sm font-semibold mb-1">{label || payload[0]?.name}</p>
      {payload.map((p, i) => (
        <p key={i} className="text-dark-300 text-xs">
          <span className="inline-block w-2 h-2 rounded-full mr-1.5" style={{ backgroundColor: p.color || p.stroke }} />
          {p.name || p.dataKey}: <span className="text-dark-100 font-medium">{p.value}</span>
        </p>
      ))}
    </div>
  );
};

export default function ThreatIntelPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [period, setPeriod] = useState(30);
  const [stats, setStats] = useState(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [dashboardRes, statsRes] = await Promise.all([
        threatIntelAPI.getDashboard(period),
        threatIntelAPI.getStats(),
      ]);
      setData(dashboardRes.data);
      setStats(statsRes.data);
    } catch {
      toast.error('Failed to load threat intelligence data');
    } finally {
      setLoading(false);
    }
  }, [period]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const riskPieData = data ? Object.entries(data.risk_distribution || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
  })).filter(d => d.value > 0) : [];

  const fileTypeData = (data?.file_type_risks || []).map(d => ({
    name: d.extension || 'Unknown',
    scans: d.scan_count,
    avgRisk: d.avg_risk,
    maxRisk: d.max_risk,
  }));

  const trendData = (() => {
    const backend = data?.threat_trend || [];
    const map = {};
    backend.forEach(d => { map[d.date] = d.count || 0; });
    const days = [];
    for (let i = period - 1; i >= 0; i--) {
      const dt = new Date();
      dt.setDate(dt.getDate() - i);
      const key = dt.toISOString().slice(0, 10);
      const label = dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      days.push({ date: label, threats: map[key] || 0 });
    }
    return days;
  })();


  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-dark-400 font-medium">Loading threat intelligence...</p>
        </div>
      </div>
    );
  }

  const totalScans = data?.summary?.total_scans || 0;
  const safeCount = data?.summary?.safe_count || 0;
  const maliciousCount = data?.summary?.malicious_count || 0;
  const suspiciousCount = data?.summary?.suspicious_count || 0;
  const threatRate = data?.summary?.threat_rate || 0;
  const totalThreats = trendData.reduce((s, d) => s + d.threats, 0);
  const peakThreats = trendData.length ? Math.max(...trendData.map(d => d.threats)) : 0;
  const avgDaily = trendData.length ? (totalThreats / trendData.length).toFixed(1) : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-red-500/20 to-orange-500/20 border border-red-500/20">
              <FiTarget className="w-6 h-6 text-red-400" />
            </div>
            Threat Intelligence
          </h1>
          <p className="text-dark-400 text-sm mt-1 ml-13">Analyze threat trends and detection patterns</p>
        </div>
        <div className="flex items-center gap-3">
          <select value={period} onChange={(e) => setPeriod(Number(e.target.value))}
            className="bg-dark-900 border border-dark-700 text-dark-100 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all">
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
            <option value={365}>Last year</option>
          </select>
          <button onClick={fetchData} disabled={loading}
            className="p-2.5 rounded-xl bg-dark-800 border border-dark-700 text-dark-300 hover:text-dark-100 hover:border-dark-600 disabled:opacity-40 transition-all">
            <FiRefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { icon: FiFile, value: totalScans, label: 'Total Scans', color: 'text-cyan-400', bg: 'from-cyan-500/20 to-blue-500/20', border: 'border-cyan-500/20' },
          { icon: FiShield, value: safeCount, label: 'Safe Files', color: 'text-green-400', bg: 'from-green-500/20 to-emerald-500/20', border: 'border-green-500/20' },
          { icon: FiAlertTriangle, value: maliciousCount, label: 'Malicious', color: 'text-red-400', bg: 'from-red-500/20 to-pink-500/20', border: 'border-red-500/20' },
          { icon: FiActivity, value: `${threatRate}%`, label: 'Threat Rate', color: 'text-yellow-400', bg: 'from-yellow-500/20 to-orange-500/20', border: 'border-yellow-500/20' },
        ].map(({ icon: Icon, value, label, color, bg, border }, idx) => (
          <div key={idx} className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5 hover:border-dark-600 transition-all">
            <div className="flex items-center gap-4">
              <div className={`p-3 rounded-xl bg-gradient-to-br ${bg} ${border} border`}>
                <Icon className={`w-5 h-5 ${color}`} />
              </div>
              <div>
                <p className="text-2xl font-bold text-dark-100">{value ?? '—'}</p>
                <p className="text-xs text-dark-400 font-medium">{label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Trend Summary Bar */}
      <div className="bg-gradient-to-r from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-red-500/20 to-orange-500/20 border border-red-500/20">
              <FiZap className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-dark-100">Threat Activity Summary</h3>
              <p className="text-xs text-dark-400">Last {period} days overview</p>
            </div>
          </div>
          <div className="flex items-center gap-6">
            <div className="text-center">
              <p className="text-xl font-bold text-red-400">{totalThreats}</p>
              <p className="text-xs text-dark-400">Total Threats</p>
            </div>
            <div className="w-px h-8 bg-dark-700" />
            <div className="text-center">
              <p className="text-xl font-bold text-orange-400">{peakThreats}</p>
              <p className="text-xs text-dark-400">Peak Day</p>
            </div>
            <div className="w-px h-8 bg-dark-700" />
            <div className="text-center">
              <p className="text-xl font-bold text-cyan-400">{avgDaily}</p>
              <p className="text-xs text-dark-400">Avg/Day</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Trend */}
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiTrendingUp className="w-4 h-4 text-red-400" />
              Threat Trend
            </h3>
            <span className="text-xs text-dark-500">{period} days</span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="threatTrendGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={COLORS.malicious} stopOpacity={0.35} />
                    <stop offset="50%" stopColor={COLORS.malicious} stopOpacity={0.1} />
                    <stop offset="100%" stopColor={COLORS.malicious} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} dy={8} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} dx={-4} allowDecimals={false} />
                <Tooltip content={<CustomTooltip />} cursor={{ stroke: COLORS.malicious, strokeWidth: 1, strokeDasharray: '4 4', strokeOpacity: 0.4 }} />
                <Area type="monotone" dataKey="threats" stroke={COLORS.malicious} strokeWidth={2.5} fill="url(#threatTrendGradient)"
                  dot={{ r: 3, fill: COLORS.malicious, stroke: '#0f172a', strokeWidth: 2 }}
                  activeDot={{ r: 5, fill: COLORS.malicious, stroke: '#0f172a', strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Distribution */}
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiShield className="w-4 h-4 text-cyan-400" />
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
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} stroke="transparent" />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>


      {/* File Type Risk Analysis */}
      <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
            <FiFile className="w-4 h-4 text-purple-400" />
              File Type Risk Analysis
            </h3>
            <span className="text-xs text-dark-500">{fileTypeData.length} types</span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={fileTypeData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} dy={8} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} dx={-4} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                <Bar dataKey="scans" fill={COLORS.cyan} radius={[4, 4, 0, 0]} barSize={20} />
                <Bar dataKey="maxRisk" fill={COLORS.malicious} radius={[4, 4, 0, 0]} barSize={20} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '12px' }} />
              </BarChart>
            </ResponsiveContainer>
          </div>
      </div>

      {/* High Risk Detections Table */}
      {data?.high_risk_detections && data.high_risk_detections.length > 0 && (
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-dark-700/50 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-dark-100 flex items-center gap-2">
              <FiAlertTriangle className="w-4 h-4 text-red-400" />
              Recent High-Risk Detections
            </h3>
            <span className="text-xs text-dark-500">{data.high_risk_detections.length} detections</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700/50">
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">File</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Risk Score</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Classification</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Detection Reasons</th>
                  <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Date</th>
                </tr>
              </thead>
              <tbody>
                {data.high_risk_detections.map((detection, i) => (
                  <tr key={i} className="border-b border-dark-700/30 hover:bg-dark-800/50 transition-colors">
                    <td className="px-6 py-3">
                      <span className="text-dark-100 truncate max-w-[200px] block">{detection.filename}</span>
                    </td>
                    <td className="px-6 py-3">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold ${
                        detection.risk_score <= 30 ? 'bg-green-500/10 text-green-400 border border-green-500/20' :
                        detection.risk_score <= 70 ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20' :
                        'bg-red-500/10 text-red-400 border border-red-500/20'
                      }`}>
                        {detection.risk_score}
                      </span>
                    </td>
                    <td className="px-6 py-3">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold ${
                        detection.classification === 'malicious' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                        detection.classification === 'suspicious' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20' :
                        'bg-green-500/10 text-green-400 border border-green-500/20'
                      }`}>
                        {detection.classification}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-dark-400 text-xs max-w-[250px] truncate">
                      {detection.detection_reasons?.join(', ') || '—'}
                    </td>
                    <td className="px-6 py-3 text-dark-400 text-xs">
                      {detection.scan_date?.slice(0, 10) || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Overall Statistics */}
      {stats && (
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
          <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
            <FiBarChart2 className="w-4 h-4 text-cyan-400" />
            Overall Statistics
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Total Scans', value: stats.total_scans, color: 'text-cyan-400', bg: 'from-cyan-500/20 to-blue-500/20', border: 'border-cyan-500/20' },
              { label: 'Average Risk', value: stats.average_risk_score, color: 'text-yellow-400', bg: 'from-yellow-500/20 to-orange-500/20', border: 'border-yellow-500/20' },
              { label: "Today's Scans", value: stats.today_scans, color: 'text-green-400', bg: 'from-green-500/20 to-emerald-500/20', border: 'border-green-500/20' },
              { label: "Today's Threats", value: stats.today_threats, color: 'text-red-400', bg: 'from-red-500/20 to-pink-500/20', border: 'border-red-500/20' },
            ].map(({ label, value, color, bg, border }, idx) => (
              <div key={idx} className={`bg-gradient-to-br ${bg} ${border} border rounded-xl p-4 text-center`}>
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
                <p className="text-xs text-dark-400 font-medium mt-1">{label}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
