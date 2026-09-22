import { useState, useEffect, useCallback, useRef } from 'react';
import toast from 'react-hot-toast';
import {
  FiActivity, FiSearch, FiRefreshCw, FiChevronLeft, FiChevronRight,
  FiClock, FiCheckCircle, FiXCircle, FiUpload, FiShield,
  FiTrash2, FiFileText, FiLogIn, FiLogOut, FiFilter, FiDatabase,
  FiAlertTriangle, FiTrendingUp, FiBarChart2,
} from 'react-icons/fi';
import { logsAPI } from '../services/api';

const ACTION_TYPES = [
  { value: '', label: 'All Actions' },
  { value: 'login', label: 'Login', icon: FiLogIn },
  { value: 'logout', label: 'Logout', icon: FiLogOut },
  { value: 'upload', label: 'Upload', icon: FiUpload },
  { value: 'scan', label: 'Scan', icon: FiSearch },
  { value: 'quarantine', label: 'Quarantine', icon: FiShield },
  { value: 'delete', label: 'Delete', icon: FiTrash2 },
  { value: 'report', label: 'Report', icon: FiFileText },
];

const RESULT_STYLES = {
  success: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20', dot: 'bg-emerald-400' },
  failure: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20', dot: 'bg-red-400' },
  warning: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20', dot: 'bg-amber-400' },
};

const ACTION_STYLES = {
  login: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20', icon: FiLogIn },
  logout: { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/20', icon: FiLogOut },
  upload: { bg: 'bg-violet-500/10', text: 'text-violet-400', border: 'border-violet-500/20', icon: FiUpload },
  scan: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/20', icon: FiSearch },
  quarantine: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20', icon: FiShield },
  delete: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20', icon: FiTrash2 },
  report: { bg: 'bg-indigo-500/10', text: 'text-indigo-400', border: 'border-indigo-500/20', icon: FiFileText },
  auto_scan: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/20', icon: FiShield },
};

function formatDate(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function formatRelative(dateStr) {
  if (!dateStr) return '';
  const diff = Date.now() - new Date(dateStr).getTime();
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

function StatCard({ icon: Icon, label, value, color }) {
  return (
    <div className="bg-dark-900 border border-dark-700 rounded-xl p-5 hover:border-dark-600 transition-colors">
      <div className="flex items-center gap-4">
        <div className={`p-3 rounded-xl ${color}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div>
          <p className="text-2xl font-bold text-dark-100">{value}</p>
          <p className="text-xs text-dark-400 mt-0.5">{label}</p>
        </div>
      </div>
    </div>
  );
}

function ResultBadge({ result }) {
  const normalized = result?.toLowerCase() || '';
  let s = { bg: 'bg-dark-700', text: 'text-dark-300', border: 'border-dark-600', dot: 'bg-dark-400' };
  if (['success', 'passed', 'clean'].includes(normalized)) s = RESULT_STYLES.success;
  else if (['failure', 'failed', 'malicious'].includes(normalized)) s = RESULT_STYLES.failure;
  else if (['warning', 'suspicious'].includes(normalized)) s = RESULT_STYLES.warning;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium ${s.bg} ${s.text} border ${s.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {result || '—'}
    </span>
  );
}

function ActionBadge({ action }) {
  const key = action?.toLowerCase() || '';
  const s = ACTION_STYLES[key] || { bg: 'bg-dark-700', text: 'text-dark-300', border: 'border-dark-600', icon: FiActivity };
  const Icon = s.icon || FiActivity;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium ${s.bg} ${s.text} border ${s.border}`}>
      <Icon className="w-3 h-3" />
      {action || '—'}
    </span>
  );
}

export default function SecurityLogsPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [stats, setStats] = useState({ total: 0, success: 0, failure: 0, warning: 0 });
  const intervalRef = useRef(null);
  const pageSize = 15;

  const fetchLogs = useCallback(async () => {
    try {
      const params = { skip: (page - 1) * pageSize, limit: pageSize };
      if (search.trim()) params.search = search.trim();
      if (actionFilter) params.action = actionFilter;
      const res = await logsAPI.list(params);
      const data = res.data;
      const items = data.items || data.results || data.logs || [];
      setLogs(items);
      setTotalPages(data.total_pages || Math.ceil((data.total || 0) / pageSize) || 1);
      setTotalCount(data.total || data.count || 0);

      let success = 0, failure = 0, warning = 0;
      items.forEach((log) => {
        const r = (log.result || log.status || '').toLowerCase();
        if (['success', 'passed', 'clean'].includes(r)) success++;
        else if (['failure', 'failed', 'malicious'].includes(r)) failure++;
        else if (['warning', 'suspicious'].includes(r)) warning++;
      });
      setStats({ total: data.total || items.length, success, failure, warning });
    } catch (err) {
      console.error('Failed to fetch security logs', err);
      setLogs([]);
    } finally {
      setLoading(false);
    }
  }, [page, search, actionFilter]);

  useEffect(() => {
    setLoading(true);
    fetchLogs();
  }, [fetchLogs]);

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(fetchLogs, 10000);
    }
    return () => clearInterval(intervalRef.current);
  }, [autoRefresh, fetchLogs]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-2">
            <FiDatabase className="text-cyan-400" /> Security Logs
          </h1>
          <p className="text-dark-400 text-sm mt-1">Complete audit trail of all system activities and security events</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => { setAutoRefresh(!autoRefresh); }}
            className={`inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all border ${
              autoRefresh
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 shadow-lg shadow-emerald-500/10'
                : 'bg-dark-800 text-dark-300 border-dark-700 hover:bg-dark-700 hover:text-dark-100'
            }`}
          >
            <FiRefreshCw className={`w-4 h-4 ${autoRefresh ? 'animate-spin' : ''}`} />
            {autoRefresh ? 'Live' : 'Auto-refresh'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard icon={FiDatabase} label="Total Entries" value={totalCount} color="bg-cyan-500/10 text-cyan-400" />
        <StatCard icon={FiCheckCircle} label="Successful" value={stats.success} color="bg-emerald-500/10 text-emerald-400" />
        <StatCard icon={FiAlertTriangle} label="Warnings" value={stats.warning} color="bg-amber-500/10 text-amber-400" />
        <StatCard icon={FiXCircle} label="Failures" value={stats.failure} color="bg-red-500/10 text-red-400" />
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 relative">
            <FiSearch className="absolute left-3.5 top-1/2 -translate-y-1/2 text-dark-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              placeholder="Search by user, action, or details..."
              className="w-full pl-10 pr-4 py-2.5 bg-dark-950 border border-dark-700 rounded-xl text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm transition-colors"
            />
          </div>
          <div className="relative">
            <FiFilter className="absolute left-3.5 top-1/2 -translate-y-1/2 text-dark-500 pointer-events-none" />
            <select
              value={actionFilter}
              onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
              className="pl-10 pr-8 py-2.5 bg-dark-950 border border-dark-700 rounded-xl text-dark-100 text-sm focus:outline-none focus:border-cyan-500/50 appearance-none cursor-pointer min-w-[180px] transition-colors"
            >
              {ACTION_TYPES.map((type) => (
                <option key={type.value} value={type.value}>{type.label}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <div className="animate-spin h-10 w-10 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
              <p className="text-dark-400 text-sm">Loading security logs...</p>
            </div>
          </div>
        ) : logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-dark-500">
            <FiDatabase className="text-4xl mb-3 opacity-50" />
            <p className="text-lg font-medium">No logs found</p>
            <p className="text-sm mt-1">
              {search || actionFilter ? 'Try adjusting your search or filter' : 'Security events will appear here'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700 bg-dark-950/50">
                  <th className="text-left px-5 py-3.5 text-dark-400 font-medium text-xs uppercase tracking-wider">
                    <div className="flex items-center gap-1.5">
                      <FiClock className="w-3.5 h-3.5" />
                      Time
                    </div>
                  </th>
                  <th className="text-left px-5 py-3.5 text-dark-400 font-medium text-xs uppercase tracking-wider">User</th>
                  <th className="text-left px-5 py-3.5 text-dark-400 font-medium text-xs uppercase tracking-wider">Action</th>
                  <th className="text-left px-5 py-3.5 text-dark-400 font-medium text-xs uppercase tracking-wider">Details</th>
                  <th className="text-left px-5 py-3.5 text-dark-400 font-medium text-xs uppercase tracking-wider">Result</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log, idx) => (
                  <tr
                    key={log.id || idx}
                    className="border-b border-dark-700/50 hover:bg-dark-950/60 transition-colors group"
                  >
                    <td className="px-5 py-3.5 whitespace-nowrap">
                      <div className="text-xs text-dark-400 font-mono">{formatDate(log.timestamp || log.created_at)}</div>
                      <div className="text-[11px] text-dark-500 mt-0.5">{formatRelative(log.timestamp || log.created_at)}</div>
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/20 flex items-center justify-center">
                          <span className="text-xs font-bold text-cyan-400">
                            {(log.user || log.username || 'U').charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <span className="text-dark-100 text-sm font-medium">{log.user || log.username || '—'}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3.5">
                      <ActionBadge action={log.action || log.event || log.type} />
                    </td>
                    <td className="px-5 py-3.5 text-dark-300 text-sm max-w-[280px]">
                      <div className="truncate" title={log.details || log.description || log.message}>
                        {log.details || log.description || log.message || '—'}
                      </div>
                    </td>
                    <td className="px-5 py-3.5">
                      <ResultBadge result={log.result || log.status || log.outcome} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {!loading && logs.length > 0 && (
          <div className="px-5 py-3.5 border-t border-dark-700 flex items-center justify-between bg-dark-950/30">
            <p className="text-xs text-dark-400">
              Showing page <span className="text-dark-300 font-medium">{page}</span> of <span className="text-dark-300 font-medium">{totalPages}</span>
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="inline-flex items-center gap-1 px-3 py-1.5 bg-dark-800 hover:bg-dark-700 disabled:opacity-40 disabled:cursor-not-allowed text-dark-200 border border-dark-700 rounded-lg text-xs font-medium transition-colors"
              >
                <FiChevronLeft className="w-3.5 h-3.5" />
                Prev
              </button>
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                let pageNum;
                if (totalPages <= 5) pageNum = i + 1;
                else if (page <= 3) pageNum = i + 1;
                else if (page >= totalPages - 2) pageNum = totalPages - 4 + i;
                else pageNum = page - 2 + i;
                return (
                  <button
                    key={pageNum}
                    onClick={() => setPage(pageNum)}
                    className={`w-8 h-8 rounded-lg text-xs font-medium transition-colors ${
                      page === pageNum
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : 'bg-dark-800 text-dark-300 border border-dark-700 hover:bg-dark-700'
                    }`}
                  >
                    {pageNum}
                  </button>
                );
              })}
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="inline-flex items-center gap-1 px-3 py-1.5 bg-dark-800 hover:bg-dark-700 disabled:opacity-40 disabled:cursor-not-allowed text-dark-200 border border-dark-700 rounded-lg text-xs font-medium transition-colors"
              >
                Next
                <FiChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
