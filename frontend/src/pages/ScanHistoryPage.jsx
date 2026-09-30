import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  FiSearch, FiFilter, FiChevronLeft, FiChevronRight, FiClock, FiFile, FiTrash2
} from 'react-icons/fi';
import toast from 'react-hot-toast';
import { scansAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';

const CLASSIFICATIONS = ['All', 'Safe', 'Suspicious', 'Malicious'];
const SORT_OPTIONS = [
  { value: 'created_at', label: 'Date (Newest)' },
  { value: '-created_at', label: 'Date (Oldest)' },
  { value: '-risk_score', label: 'Risk (High-Low)' },
  { value: 'risk_score', label: 'Risk (Low-High)' },
  { value: 'filename', label: 'Filename (A-Z)' },
  { value: '-filename', label: 'Filename (Z-A)' },
];

export default function ScanHistoryPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useAuth();

  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [totalCount, setTotalCount] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [classification, setClassification] = useState(searchParams.get('classification') || 'All');
  const [sort, setSort] = useState(searchParams.get('sort') || '-created_at');
  const [dateFrom, setDateFrom] = useState(searchParams.get('date_from') || '');
  const [dateTo, setDateTo] = useState(searchParams.get('date_to') || '');
  const perPage = 15;

  const fetchScans = useCallback(async () => {
    if (!user) {
      setScans([]);
      setTotalCount(0);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const params = {
        skip: (currentPage - 1) * perPage,
        limit: perPage,
        sort_by: sort.replace(/^-/, ''),
        sort_order: sort.startsWith('-') ? 'desc' : 'asc',
      };
      if (search) params.search = search;
      if (classification !== 'All') params.classification = classification.toLowerCase();
      if (dateFrom) params.date_from = dateFrom;
      if (dateTo) params.date_to = dateTo;

      const res = await scansAPI.list(params);
      const data = res.data;
      const rawScans = data.scans || data.results || data.items || [];
      const currentUid = String(user.id);
      const userScans = rawScans.filter((s) => {
        const scanUid = s.user_id != null ? String(s.user_id) : null;
        const fileUid = s.file?.uploaded_by != null ? String(s.file.uploaded_by) : null;
        const uploadUid = s.uploaded_by != null ? String(s.uploaded_by) : null;
        return scanUid === currentUid || fileUid === currentUid || uploadUid === currentUid;
      });
      setScans(userScans);
      setTotalCount(userScans.length);
    } catch (err) {
      console.error('Failed to fetch scan history', err);
      setScans([]);
    } finally {
      setLoading(false);
    }
  }, [user, currentPage, search, classification, sort, dateFrom, dateTo]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  useEffect(() => {
    // Reset scans state whenever active user identity changes
    setScans([]);
    setTotalCount(0);
    setCurrentPage(1);
  }, [user?.id]);

  useEffect(() => {
    const params = {};
    if (search) params.search = search;
    if (classification !== 'All') params.classification = classification;
    if (sort !== '-created_at') params.sort = sort;
    if (dateFrom) params.date_from = dateFrom;
    if (dateTo) params.date_to = dateTo;
    setSearchParams(params, { replace: true });
  }, [search, classification, sort, dateFrom, dateTo]);

  const handleDeleteScan = async (scanId) => {
    if (!window.confirm(`Are you sure you want to delete scan #${scanId}?`)) return;
    try {
      await scansAPI.delete(scanId);
      toast.success('Scan deleted successfully');
      fetchScans();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to delete scan');
    }
  };

  const totalPages = Math.ceil(totalCount / perPage);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setCurrentPage(1);
    fetchScans();
  };

  const truncateHash = (hash) => {
    if (!hash) return '—';
    if (hash.length <= 16) return hash;
    return hash.slice(0, 8) + '...' + hash.slice(-8);
  };

  const formatSize = (bytes) => {
    if (!bytes) return '—';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  };

  const getRiskBadge = (score) => {
    if (score <= 30) return 'bg-green-500/20 text-green-400 border-green-500/30';
    if (score <= 70) return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    return 'bg-red-500/20 text-red-400 border-red-500/30';
  };

  const getClassBadge = (cls) => {
    const map = {
      safe: 'bg-green-500/20 text-green-400 border-green-500/30',
      suspicious: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      malicious: 'bg-red-500/20 text-red-400 border-red-500/30',
    };
    return map[cls?.toLowerCase()] || 'bg-dark-700 text-dark-300 border-dark-600';
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100">Scan History</h1>
        <p className="text-dark-400 text-sm mt-1">Browse and search all file scan results</p>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
        <div className="flex flex-col lg:flex-row gap-4">
          <form onSubmit={handleSearchSubmit} className="flex-1 relative">
            <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by filename or hash..."
              className="w-full pl-10 pr-4 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm"
            />
          </form>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <FiFilter className="text-dark-500" />
              <select
                value={classification}
                onChange={(e) => { setClassification(e.target.value); setCurrentPage(1); }}
                className="bg-dark-950 border border-dark-700 rounded-lg px-3 py-2.5 text-dark-100 text-sm focus:outline-none focus:border-cyan-500/50"
              >
                {CLASSIFICATIONS.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>

            <select
              value={sort}
              onChange={(e) => setSort(e.target.value)}
              className="bg-dark-950 border border-dark-700 rounded-lg px-3 py-2.5 text-dark-100 text-sm focus:outline-none focus:border-cyan-500/50"
            >
              {SORT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>

            <div className="flex items-center gap-2">
              <FiClock className="text-dark-500" />
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => { setDateFrom(e.target.value); setCurrentPage(1); }}
                className="bg-dark-950 border border-dark-700 rounded-lg px-3 py-2.5 text-dark-100 text-sm focus:outline-none focus:border-cyan-500/50"
              />
              <span className="text-dark-500">—</span>
              <input
                type="date"
                value={dateTo}
                onChange={(e) => { setDateTo(e.target.value); setCurrentPage(1); }}
                className="bg-dark-950 border border-dark-700 rounded-lg px-3 py-2.5 text-dark-100 text-sm focus:outline-none focus:border-cyan-500/50"
              />
            </div>
          </div>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="text-center">
              <div className="animate-spin h-8 w-8 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              <p className="text-dark-400 text-sm">Loading scan history...</p>
            </div>
          </div>
        ) : scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-52 text-dark-400">
            <FiFile className="text-4xl mb-3 text-dark-500" />
            <p className="text-lg font-medium text-dark-200">No scan history available.</p>
            <p className="text-sm text-dark-400 mt-1">
              {search || classification !== 'All' || dateFrom || dateTo
                ? 'No scans match your search or filters. Try adjusting them.'
                : 'Upload and scan a file to start building your personal scan history.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700">
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">ID</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Filename</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Hash</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Size</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Risk Score</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Classification</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Date</th>
                  <th className="text-right px-5 py-3 text-dark-400 font-medium">Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => navigate(`/scan/${scan.id}`)}
                    className="border-b border-dark-700/50 hover:bg-dark-950 cursor-pointer transition-colors"
                  >
                    <td className="px-5 py-3 text-dark-400 text-xs font-mono">#{scan.id}</td>
                    <td className="px-5 py-3 text-dark-100 truncate max-w-[200px]">
                      <div className="flex items-center gap-2">
                        <FiFile className="text-dark-500 flex-shrink-0" />
                        <span>{scan.filename || scan.file?.original_filename || 'Unknown'}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <code className="text-dark-300 text-xs font-mono">
                        {truncateHash(scan.hash || scan.sha256 || scan.file?.sha256 || scan.hashes?.sha256)}
                      </code>
                    </td>
                    <td className="px-5 py-3 text-dark-300 text-xs">
                      {formatSize(scan.file_size ?? scan.size ?? scan.file?.file_size)}
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-block px-2.5 py-1 rounded text-xs font-semibold border ${getRiskBadge(scan.risk_score)}`}>
                        {scan.risk_score}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-block px-2.5 py-1 rounded text-xs font-semibold border ${getClassBadge(scan.classification)}`}>
                        {scan.classification}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-dark-400 text-xs">
                      {scan.created_at || scan.scan_date || scan.file?.upload_date
                        ? new Date(scan.created_at || scan.scan_date || scan.file?.upload_date).toLocaleDateString()
                        : '—'}
                    </td>
                    <td className="px-5 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        onClick={() => handleDeleteScan(scan.id)}
                        className="p-1.5 rounded-lg text-dark-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                        title="Delete scan record"
                      >
                        <FiTrash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-dark-400 text-sm">
            Showing {((currentPage - 1) * perPage) + 1}—{Math.min(currentPage * perPage, totalCount)} of {totalCount}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-2 bg-dark-900 border border-dark-700 rounded-lg text-dark-300 hover:bg-dark-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              <FiChevronLeft />
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              let page;
              if (totalPages <= 5) {
                page = i + 1;
              } else if (currentPage <= 3) {
                page = i + 1;
              } else if (currentPage >= totalPages - 2) {
                page = totalPages - 4 + i;
              } else {
                page = currentPage - 2 + i;
              }
              return (
                <button
                  key={page}
                  onClick={() => setCurrentPage(page)}
                  className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    currentPage === page
                      ? 'bg-cyan-600 text-white'
                      : 'bg-dark-900 border border-dark-700 text-dark-300 hover:bg-dark-800'
                  }`}
                >
                  {page}
                </button>
              );
            })}
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-2 bg-dark-900 border border-dark-700 rounded-lg text-dark-300 hover:bg-dark-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              <FiChevronRight />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
