import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  FiFileText, FiDownload, FiClock, FiCalendar,
} from 'react-icons/fi';
import { scansAPI, reportsAPI } from '../services/api';

export default function ReportsPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState(null);
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await scansAPI.list({ limit: 100 });
      setScans(res.data.scans || res.data.results || res.data.items || res.data.data || []);
    } catch (err) {
      console.error('Failed to fetch scans', err);
      setScans([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (scanId, filename) => {
    setDownloadingId(scanId);
    try {
      const res = await reportsAPI.getPDF(scanId);
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `report-${filename || scanId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      toast.success('Report downloaded');
    } catch (err) {
      toast.error('Failed to download report');
    } finally {
      setDownloadingId(null);
    }
  };

  const filteredScans = scans.filter((scan) => {
    const scanDate = scan.scan_date;
    if (!scanDate) return true;
    const d = new Date(scanDate);
    if (dateFrom && d < new Date(dateFrom)) return false;
    if (dateTo && d > new Date(dateTo + 'T23:59:59')) return false;
    return true;
  });

  const getRiskBadge = (score) => {
    if (score <= 30) return 'bg-green-500/20 text-green-400 border border-green-500/30';
    if (score <= 70) return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
    return 'bg-red-500/20 text-red-400 border border-red-500/30';
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Reports</h1>
          <p className="text-dark-400 text-sm mt-1">Download and manage scan analysis reports</p>
        </div>
        <div className="flex items-center gap-2 text-sm text-dark-400">
          <FiFileText className="text-cyan-400" />
          <span>{filteredScans.length} report(s)</span>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="flex items-center gap-2">
            <FiCalendar className="text-dark-500" />
            <span className="text-sm text-dark-400">Filter by date:</span>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              className="bg-dark-950 border border-dark-700 rounded-lg px-3 py-2 text-dark-100 text-sm focus:outline-none focus:border-cyan-500/50"
            />
            <span className="text-dark-500">to</span>
            <input
              type="date"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              className="bg-dark-950 border border-dark-700 rounded-lg px-3 py-2 text-dark-100 text-sm focus:outline-none focus:border-cyan-500/50"
            />
            {(dateFrom || dateTo) && (
              <button
                onClick={() => { setDateFrom(''); setDateTo(''); }}
                className="px-3 py-2 text-xs text-dark-400 hover:text-dark-100 bg-dark-700 hover:bg-dark-600 rounded-lg transition-colors"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="text-center">
              <div className="animate-spin h-8 w-8 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              <p className="text-dark-400 text-sm">Loading reports...</p>
            </div>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-dark-500">
            <FiFileText className="text-4xl mb-3" />
            <p className="text-lg font-medium">No reports found</p>
            <p className="text-sm mt-1">
              {scans.length === 0
                ? 'Scan some files to generate reports'
                : 'No reports match the selected date range'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700">
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Report ID</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Scan ID</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Filename</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Generated Date</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Risk Score</th>
                  <th className="text-right px-5 py-3 text-dark-400 font-medium">Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => {
                  const date = scan.scan_date;
                  return (
                    <tr
                      key={scan.id}
                      className="border-b border-dark-700/50 hover:bg-dark-950 transition-colors"
                    >
                      <td className="px-5 py-3 text-dark-400 text-xs font-mono">
                        RPT-{String(scan.id).padStart(6, '0')}
                      </td>
                      <td className="px-5 py-3 text-dark-300 text-xs font-mono">
                        #{scan.id}
                      </td>
                      <td className="px-5 py-3 text-dark-100 truncate max-w-[200px]">
                        <div className="flex items-center gap-2">
                          <FiFileText className="w-3.5 h-3.5 text-dark-400 shrink-0" />
                          <span>{scan.file?.original_filename || 'Unknown'}</span>
                        </div>
                      </td>
                      <td className="px-5 py-3 text-dark-400 text-xs">
                        <div className="flex items-center gap-1.5">
                          <FiClock className="w-3 h-3" />
                          {formatDate(date)}
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        <span className={`inline-block px-2.5 py-1 rounded text-xs font-semibold ${getRiskBadge(scan.risk_score)}`}>
                          {scan.risk_score}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-right">
                        <button
                          onClick={() => handleDownload(scan.id, scan.file?.original_filename)}
                          disabled={downloadingId === scan.id}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/20 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
                        >
                          {downloadingId === scan.id ? (
                            <>
                              <div className="animate-spin h-3 w-3 border-2 border-cyan-400 border-t-transparent rounded-full" />
                              Generating...
                            </>
                          ) : (
                            <>
                              <FiDownload className="w-3 h-3" />
                              Download PDF
                            </>
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
