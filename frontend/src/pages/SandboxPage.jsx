import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  FiShield, FiUpload, FiCheckCircle,
  FiAlertTriangle, FiClock, FiRefreshCw, FiFile, FiActivity,
} from 'react-icons/fi';

export default function SandboxPage() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [duration, setDuration] = useState(30);
  const [activeJob, setActiveJob] = useState(null);

  useEffect(() => {
    fetchJobs();
    const interval = setInterval(fetchJobs, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchJobs = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('/sandbox/jobs', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setJobs(data.jobs || []);
      } else {
        setJobs([]);
      }
    } catch (err) {
      console.error('Failed to fetch sandbox jobs', err);
      setJobs([]);
    } finally {
      setLoading(false);
    }
  };

  const handleUpload = async (file) => {
    if (!file) return;
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('duration', String(duration));

      const token = localStorage.getItem('token');
      const res = await fetch('/sandbox/submit', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      if (res.ok) {
        const data = await res.json();
        toast.success(data.message || 'File submitted for sandbox analysis');
        fetchJobs();
      } else {
        let msg = 'Failed to submit file';
        try {
          const data = await res.json();
          msg = data.detail || data.message || msg;
        } catch {}
        toast.error(msg);
      }
    } catch (err) {
      console.error('Sandbox submit error:', err);
      toast.error('Failed to submit file');
    } finally {
      setUploading(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleUpload(e.dataTransfer.files[0]);
    }
  };

  const handleDrag = (e) => {
    e.preventDefault();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const viewReport = (job) => {
    setActiveJob(job);
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'running':
        return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
      case 'completed':
        return 'bg-green-500/20 text-green-400 border border-green-500/30';
      case 'failed':
        return 'bg-red-500/20 text-red-400 border border-red-500/30';
      default:
        return 'bg-dark-500/20 text-dark-400 border border-dark-500/30';
    }
  };

  const getVerdictBadge = (verdict) => {
    if (!verdict) return 'bg-dark-500/20 text-dark-400 border border-dark-500/30';
    switch (verdict) {
      case 'malicious':
        return 'bg-red-500/20 text-red-400 border border-red-500/30';
      case 'suspicious':
        return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
      case 'clean':
        return 'bg-green-500/20 text-green-400 border border-green-500/30';
      default:
        return 'bg-dark-500/20 text-dark-400 border border-dark-500/30';
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-2">
          <FiShield className="text-cyan-400" /> File Sandbox
        </h1>
        <p className="text-dark-400 text-sm mt-1">Submit files for isolated behavior analysis in a safe environment</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-cyan-500/10">
              <FiShield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-dark-100">{jobs.length}</p>
              <p className="text-xs text-dark-400">Total Analyses</p>
            </div>
          </div>
        </div>
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-yellow-500/10">
              <FiActivity className="w-6 h-6 text-yellow-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-dark-100">{jobs.filter(j => j.status === 'running').length}</p>
              <p className="text-xs text-dark-400">Running</p>
            </div>
          </div>
        </div>
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-green-500/10">
              <FiCheckCircle className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-dark-100">{jobs.filter(j => j.status === 'completed').length}</p>
              <p className="text-xs text-dark-400">Completed</p>
            </div>
          </div>
        </div>
      </div>

      <div
        className={`bg-dark-900 border-2 border-dashed rounded-xl p-8 text-center transition-colors ${
          dragActive ? 'border-cyan-500 bg-cyan-500/5' : 'border-dark-700 hover:border-dark-600'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <div className="flex flex-col items-center">
          <div className="p-4 rounded-full bg-dark-800 mb-4">
            <FiUpload className={`w-8 h-8 ${dragActive ? 'text-cyan-400' : 'text-dark-400'}`} />
          </div>
          <p className="text-dark-100 font-medium mb-1">
            {uploading ? 'Uploading...' : 'Drag & drop a file here'}
          </p>
          <p className="text-dark-400 text-sm mb-4">or click to browse</p>
          <div className="flex items-center gap-3 mb-4">
            <label className="text-xs text-dark-400">Analysis duration:</label>
            <select
              value={duration}
              onChange={(e) => setDuration(Number(e.target.value))}
              className="bg-dark-800 border border-dark-700 rounded-lg px-3 py-1.5 text-dark-100 text-xs focus:outline-none focus:border-cyan-500/50"
            >
              <option value={15}>15 seconds</option>
              <option value={30}>30 seconds</option>
              <option value={60}>60 seconds</option>
              <option value={120}>2 minutes</option>
            </select>
          </div>
          <label className="cursor-pointer">
            <input
              type="file"
              className="hidden"
              onChange={(e) => {
                if (e.target.files[0]) handleUpload(e.target.files[0]);
                e.target.value = '';
              }}
            />
            <span className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors">
              <FiUpload className="w-4 h-4" /> Select File
            </span>
          </label>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-700 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-dark-100">Sandbox Analysis Jobs</h2>
          <button
            onClick={fetchJobs}
            disabled={loading}
            className="p-1.5 rounded text-dark-400 hover:text-dark-100 hover:bg-dark-800 transition-colors"
          >
            <FiRefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="text-center">
              <div className="animate-spin h-8 w-8 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              <p className="text-dark-400 text-sm">Loading jobs...</p>
            </div>
          </div>
        ) : jobs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-dark-500">
            <FiShield className="text-4xl mb-3" />
            <p className="text-lg font-medium">No sandbox analyses yet</p>
            <p className="text-sm mt-1">Upload a file to start behavior analysis</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700">
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Job ID</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Filename</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Status</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Verdict</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Submitted</th>
                  <th className="text-right px-5 py-3 text-dark-400 font-medium">Action</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <tr key={job.id} className="border-b border-dark-700/50 hover:bg-dark-950 transition-colors">
                    <td className="px-5 py-3 text-dark-400 text-xs font-mono">SBX-{String(job.id).padStart(4, '0')}</td>
                    <td className="px-5 py-3 text-dark-100">
                      <div className="flex items-center gap-2">
                        <FiFile className="w-3.5 h-3.5 text-dark-400" />
                        <span className="truncate max-w-[200px]">{job.filename}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium ${getStatusBadge(job.status)}`}>
                        {job.status === 'running' && <FiActivity className="w-3 h-3 animate-pulse" />}
                        {job.status === 'completed' && <FiCheckCircle className="w-3 h-3" />}
                        {job.status === 'failed' && <FiAlertTriangle className="w-3 h-3" />}
                        {job.status}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-block px-2.5 py-1 rounded text-xs font-medium ${getVerdictBadge(job.verdict)}`}>
                        {job.verdict || 'pending'}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-dark-400 text-xs">
                      <div className="flex items-center gap-1.5">
                        <FiClock className="w-3 h-3" />
                        {formatDate(job.created_at)}
                      </div>
                    </td>
                    <td className="px-5 py-3 text-right">
                      {job.status === 'completed' && (
                        <button
                          onClick={() => viewReport(job)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/20 rounded-lg text-xs font-medium transition-colors"
                        >
                          View Report
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {activeJob && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={() => setActiveJob(null)}>
          <div className="bg-dark-900 border border-dark-700 rounded-xl w-full max-w-2xl max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="px-6 py-4 border-b border-dark-700 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-dark-100">Sandbox Report</h2>
              <button onClick={() => setActiveJob(null)} className="text-dark-400 hover:text-dark-100">✕</button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-dark-400">Filename</p>
                  <p className="text-sm text-dark-100">{activeJob.filename}</p>
                </div>
                <div>
                  <p className="text-xs text-dark-400">Verdict</p>
                  <span className={`inline-block px-2.5 py-1 rounded text-xs font-medium mt-1 ${getVerdictBadge(activeJob.verdict)}`}>
                    {activeJob.verdict || 'pending'}
                  </span>
                </div>
                <div>
                  <p className="text-xs text-dark-400">File Hash</p>
                  <p className="text-sm text-dark-100 font-mono text-xs break-all">{activeJob.hash || '—'}</p>
                </div>
                <div>
                  <p className="text-xs text-dark-400">Analysis Duration</p>
                  <p className="text-sm text-dark-100">{activeJob.duration || '—'}s</p>
                </div>
              </div>
              {activeJob.behaviors && activeJob.behaviors.length > 0 && (
                <div>
                  <p className="text-xs text-dark-400 mb-2">Observed Behaviors</p>
                  <div className="space-y-2">
                    {activeJob.behaviors.map((behavior, idx) => (
                      <div key={idx} className="bg-dark-800 rounded-lg p-3 border border-dark-700">
                        <p className="text-sm text-dark-100">{behavior.description}</p>
                        <p className="text-xs text-dark-400 mt-1">Risk: {behavior.risk_level}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
