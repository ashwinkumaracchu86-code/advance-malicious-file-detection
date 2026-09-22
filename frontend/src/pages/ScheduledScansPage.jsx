import { useState, useEffect, useCallback, useRef } from 'react';
import toast from 'react-hot-toast';
import {
  FiClock, FiPlus, FiTrash2, FiPlay, FiPause, FiRefreshCw, FiFolder, FiChevronDown
} from 'react-icons/fi';
import { featuresAPI } from '../services/api';

export default function ScheduledScansPage() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [folderPath, setFolderPath] = useState('');
  const [interval, setInterval_] = useState(60);
  const [jobName, setJobName] = useState('');
  const [showPresets, setShowPresets] = useState(false);
  const [presetPaths, setPresetPaths] = useState([]);
  const dropdownRef = useRef(null);

  const fetchJobs = useCallback(async () => {
    try {
      const res = await featuresAPI.getScheduledScans();
      setJobs(res.data.jobs || []);
    } catch (err) {
      console.error('Failed to fetch scheduled scans:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchPresetPaths = useCallback(async () => {
    try {
      const res = await featuresAPI.getCommonPaths();
      setPresetPaths(res.data.paths || []);
    } catch {
      setPresetPaths([]);
    }
  }, []);

  useEffect(() => {
    fetchJobs();
    fetchPresetPaths();
    const interval = setInterval(fetchJobs, 15000);
    return () => clearInterval(interval);
  }, [fetchJobs, fetchPresetPaths]);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setShowPresets(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleAdd = async () => {
    if (!folderPath.trim()) {
      toast.error('Enter a folder path');
      return;
    }
    try {
      const res = await featuresAPI.addScheduledScan({
        folder_path: folderPath,
        interval_minutes: interval,
        name: jobName || `Scan: ${folderPath.split('\\').pop() || folderPath.split('/').pop()}`,
      });
      if (res.data.error) {
        toast.error(res.data.error);
        return;
      }
      toast.success('Scheduled scan added');
      setFolderPath('');
      setJobName('');
      fetchJobs();
    } catch (err) {
      toast.error(err.response?.data?.detail || err.response?.data?.error || 'Failed to add scheduled scan');
    }
  };

  const handleRemove = async (id) => {
    try {
      await featuresAPI.removeScheduledScan(id);
      toast.success('Scheduled scan removed');
      fetchJobs();
    } catch (err) {
      toast.error('Failed to remove');
    }
  };

  const handleToggle = async (id, enabled) => {
    try {
      await featuresAPI.toggleScheduledScan(id, enabled);
      toast.success(enabled ? 'Enabled' : 'Disabled');
      fetchJobs();
    } catch (err) {
      toast.error('Failed to toggle');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-2">
          <FiClock className="text-cyan-400" /> Scheduled Scans
        </h1>
        <p className="text-dark-400 text-sm mt-1">Automatically scan folders on a schedule</p>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
          <FiPlus className="text-cyan-400" /> Add Scheduled Scan
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div className="relative" ref={dropdownRef}>
            <input
              type="text"
              value={folderPath}
              onChange={(e) => setFolderPath(e.target.value)}
              placeholder="Folder path (e.g., C:\Downloads)"
              className="w-full px-4 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm font-mono pr-10"
            />
            <button
              onClick={() => setShowPresets(!showPresets)}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded hover:bg-dark-800 transition-colors"
              title="Quick paths"
            >
              <FiChevronDown className={`w-4 h-4 text-dark-400 transition-transform ${showPresets ? 'rotate-180' : ''}`} />
            </button>
            {showPresets && presetPaths.length > 0 && (
              <div className="absolute z-10 top-full mt-1 left-0 right-0 bg-dark-900 border border-dark-700 rounded-lg shadow-lg overflow-hidden">
                {presetPaths.map((preset) => (
                  <button
                    key={preset.label}
                    onClick={() => {
                      setFolderPath(preset.path);
                      setShowPresets(false);
                      if (!preset.exists) {
                        toast.error(`Folder not found: ${preset.path}`);
                      }
                    }}
                    className={`w-full px-4 py-2.5 text-left text-sm hover:bg-dark-800 transition-colors flex items-center gap-2 ${preset.exists ? 'text-dark-200' : 'text-dark-500'}`}
                  >
                    <FiFolder className="w-4 h-4 text-cyan-400" />
                    <span>{preset.label}</span>
                    <span className="text-xs text-dark-500 ml-auto font-mono">{preset.path}</span>
                    {!preset.exists && <span className="text-xs text-red-400 ml-1">missing</span>}
                  </button>
                ))}
              </div>
            )}
          </div>
          <input
            type="text"
            value={jobName}
            onChange={(e) => setJobName(e.target.value)}
            placeholder="Job name (optional)"
            className="px-4 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm"
          />
          <select
            value={interval}
            onChange={(e) => setInterval_(Number(e.target.value))}
            className="px-4 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 focus:outline-none focus:border-cyan-500/50 text-sm"
          >
            <option value={10}>Every 10 minutes</option>
            <option value={30}>Every 30 minutes</option>
            <option value={60}>Every 1 hour</option>
            <option value={180}>Every 3 hours</option>
            <option value={360}>Every 6 hours</option>
            <option value={720}>Every 12 hours</option>
            <option value={1440}>Every 24 hours</option>
          </select>
        </div>
        <button
          onClick={handleAdd}
          className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
        >
          <FiPlus className="w-4 h-4" /> Add Schedule
        </button>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-700 flex items-center gap-2">
          <FiClock className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-dark-100">Scheduled Jobs ({jobs.length})</h3>
        </div>
        {jobs.length === 0 ? (
          <div className="p-8 text-center text-dark-500 text-sm">No scheduled scans configured</div>
        ) : (
          <div className="divide-y divide-dark-700/50">
            {jobs.map((job) => (
              <div key={job.id} className="px-5 py-4 hover:bg-dark-950 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <FiFolder className="w-4 h-4 text-cyan-400" />
                    <div>
                      <p className="text-sm font-medium text-dark-100">{job.name}</p>
                      <p className="text-xs text-dark-400 font-mono">{job.folder_path}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-dark-400">Every {job.interval_minutes}min</span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${job.enabled ? 'bg-green-500/20 text-green-400' : 'bg-dark-700 text-dark-400'}`}>
                      {job.enabled ? 'Active' : 'Paused'}
                    </span>
                    {job.last_result && (
                      <span className="text-xs text-dark-400">Last: {job.last_result.scanned} files, {job.last_result.threats} threats</span>
                    )}
                    <button
                      onClick={() => handleToggle(job.id, !job.enabled)}
                      className="p-1.5 rounded-lg hover:bg-dark-800 transition-colors"
                    >
                      {job.enabled ? <FiPause className="w-4 h-4 text-yellow-400" /> : <FiPlay className="w-4 h-4 text-green-400" />}
                    </button>
                    <button
                      onClick={() => handleRemove(job.id)}
                      className="p-1.5 rounded-lg hover:bg-dark-800 transition-colors"
                    >
                      <FiTrash2 className="w-4 h-4 text-red-400" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
