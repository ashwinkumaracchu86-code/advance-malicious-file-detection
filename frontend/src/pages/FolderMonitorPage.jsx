import { useState, useEffect, useRef, useCallback } from 'react';
import toast from 'react-hot-toast';
import {
  FiFolder, FiPlay, FiSquare, FiActivity, FiMonitor, FiFile,
  FiCheckCircle, FiAlertTriangle, FiRefreshCw, FiInfo, FiTrash2,
  FiLock, FiXOctagon, FiShield,
} from 'react-icons/fi';
import { antivirusAPI } from '../services/api';

export default function FolderMonitorPage() {
  const [folderPath, setFolderPath] = useState('');
  const [monitoring, setMonitoring] = useState(false);
  const [detectedFiles, setDetectedFiles] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);
  const [monitoredPaths, setMonitoredPaths] = useState([]);
  const [startTime, setStartTime] = useState(null);
  const [elapsed, setElapsed] = useState('00:00:00');
  const timerRef = useRef(null);
  const refreshInterval = useRef(null);

  const fetchData = useCallback(async () => {
    try {
      const [statusRes, histRes] = await Promise.all([
        antivirusAPI.getStatus(),
        antivirusAPI.getScanHistory(),
      ]);
      const paths = statusRes.data.monitored_paths || [];
      setMonitoredPaths(paths);
      setMonitoring(paths.length > 0);
      setScanHistory(histRes.data.history || []);
    } catch (err) {
      console.error('Failed to fetch monitor data:', err);
    }
  }, []);

  useEffect(() => {
    fetchData();
    refreshInterval.current = setInterval(fetchData, 5000);
    return () => {
      clearInterval(refreshInterval.current);
      clearInterval(timerRef.current);
    };
  }, [fetchData]);

  useEffect(() => {
    if (monitoring && startTime) {
      timerRef.current = setInterval(() => {
        const diff = Date.now() - startTime;
        const hrs = String(Math.floor(diff / 3600000)).padStart(2, '0');
        const mins = String(Math.floor((diff % 3600000) / 60000)).padStart(2, '0');
        const secs = String(Math.floor((diff % 60000) / 1000)).padStart(2, '0');
        setElapsed(`${hrs}:${mins}:${secs}`);
      }, 1000);
    }
    return () => clearInterval(timerRef.current);
  }, [monitoring, startTime]);

  const handleStart = async () => {
    if (!folderPath.trim()) {
      toast.error('Please enter a folder path');
      return;
    }
    try {
      await antivirusAPI.addMonitoredPath(folderPath);
      setMonitoring(true);
      setStartTime(Date.now());
      toast.success(`Monitoring started for: ${folderPath}`);
      setFolderPath('');
      fetchData();
    } catch (err) {
      toast.error('Failed to start monitoring');
    }
  };

  const handleStop = async (path) => {
    try {
      await antivirusAPI.removeMonitoredPath(path);
      toast.success('Monitoring stopped');
      fetchData();
    } catch (err) {
      toast.error('Failed to stop monitoring');
    }
  };

  const handleStopAll = async () => {
    for (const path of monitoredPaths) {
      try {
        await antivirusAPI.removeMonitoredPath(path);
      } catch (err) {
        // Continue with other paths
      }
    }
    setMonitoring(false);
    clearInterval(timerRef.current);
    toast('All monitoring stopped', { icon: '⏹' });
    fetchData();
  };

  const getRiskBadge = (risk) => {
    const map = {
      safe: 'bg-green-500/20 text-green-400 border border-green-500/30',
      suspicious: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
      malicious: 'bg-red-500/20 text-red-400 border border-red-500/30',
    };
    return map[risk] || 'bg-dark-700 text-dark-300 border border-dark-600';
  };

  const formatTime = (ts) => {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleTimeString();
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100">Folder Monitor</h1>
        <p className="text-dark-400 text-sm mt-1">Real-time file system monitoring and threat detection</p>
      </div>

      <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-xl p-4 flex items-start gap-3">
        <FiInfo className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-cyan-400">Live Backend Integration</p>
          <p className="text-xs text-dark-400 mt-1">
            Folder monitoring is connected to the backend. Add folders to monitor and all new files will be
            automatically scanned. Threats will be quarantined automatically.
          </p>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-lg">
            <FiMonitor className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-dark-100">How Folder Monitoring Works</h2>
            <p className="text-xs text-dark-400">Continuous file system event tracking</p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { icon: FiFolder, title: 'Directory Watch', desc: 'Monitors specified directories for new files using OS event APIs' },
            { icon: FiActivity, title: 'Auto-Scan', desc: 'Automatically scans new files against all detection engines' },
            { icon: FiShield, title: 'Auto-Quarantine', desc: 'Threats are automatically quarantined to protect your system' },
          ].map((item, i) => (
            <div key={i} className="flex items-start gap-3 p-3 bg-dark-950 rounded-lg border border-dark-700/50">
              <item.icon className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-dark-100">{item.title}</p>
                <p className="text-xs text-dark-400 mt-0.5">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-dark-100 mb-4">Add Folder to Monitor</h3>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 relative">
            <FiFolder className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" />
            <input
              type="text"
              value={folderPath}
              onChange={(e) => setFolderPath(e.target.value)}
              placeholder="Enter folder path (e.g., C:\Users\Downloads)"
              className="w-full pl-10 pr-4 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm font-mono"
            />
          </div>
          <button
            onClick={handleStart}
            className="inline-flex items-center gap-2 px-5 py-2.5 bg-green-600 hover:bg-green-500 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <FiPlay className="w-4 h-4" />
            Start Monitoring
          </button>
        </div>

        {monitoredPaths.length > 0 && (
          <div className="mt-4 flex items-center gap-4 p-3 bg-dark-950 rounded-lg border border-dark-700/50">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse" />
              <span className="text-sm font-medium text-green-400">Monitoring Active</span>
            </div>
            <div className="h-4 w-px bg-dark-700" />
            <div className="flex items-center gap-2">
              <FiFolder className="w-3.5 h-3.5 text-dark-400" />
              <span className="text-xs text-dark-300">{monitoredPaths.length} folder(s)</span>
            </div>
            <div className="h-4 w-px bg-dark-700" />
            <button
              onClick={handleStopAll}
              className="inline-flex items-center gap-1 px-3 py-1 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded text-xs font-medium transition-colors"
            >
              <FiSquare className="w-3 h-3" />
              Stop All
            </button>
          </div>
        )}
      </div>

      {monitoredPaths.length > 0 && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-dark-700 flex items-center gap-2">
            <FiFolder className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-dark-100">Monitored Folders</h3>
          </div>
          <div className="p-4 space-y-2">
            {monitoredPaths.map((path, idx) => (
              <div key={idx} className="flex items-center justify-between bg-dark-950 rounded-lg px-4 py-3 border border-dark-700">
                <div className="flex items-center gap-3">
                  <FiFolder className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm text-dark-100 font-mono">{path}</span>
                </div>
                <button
                  onClick={() => handleStop(path)}
                  className="text-dark-500 hover:text-red-400 transition-colors"
                >
                  <FiTrash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {scanHistory.length > 0 && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-dark-700 flex items-center gap-2">
            <FiRefreshCw className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-dark-100">Recently Monitored Files</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700">
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Filename</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Classification</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Risk Score</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Quarantined</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {scanHistory.slice(0, 20).map((entry, idx) => (
                  <tr key={idx} className="border-b border-dark-700/50 hover:bg-dark-950 transition-colors">
                    <td className="px-5 py-3 text-dark-100">
                      <div className="flex items-center gap-2">
                        <FiFile className="w-3.5 h-3.5 text-dark-400 shrink-0" />
                        <span className="truncate max-w-[180px]">{entry.filename}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-block px-2.5 py-1 rounded text-xs font-medium border ${getRiskBadge(entry.classification)}`}>
                        {entry.classification?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className={`text-xs font-mono font-bold ${
                        entry.risk_score > 70 ? 'text-red-400' : entry.risk_score > 30 ? 'text-yellow-400' : 'text-green-400'
                      }`}>
                        {entry.risk_score}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      {entry.quarantined ? (
                        <FiLock className="w-4 h-4 text-red-400" />
                      ) : (
                        <span className="text-dark-500">-</span>
                      )}
                    </td>
                    <td className="px-5 py-3 text-dark-400 text-xs">{formatTime(entry.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-4 flex items-start gap-3">
        <FiMonitor className="w-5 h-5 text-dark-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-dark-200">Backend-Powered Monitoring</p>
          <p className="text-xs text-dark-400 mt-1">
            Monitoring is powered by the backend watchdog service. Add folders to the monitored list
            and all new files will be automatically scanned and quarantined if threats are detected.
          </p>
        </div>
      </div>
    </div>
  );
}
