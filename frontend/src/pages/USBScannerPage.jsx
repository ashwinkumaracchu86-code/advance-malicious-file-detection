import { useState, useEffect, useRef, useCallback } from 'react';
import toast from 'react-hot-toast';
import {
  FiCpu, FiMonitor, FiHardDrive, FiCheckCircle, FiAlertTriangle,
  FiPlay, FiLoader, FiInfo, FiShield, FiSearch, FiFile, FiRefreshCw,
  FiX, FiEye, FiArrowLeft,
} from 'react-icons/fi';
import { usbScannerAPI } from '../services/api';

export default function USBScannerPage() {
  const [drives, setDrives] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDrive, setSelectedDrive] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState(null);
  const [driveFiles, setDriveFiles] = useState(null);
  const [showFiles, setShowFiles] = useState(false);
  const [autoDetected, setAutoDetected] = useState(false);
  const previousDriveIds = useRef(new Set());
  const pollingRef = useRef(null);

  const fetchDrives = useCallback(async (isAuto = false) => {
    try {
      const response = await usbScannerAPI.getDrives();
      const newDrives = response.data.drives;
      const newIds = new Set(newDrives.map(d => d.id));

      if (isAuto && previousDriveIds.current.size > 0) {
        for (const drive of newDrives) {
          if (!previousDriveIds.current.has(drive.id)) {
            toast.success(`USB detected: ${drive.name}`);
            setAutoDetected(true);
            setSelectedDrive(drive);
            setScanResults(null);
            setDriveFiles(null);
            setShowFiles(false);
            break;
          }
        }
        for (const prevId of previousDriveIds.current) {
          if (!newIds.has(prevId)) {
            toast.error('USB drive disconnected');
            setSelectedDrive(prev => prev && !newIds.has(prev.id) ? null : prev);
            setScanResults(null);
            setDriveFiles(null);
            setShowFiles(false);
          }
        }
      }

      previousDriveIds.current = newIds;
      setDrives(newDrives);
    } catch (error) {
      console.error('Error fetching drives:', error);
      if (!isAuto) {
        toast.error('Failed to detect USB drives');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDrives(false);
    pollingRef.current = setInterval(() => {
      fetchDrives(true);
    }, 3000);
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [fetchDrives]);

  const handleSelectDrive = (drive) => {
    setSelectedDrive(drive);
    setScanResults(null);
    setDriveFiles(null);
    setShowFiles(false);
    toast.success(`Selected: ${drive.name}`);
  };

  const handleViewFiles = async (drive) => {
    setShowFiles(true);
    setDriveFiles(null);
    try {
      const response = await usbScannerAPI.getFiles(drive.path);
      setDriveFiles(response.data);
    } catch (error) {
      console.error('Error fetching files:', error);
      toast.error('Failed to list files');
    }
  };

  const handleScan = async (drive) => {
    const target = drive || selectedDrive;
    if (!target) {
      toast.error('Please select a drive first');
      return;
    }
    setSelectedDrive(target);
    setScanning(true);
    setScanProgress(0);
    setScanResults(null);

    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 8 + 2;
      if (progress >= 95) progress = 95;
      setScanProgress(Math.min(progress, 95));
    }, 300);

    try {
      const response = await usbScannerAPI.scanDrive(target.path);

      clearInterval(interval);
      setScanProgress(100);

      const results = response.data.results.map((result, index) => ({
        id: index + 1,
        filename: result.filename,
        risk: result.classification === 'malicious' ? 'critical' :
              result.classification === 'suspicious' ? 'high' :
              result.classification === 'clean' ? 'safe' : 'safe',
        score: result.risk_score,
        reason: result.reasons?.[0] || 'Analysis complete',
        allReasons: result.reasons || [],
        file_size: result.file_size,
        extension: result.extension,
        mime_type: result.mime_type,
        md5: result.md5,
        sha256: result.sha256,
        entropy: result.entropy,
        original_path: result.original_path,
      }));

      setScanResults(results);
      setScanning(false);

      const malicious = response.data.malicious_count;
      const suspicious = response.data.suspicious_count;
      if (malicious > 0 || suspicious > 0) {
        toast.error(`Threats found: ${malicious} malicious, ${suspicious} suspicious`);
      } else {
        toast.success('Scan complete - No threats detected');
      }
    } catch (error) {
      clearInterval(interval);
      console.error('Scan error:', error);
      toast.error('Scan failed: ' + (error.response?.data?.detail || error.message));
      setScanning(false);
      setScanProgress(0);
    }
  };

  const getRiskBadge = (risk) => {
    const map = {
      safe: 'bg-green-500/20 text-green-400 border border-green-500/30',
      low: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
      high: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
      critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
    };
    return map[risk] || 'bg-dark-700 text-dark-300 border border-dark-600';
  };

  const formatSize = (bytes) => {
    if (!bytes) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100">USB Scanner</h1>
        <p className="text-dark-400 text-sm mt-1">Real-time USB drive detection and malware scanning</p>
      </div>

      <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-4 flex items-start gap-3">
        <FiHardDrive className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-green-400">Real-Time USB Monitoring Active</p>
          <p className="text-xs text-dark-400 mt-1">
            Auto-detecting USB drives every 3 seconds. Insert a pendrive to automatically detect and scan it.
            Disconnected drives are removed automatically.
          </p>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-700 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-dark-100">
            Detected Removable Drives
            <span className="ml-2 text-dark-400 font-normal">({drives.length})</span>
          </h3>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 text-xs text-green-400">
              <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
              Auto-scan ON
            </span>
            <button
              onClick={() => fetchDrives(false)}
              disabled={loading}
              className="inline-flex items-center gap-2 px-3 py-1.5 bg-dark-700 hover:bg-dark-600 text-dark-200 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
            >
              <FiRefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
        </div>
        <div className="p-5 grid grid-cols-1 md:grid-cols-3 gap-4">
          {loading ? (
            <div className="col-span-3 flex items-center justify-center py-8">
              <FiLoader className="w-6 h-6 text-cyan-400 animate-spin" />
              <span className="ml-2 text-dark-400">Scanning for USB drives...</span>
            </div>
          ) : drives.length === 0 ? (
            <div className="col-span-3 text-center py-12">
              <FiHardDrive className="w-10 h-10 text-dark-500 mx-auto mb-3" />
              <p className="text-dark-300 text-sm font-medium">No USB drives detected</p>
              <p className="text-dark-500 text-xs mt-1">Insert a USB drive - it will appear automatically</p>
            </div>
          ) : (
            drives.map((drive) => (
              <div
                key={drive.id}
                onClick={() => handleSelectDrive(drive)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  selectedDrive?.id === drive.id
                    ? 'bg-cyan-500/10 border-cyan-500/30 ring-1 ring-cyan-500/20'
                    : 'bg-dark-950 border-dark-700/50 hover:border-dark-600'
                }`}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <FiHardDrive className={`w-5 h-5 ${selectedDrive?.id === drive.id ? 'text-cyan-400' : 'text-dark-400'}`} />
                    <span className="text-sm font-medium text-dark-100">{drive.name}</span>
                  </div>
                  <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                </div>
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <span className="text-dark-400">Capacity</span>
                    <span className="text-dark-200">{drive.size}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-dark-400">Used</span>
                    <span className="text-dark-200">{drive.used}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-dark-400">Free</span>
                    <span className="text-dark-200">{drive.free}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-dark-400">Files</span>
                    <span className="text-dark-200">{drive.files.toLocaleString()}</span>
                  </div>
                </div>
                {selectedDrive?.id === drive.id && (
                  <div className="mt-3 pt-3 border-t border-cyan-500/20 flex items-center justify-center gap-1.5">
                    <FiCheckCircle className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="text-xs font-medium text-cyan-400">Selected</span>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      {selectedDrive && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-dark-100">
                Scanning: {selectedDrive.name}
              </h3>
              <p className="text-xs text-dark-400 mt-0.5">
                {selectedDrive.path} - {selectedDrive.files} files on drive
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleViewFiles(selectedDrive)}
                disabled={showFiles}
                className="inline-flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 text-dark-200 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
              >
                <FiEye className="w-4 h-4" />
                View Files
              </button>
              <button
                onClick={() => handleScan(null)}
                disabled={scanning}
                className="inline-flex items-center gap-2 px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {scanning ? (
                  <>
                    <FiLoader className="w-4 h-4 animate-spin" />
                    Scanning... {Math.round(scanProgress)}%
                  </>
                ) : (
                  <>
                    <FiSearch className="w-4 h-4" />
                    Scan Drive
                  </>
                )}
              </button>
            </div>
          </div>

          {scanning && (
            <div className="mb-4">
              <div className="w-full h-2 bg-dark-950 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 to-cyan-400 rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
              <p className="text-xs text-dark-400 mt-2 text-center">
                Analyzing files... {Math.round(scanProgress)}% complete
              </p>
            </div>
          )}
        </div>
      )}

      {showFiles && driveFiles && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-dark-700 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowFiles(false)}
                className="p-1 hover:bg-dark-700 rounded"
              >
                <FiArrowLeft className="w-4 h-4 text-dark-400" />
              </button>
              <h3 className="text-sm font-semibold text-dark-100">
                Files on {selectedDrive?.name}
                <span className="ml-2 text-dark-400 font-normal">({driveFiles.total_files} files)</span>
              </h3>
            </div>
            <button
              onClick={() => handleScan(selectedDrive)}
              disabled={scanning}
              className="inline-flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium transition-colors"
            >
              <FiSearch className="w-3.5 h-3.5" />
              Scan All
            </button>
          </div>
          <div className="max-h-96 overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-dark-900">
                <tr className="border-b border-dark-700">
                  <th className="text-left px-4 py-2 text-dark-400 font-medium">Name</th>
                  <th className="text-left px-4 py-2 text-dark-400 font-medium">Size</th>
                  <th className="text-left px-4 py-2 text-dark-400 font-medium">Type</th>
                  <th className="text-left px-4 py-2 text-dark-400 font-medium">Modified</th>
                </tr>
              </thead>
              <tbody>
                {driveFiles.files.map((file, index) => (
                  <tr key={index} className="border-b border-dark-700/50 hover:bg-dark-950 transition-colors">
                    <td className="px-4 py-2 text-dark-100">
                      <div className="flex items-center gap-2">
                        <FiFile className="w-3.5 h-3.5 text-dark-400 shrink-0" />
                        <span className="font-mono text-xs truncate max-w-[200px]">{file.name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2 text-dark-300 text-xs">{file.size_human}</td>
                    <td className="px-4 py-2 text-dark-400 text-xs">{file.extension || '-'}</td>
                    <td className="px-4 py-2 text-dark-400 text-xs">
                      {file.modified ? new Date(file.modified).toLocaleDateString() : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {scanResults && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-dark-700">
            <h3 className="text-sm font-semibold text-dark-100">
              Scan Report
              <span className="ml-2 text-dark-400 font-normal">
                ({scanResults.length} files scanned)
              </span>
            </h3>
          </div>
          <div className="overflow-x-auto">
            {scanResults.length === 0 ? (
              <div className="text-center py-8">
                <FiCheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                <p className="text-dark-200 text-sm">No threats detected</p>
                <p className="text-dark-400 text-xs mt-1">All files appear to be safe</p>
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-dark-700">
                    <th className="text-left px-4 py-3 text-dark-400 font-medium">Filename</th>
                    <th className="text-left px-4 py-3 text-dark-400 font-medium">Risk</th>
                    <th className="text-left px-4 py-3 text-dark-400 font-medium">Score</th>
                    <th className="text-left px-4 py-3 text-dark-400 font-medium">Size</th>
                    <th className="text-left px-4 py-3 text-dark-400 font-medium">Type</th>
                    <th className="text-left px-4 py-3 text-dark-400 font-medium">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {scanResults.map((result) => (
                    <tr key={result.id} className="border-b border-dark-700/50 hover:bg-dark-950 transition-colors">
                      <td className="px-4 py-3 text-dark-100">
                        <div className="flex items-center gap-2">
                          {result.risk === 'critical' || result.risk === 'high' ? (
                            <FiAlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                          ) : (
                            <FiFile className="w-3.5 h-3.5 text-dark-400 shrink-0" />
                          )}
                          <span className="font-mono text-xs">{result.filename}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-block px-2.5 py-1 rounded text-xs font-medium ${getRiskBadge(result.risk)}`}>
                          {result.risk}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-mono font-bold ${
                          result.score > 70 ? 'text-red-400' : result.score > 30 ? 'text-yellow-400' : 'text-green-400'
                        }`}>
                          {result.score}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-dark-300 text-xs">{formatSize(result.file_size)}</td>
                      <td className="px-4 py-3 text-dark-400 text-xs">{result.extension}</td>
                      <td className="px-4 py-3 text-dark-400 text-xs max-w-[250px] truncate">{result.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-4 flex items-start gap-3">
        <FiMonitor className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-dark-200">Auto-Detection Active</p>
          <p className="text-xs text-dark-400 mt-1">
            The system polls for USB drives every 3 seconds. New drives appear automatically.
            When you insert a pendrive, it is detected in real-time and can be scanned immediately.
            Disconnected drives are removed from the list automatically.
          </p>
        </div>
      </div>
    </div>
  );
}
