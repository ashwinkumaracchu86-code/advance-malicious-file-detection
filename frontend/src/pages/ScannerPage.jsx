import { useState, useRef, useCallback, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  FiUploadCloud, FiFile, FiX, FiCopy, FiCheck, FiExternalLink,
  FiAlertTriangle, FiShield, FiHash, FiCpu, FiLock, FiSearch, FiPlay,
  FiSquare, FiTrash2, FiClock, FiEye, FiTrendingUp, FiInfo, FiZap,
} from 'react-icons/fi';
import toast from 'react-hot-toast';
import { filesAPI, scansAPI, antivirusAPI, realtimeAPI } from '../services/api';

const SCAN_OPTIONS = [
  { id: 'hash', label: 'Hash Lookup', desc: 'Known malware DB', default: true },
  { id: 'entropy', label: 'Entropy Analysis', desc: 'Packing detection', default: true },
  { id: 'strings', label: 'String Analysis', desc: 'Suspicious strings', default: true },
  { id: 'pe', label: 'PE Analysis', desc: 'Executable inspection', default: true },
  { id: 'network', label: 'Network Scan', desc: 'Connection analysis', default: true },
];

export default function ScannerPage() {
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [autoScanEnabled, setAutoScanEnabled] = useState(true);
  const [scanOptions, setScanOptions] = useState(SCAN_OPTIONS.reduce((acc, o) => ({ ...acc, [o.id]: o.default }), {}));
  const [showOptions, setShowOptions] = useState(false);
  const fileInputRef = useRef(null);

  useEffect(() => {
    antivirusAPI.getStatus().then((res) => setAutoScanEnabled(res.data.auto_scan_enabled)).catch(() => {});
  }, []);

  const handleStopAutoScan = async () => {
    try { await realtimeAPI.stopAutoScan(); setAutoScanEnabled(false); toast.success('Auto-scan stopped'); }
    catch { toast.error('Failed to stop auto-scan'); }
  };

  const handleStartAutoScan = async () => {
    try { await realtimeAPI.startAutoScan(); setAutoScanEnabled(true); toast.success('Auto-scan started'); }
    catch { toast.error('Failed to start auto-scan'); }
  };

  const handleFiles = (fileList) => {
    const newFiles = Array.from(fileList);
    setFiles((prev) => [...prev, ...newFiles]);
    setResult(null);
  };

  const handleDrop = useCallback((e) => {
    e.preventDefault(); setDragOver(false);
    if (e.dataTransfer.files?.length) handleFiles(e.dataTransfer.files);
  }, []);

  const handleDragOver = useCallback((e) => { e.preventDefault(); setDragOver(true); }, []);
  const handleDragLeave = useCallback((e) => { e.preventDefault(); setDragOver(false); }, []);

  const removeFile = (index) => setFiles((prev) => prev.filter((_, i) => i !== index));
  const clearFiles = () => { setFiles([]); setResult(null); };

  const uploadAndScan = async () => {
    if (files.length === 0) { toast.error('Please select files to scan'); return; }
    setUploading(true); setProgress(0); setResult(null);
    try {
      const formData = new FormData();
      files.forEach((f) => formData.append('files', f));
      const uploadRes = await filesAPI.upload(formData, (e) => {
        if (e.total) setProgress(Math.round((e.loaded / e.total) * 100));
      });
      const uploadData = uploadRes.data;
      toast.success(`${uploadData.uploaded || 0} file(s) uploaded & scanned`);
      setUploading(false); setScanning(false);

      if (uploadData.results && uploadData.results.length > 0) {
        const allResults = [];
        for (const result of uploadData.results) {
          const scanResult = result.scan;
          if (scanResult && scanResult.id) {
            try {
              const detailRes = await scansAPI.get(scanResult.id);
              const detail = detailRes.data;
              let parsed = { ...detail };
              if (detail.file) parsed = { ...parsed, ...detail.file };
              ['suspicious_strings', 'detection_reasons'].forEach(key => {
                if (typeof parsed[key] === 'string') { try { parsed[key] = JSON.parse(parsed[key]); } catch { parsed[key] = []; } }
              });
              allResults.push(parsed);
            } catch { allResults.push(scanResult); }
          } else if (result.file) { allResults.push({ ...scanResult, ...result.file }); }
        }
        if (allResults.length === 1) setResult({ scan: allResults[0] });
        else {
          const malicious = allResults.filter(r => r.classification === 'malicious').length;
          const suspicious = allResults.filter(r => r.classification === 'suspicious').length;
          const safe = allResults.filter(r => r.classification === 'safe').length;
          setResult({ batch: true, results: allResults, summary: { total: allResults.length, malicious, suspicious, safe } });
        }
      } else if (uploadData.error) toast.error(uploadData.error);
      else toast.error('No results returned');
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Upload failed';
      toast.error(msg);
      setUploading(false);
    }
  };

  const copyToClipboard = (text) => navigator.clipboard.writeText(text).then(() => toast.success('Copied'));
  const formatSize = (bytes) => {
    if (!bytes) return '—';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  };
  const getRiskColor = (score) => score <= 30 ? 'text-green-400' : score <= 70 ? 'text-yellow-400' : 'text-red-400';
  const getClassBadge = (cls) => ({
    safe: 'bg-green-500/20 text-green-400 border-green-500/30',
    suspicious: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    malicious: 'bg-red-500/20 text-red-400 border-red-500/30',
  }[cls?.toLowerCase()] || 'bg-dark-700 text-dark-300 border-dark-600');

  const scanData = result?.scan || result;
  const hashes = scanData?.hashes || {};
  const suspiciousStrings = scanData?.suspicious_strings || [];
  const reasons = scanData?.detection_reasons || [];
  const totalSize = files.reduce((s, f) => s + f.size, 0);
  const activeEngines = Object.values(scanOptions).filter(Boolean).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/20">
              <FiSearch className="w-6 h-6 text-cyan-400" />
            </div>
            File Scanner
          </h1>
          <p className="text-dark-400 text-sm mt-1 ml-13">Multi-engine malware analysis and threat detection</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-dark-400 bg-dark-800 border border-dark-700 px-3 py-1.5 rounded-xl">
            <FiZap className="w-3 h-3 inline mr-1 text-cyan-400" />{activeEngines} engines active
          </span>
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
        </div>
      </div>

      {/* Drop Zone */}
      <div
        onDrop={handleDrop} onDragOver={handleDragOver} onDragLeave={handleDragLeave}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer transition-all ${
          dragOver ? 'border-cyan-400 bg-cyan-500/5 scale-[1.01]' : 'border-dark-600 hover:border-cyan-500/30 hover:bg-dark-900/50 bg-gradient-to-br from-dark-900 to-dark-950'
        }`}
      >
        <div className={`p-4 rounded-2xl inline-block mb-4 transition-all ${dragOver ? 'bg-cyan-500/20 scale-110' : 'bg-cyan-500/10 border border-cyan-500/20'}`}>
          <FiUploadCloud className={`w-10 h-10 ${dragOver ? 'text-cyan-300' : 'text-cyan-400'}`} />
        </div>
        <p className="text-dark-100 text-lg font-semibold">
          {dragOver ? 'Drop files here!' : 'Drag & drop files here, or click to browse'}
        </p>
        <p className="text-dark-500 text-sm mt-2">Supports any file type &bull; Max 50MB per file &bull; Batch upload supported</p>
        <input ref={fileInputRef} type="file" multiple onChange={(e) => handleFiles(e.target.files)} className="hidden" />
      </div>

      {/* Scan Options */}
      <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
        <button onClick={() => setShowOptions(!showOptions)}
          className="w-full px-6 py-4 flex items-center justify-between hover:bg-dark-800/50 transition-colors">
          <div className="flex items-center gap-3">
            <FiCpu className="w-4 h-4 text-cyan-400" />
            <span className="text-sm font-semibold text-dark-100">Scan Engines ({activeEngines} active)</span>
          </div>
          <span className={`text-xs text-dark-400 transition-transform ${showOptions ? 'rotate-180' : ''}`}>&#9660;</span>
        </button>
        {showOptions && (
          <div className="px-6 pb-4 grid grid-cols-2 md:grid-cols-3 gap-3">
            {SCAN_OPTIONS.map((opt) => (
              <div key={opt.id}
                className={`flex items-center justify-between p-3 rounded-xl border transition-all ${
                  scanOptions[opt.id] ? 'bg-cyan-500/5 border-cyan-500/20' : 'bg-dark-800/50 border-dark-700/50'
                }`}>
                <div>
                  <p className="text-xs font-semibold text-dark-100">{opt.label}</p>
                  <p className="text-[10px] text-dark-400">{opt.desc}</p>
                </div>
                <button onClick={() => setScanOptions({ ...scanOptions, [opt.id]: !scanOptions[opt.id] })}
                  className={`w-10 h-5 rounded-full transition-colors relative ${scanOptions[opt.id] ? 'bg-cyan-600' : 'bg-dark-700'}`}>
                  <div className={`w-4 h-4 rounded-full bg-white absolute top-0.5 transition-all ${scanOptions[opt.id] ? 'left-5' : 'left-0.5'}`} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* File Queue */}
      {files.length > 0 && (
        <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <FiFile className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-dark-100">File Queue ({files.length} files, {formatSize(totalSize)})</h3>
            </div>
            <button onClick={clearFiles} className="text-xs text-dark-400 hover:text-red-400 transition-colors flex items-center gap-1">
              <FiTrash2 className="w-3 h-3" /> Clear all
            </button>
          </div>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {files.map((f, i) => (
              <div key={i} className="flex items-center justify-between bg-dark-800/50 rounded-xl px-4 py-3 border border-dark-700/50 hover:border-dark-600 transition-all">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="p-1.5 rounded-lg bg-dark-700 border border-dark-600">
                    <FiFile className="w-3.5 h-3.5 text-dark-400" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm text-dark-100 truncate">{f.name}</p>
                    <p className="text-[10px] text-dark-500">{formatSize(f.size)}</p>
                  </div>
                </div>
                <button onClick={() => removeFile(i)} className="text-dark-500 hover:text-red-400 p-1.5 rounded-lg hover:bg-red-500/10 transition-all">
                  <FiX className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>

          {/* Upload Progress */}
          {(uploading || scanning) && (
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-dark-300 flex items-center gap-2">
                  <span className="animate-spin h-4 w-4 border-2 border-cyan-500 border-t-transparent rounded-full inline-block" />
                  {uploading ? 'Uploading & Scanning...' : 'Analyzing...'}
                </span>
                <span className="text-cyan-400 font-semibold">{uploading ? `${progress}%` : 'Processing...'}</span>
              </div>
              <div className="w-full bg-dark-800 rounded-full h-3 overflow-hidden">
                <div className={`h-full rounded-full transition-all duration-300 ${scanning ? 'bg-gradient-to-r from-cyan-500 to-blue-500 animate-pulse w-full' : 'bg-gradient-to-r from-cyan-500 to-blue-500'}`}
                  style={uploading ? { width: `${progress}%` } : undefined} />
              </div>
            </div>
          )}

          {/* Scan Button */}
          {!uploading && !scanning && (
            <button onClick={uploadAndScan}
              className="w-full mt-4 py-3.5 bg-gradient-to-r from-cyan-600 to-blue-500 hover:from-cyan-500 hover:to-blue-400 text-white font-semibold rounded-xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20">
              <FiSearch className="w-5 h-5" />
              Upload & Scan {files.length} file{files.length > 1 ? 's' : ''}
            </button>
          )}
        </div>
      )}

      {/* Batch Results */}
      {result?.batch && (
        <div className="space-y-6">
          {/* Summary */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiTrendingUp className="w-4 h-4 text-cyan-400" /> Batch Scan Summary
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Total Files', value: result.summary.total, color: 'text-cyan-400', bg: 'from-cyan-500/20 to-blue-500/20' },
                { label: 'Safe', value: result.summary.safe, color: 'text-green-400', bg: 'from-green-500/20 to-emerald-500/20' },
                { label: 'Suspicious', value: result.summary.suspicious, color: 'text-yellow-400', bg: 'from-yellow-500/20 to-orange-500/20' },
                { label: 'Malicious', value: result.summary.malicious, color: 'text-red-400', bg: 'from-red-500/20 to-pink-500/20' },
              ].map(({ label, value, color, bg }, i) => (
                <div key={i} className={`bg-gradient-to-br ${bg} border border-dark-700/50 rounded-xl p-4 text-center`}>
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                  <p className="text-xs text-dark-400 font-medium mt-1">{label}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Results Table */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-dark-700/50">
              <h3 className="text-sm font-semibold text-dark-100">Scan Results ({result.results.length} files)</h3>
            </div>
            <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-dark-900">
                  <tr className="border-b border-dark-700/50">
                    <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">File</th>
                    <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Risk</th>
                    <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Class</th>
                    <th className="text-left px-6 py-3 text-dark-400 font-medium text-xs uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {result.results.map((r, i) => (
                    <tr key={i} className="border-b border-dark-700/30 hover:bg-dark-800/50 transition-colors">
                      <td className="px-6 py-3 flex items-center gap-2">
                        <FiFile className="text-dark-500 w-3.5 h-3.5 shrink-0" />
                        <span className="text-dark-100 truncate max-w-[250px]">{r.original_filename || r.filename}</span>
                      </td>
                      <td className="px-6 py-3">
                        <span className={`px-2.5 py-1 rounded-lg text-xs font-semibold border ${
                          r.risk_score <= 30 ? 'bg-green-500/10 text-green-400 border-green-500/20' :
                          r.risk_score <= 70 ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' :
                          'bg-red-500/10 text-red-400 border-red-500/20'
                        }`}>{r.risk_score}</span>
                      </td>
                      <td className="px-6 py-3">
                        <span className={`px-2.5 py-1 rounded-lg text-xs font-semibold border ${getClassBadge(r.classification)}`}>
                          {r.classification?.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-3">
                        <Link to={`/scan/${r.id}`} className="text-cyan-400 hover:text-cyan-300 text-xs flex items-center gap-1">
                          <FiEye className="w-3 h-3" /> Details
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Single File Results */}
      {scanData && !result?.batch && (
        <div className="space-y-6">
          {/* Risk Score + File Info */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <div className="flex flex-col md:flex-row md:items-start gap-6">
              <div className="flex flex-col items-center">
                <div className="relative w-36 h-36">
                  <svg className="w-36 h-36 -rotate-90" viewBox="0 0 120 120">
                    <circle cx="60" cy="60" r="52" stroke="#1e293b" strokeWidth="10" fill="none" />
                    <circle cx="60" cy="60" r="52"
                      stroke={scanData.risk_score <= 30 ? '#22c55e' : scanData.risk_score <= 70 ? '#eab308' : '#ef4444'}
                      strokeWidth="10" fill="none"
                      strokeDasharray={`${(scanData.risk_score / 100) * 327} 327`}
                      strokeLinecap="round" />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className={`text-3xl font-bold ${getRiskColor(scanData.risk_score)}`}>{scanData.risk_score}</span>
                    <span className="text-dark-500 text-xs">/100</span>
                  </div>
                </div>
                <p className="text-dark-400 text-xs mt-2">Risk Score</p>
              </div>

              <div className="flex-1 space-y-3">
                <div className="flex items-center gap-3 flex-wrap">
                  <h2 className="text-xl font-bold text-dark-100">{scanData.filename}</h2>
                  <span className={`px-3 py-1 rounded-xl text-xs font-semibold border ${getClassBadge(scanData.classification)}`}>
                    {scanData.classification?.toUpperCase()}
                  </span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {[
                    { label: 'Size', value: formatSize(scanData.file_size || scanData.size) },
                    { label: 'Type', value: scanData.file_type || scanData.mime_type || '—' },
                    { label: 'Entropy', value: scanData.entropy?.toFixed(2) || '—' },
                    { label: 'Scan Date', value: scanData.created_at ? new Date(scanData.created_at).toLocaleString() : '—' },
                  ].map(({ label, value }, i) => (
                    <div key={i} className="bg-dark-800/50 rounded-xl p-3 border border-dark-700/50">
                      <span className="text-dark-500 text-[10px] uppercase tracking-wider block">{label}</span>
                      <span className="text-dark-100 text-sm font-medium">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Hashes */}
          <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
              <FiHash className="w-4 h-4 text-cyan-400" /> File Hashes
            </h3>
            <div className="space-y-2">
              {[
                { label: 'MD5', value: hashes.md5 },
                { label: 'SHA-1', value: hashes.sha1 },
                { label: 'SHA-256', value: hashes.sha256 },
              ].map((h) => h.value && (
                <div key={h.label} className="flex items-center justify-between bg-dark-800/50 rounded-xl px-4 py-3 border border-dark-700/50">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="text-dark-500 text-xs font-medium w-16 flex-shrink-0">{h.label}</span>
                    <code className="text-dark-200 text-xs font-mono truncate">{h.value}</code>
                  </div>
                  <button onClick={() => copyToClipboard(h.value)} className="text-dark-500 hover:text-cyan-400 ml-2 p-1.5 rounded-lg hover:bg-cyan-500/10 transition-all" title="Copy">
                    <FiCopy size={14} />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Detection Reasons */}
          {reasons.length > 0 && (
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <FiAlertTriangle className="w-4 h-4 text-red-400" /> Detection Reasons
              </h3>
              <div className="space-y-2">
                {reasons.map((r, i) => (
                  <div key={i} className="flex items-start gap-3 text-sm bg-red-500/5 rounded-xl px-4 py-3 border border-red-500/10">
                    <FiAlertTriangle className="text-red-400 mt-0.5 flex-shrink-0 w-4 h-4" />
                    <span className="text-dark-300">{r}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Suspicious Strings */}
          {suspiciousStrings.length > 0 && (
            <div className="bg-gradient-to-br from-dark-900 to-dark-950 border border-dark-700 rounded-2xl p-6">
              <h3 className="text-sm font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <FiEye className="w-4 h-4 text-orange-400" /> Suspicious Strings ({suspiciousStrings.length})
              </h3>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {suspiciousStrings.map((s, i) => (
                  <div key={i} className="bg-dark-800/50 rounded-xl px-4 py-2 border border-dark-700/50 font-mono text-xs text-dark-300 flex items-center gap-2">
                    <span className="text-dark-600 w-8 flex-shrink-0">#{i + 1}</span>
                    <span className="truncate">{typeof s === 'string' ? s : s.value || JSON.stringify(s)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Full Report Link */}
          <div className="flex justify-center">
            <Link to={`/scan/${scanData.id}`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-dark-800 to-dark-700 hover:from-dark-700 hover:to-dark-600 border border-dark-600 text-dark-100 rounded-xl transition-all shadow-lg">
              <FiExternalLink className="w-4 h-4" /> View Full Report
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
