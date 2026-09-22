import { useState, useEffect, useCallback } from 'react';
import {
  FiFolder, FiFolderPlus, FiTrash2, FiPlay, FiSearch, FiServer,
  FiCheckCircle, FiAlertTriangle, FiShield, FiRefreshCw, FiChevronRight,
  FiHome, FiFile, FiChevronLeft
} from 'react-icons/fi';
import toast from 'react-hot-toast';
import { networkShareAPI } from '../services/api';

export default function NetworkSharePage() {
  const [shares, setShares] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newShare, setNewShare] = useState({ name: '', path: '', share_type: 'local' });
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [scanPath, setScanPath] = useState('');
  const [recursive, setRecursive] = useState(true);
  const [browserPath, setBrowserPath] = useState('');
  const [browserEntries, setBrowserEntries] = useState([]);
  const [browserParent, setBrowserParent] = useState(null);
  const [showBrowser, setShowBrowser] = useState(false);
  const [selectedPath, setSelectedPath] = useState('');
  const [browseLoading, setBrowseLoading] = useState(false);

  const fetchShares = useCallback(async () => {
    setLoading(true);
    try {
      const res = await networkShareAPI.listShares();
      setShares(res.data.shares || []);
    } catch (err) {
      console.error('Failed to fetch shares', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchShares();
  }, [fetchShares]);

  const handleAddShare = async () => {
    if (!newShare.name.trim() || !newShare.path.trim()) {
      toast.error('Please fill in all fields');
      return;
    }
    try {
      await networkShareAPI.addShare(newShare);
      toast.success('Share added successfully');
      setShowAddModal(false);
      setNewShare({ name: '', path: '', share_type: 'local' });
      fetchShares();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to add share');
    }
  };

  const handleRemoveShare = async (shareId) => {
    if (!window.confirm('Are you sure you want to remove this share?')) return;
    try {
      await networkShareAPI.removeShare(shareId);
      toast.success('Share removed');
      fetchShares();
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to remove share');
    }
  };

  const handleScan = async () => {
    const pathToScan = selectedPath || scanPath;
    if (!pathToScan.trim()) {
      toast.error('Please enter or select a path to scan');
      return;
    }
    setScanning(true);
    setScanResults(null);
    try {
      const res = await networkShareAPI.scanPath({ path: pathToScan, recursive });
      setScanResults(res.data);
      toast.success(`Scanned ${res.data.files_scanned} file(s)`);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const browseDirectory = async (path) => {
    setBrowseLoading(true);
    try {
      const res = await networkShareAPI.browsePath(path || '/');
      setBrowserEntries(res.data.entries || []);
      setBrowserPath(res.data.current_path || '/');
      setBrowserParent(res.data.parent_path || null);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Failed to browse directory');
      setBrowserEntries([]);
    } finally {
      setBrowseLoading(false);
    }
  };

  const openBrowser = () => {
    setShowBrowser(true);
    const initialPath = scanPath || selectedPath || defaultPath;
    browseDirectory(initialPath);
  };

  const selectBrowserPath = (path) => {
    setSelectedPath(path);
    setScanPath(path);
    setShowBrowser(false);
    toast.success(`Selected: ${path}`);
  };

  const defaultPath = typeof window !== 'undefined' && window.navigator?.platform?.includes('Win') ? 'C:\\' : '/';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Network Share Scanner</h1>
          <p className="text-dark-400 text-sm mt-1">Scan files on network shares and local directories</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={openBrowser}
            className="px-4 py-2 bg-dark-800 hover:bg-dark-700 border border-dark-600 text-dark-100 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            <FiFolder className="w-4 h-4" /> Browse
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            <FiFolderPlus className="w-4 h-4" /> Add Share
          </button>
        </div>
      </div>

      {shares.length > 0 && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
          <h3 className="text-dark-200 font-semibold mb-4 flex items-center gap-2">
            <FiServer className="text-cyan-400" /> Configured Shares ({shares.length})
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {shares.map((share) => (
              <div key={share.id} className="bg-dark-950 border border-dark-700 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-dark-100 font-medium">{share.name}</span>
                  <button
                    onClick={() => handleRemoveShare(share.id)}
                    className="text-dark-500 hover:text-red-400 transition-colors"
                  >
                    <FiTrash2 className="w-4 h-4" />
                  </button>
                </div>
                <p className="text-dark-400 text-xs font-mono truncate mb-2">{share.path}</p>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 bg-dark-800 border border-dark-600 rounded text-xs text-dark-300">
                    {share.share_type.toUpperCase()}
                  </span>
                  <span className="text-dark-500 text-xs">{share.status}</span>
                </div>
                <button
                  onClick={() => { setSelectedPath(share.path); setScanPath(share.path); }}
                  className="mt-3 w-full py-1.5 bg-dark-800 hover:bg-dark-700 border border-dark-600 text-dark-200 rounded text-xs font-medium transition-colors"
                >
                  Select for scanning
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-6">
        <h3 className="text-dark-200 font-semibold mb-4 flex items-center gap-2">
          <FiSearch className="text-cyan-400" /> Scan Path
        </h3>
        <div className="flex items-center gap-3 mb-4">
          <input
            type="text"
            value={scanPath}
            onChange={(e) => { setScanPath(e.target.value); setSelectedPath(''); }}
            placeholder={`Enter path to scan (e.g., ${defaultPath}Users or /home)`}
            className="flex-1 bg-dark-950 border border-dark-600 text-dark-100 rounded-lg px-4 py-2.5 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
          />
          <button
            onClick={openBrowser}
            className="p-2.5 bg-dark-800 hover:bg-dark-700 border border-dark-600 text-dark-300 rounded-lg transition-colors"
            title="Browse"
          >
            <FiFolder />
          </button>
        </div>
        <div className="flex items-center justify-between">
          <label className="flex items-center gap-2 text-dark-300 text-sm">
            <input
              type="checkbox"
              checked={recursive}
              onChange={(e) => setRecursive(e.target.checked)}
              className="rounded border-dark-600 bg-dark-800 text-cyan-500 focus:ring-cyan-500"
            />
            Scan recursively
          </label>
          <button
            onClick={handleScan}
            disabled={scanning || !(selectedPath || scanPath).trim()}
            className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-800 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            {scanning ? (
              <>
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Scanning...
              </>
            ) : (
              <>
                <FiPlay className="w-4 h-4" /> Start Scan
              </>
            )}
          </button>
        </div>
      </div>

      {scanResults && (
        <div className="space-y-4">
          <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
            <h3 className="text-dark-200 font-semibold mb-4">Scan Results</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-dark-950 rounded-lg p-4 border border-dark-700">
                <span className="text-dark-500 text-xs block">Files Found</span>
                <span className="text-dark-100 text-xl font-bold">{scanResults.files_found}</span>
              </div>
              <div className="bg-dark-950 rounded-lg p-4 border border-dark-700">
                <span className="text-dark-500 text-xs block">Files Scanned</span>
                <span className="text-dark-100 text-xl font-bold">{scanResults.files_scanned}</span>
              </div>
              <div className="bg-dark-950 rounded-lg p-4 border border-dark-700">
                <span className="text-dark-500 text-xs block">Malicious</span>
                <span className="text-red-400 text-xl font-bold">{scanResults.malicious_count}</span>
              </div>
              <div className="bg-dark-950 rounded-lg p-4 border border-dark-700">
                <span className="text-dark-500 text-xs block">Suspicious</span>
                <span className="text-yellow-400 text-xl font-bold">{scanResults.suspicious_count}</span>
              </div>
            </div>
          </div>

          {scanResults.results && scanResults.results.length > 0 && (
            <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
              <div className="p-5 border-b border-dark-700">
                <h3 className="text-dark-200 font-semibold">Scanned Files</h3>
              </div>
              <div className="overflow-x-auto max-h-96 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-dark-900">
                    <tr className="border-b border-dark-700">
                      <th className="text-left px-5 py-3 text-dark-400 font-medium">File</th>
                      <th className="text-left px-5 py-3 text-dark-400 font-medium">Risk Score</th>
                      <th className="text-left px-5 py-3 text-dark-400 font-medium">Classification</th>
                      <th className="text-left px-5 py-3 text-dark-400 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResults.results.map((result, i) => (
                      <tr key={i} className="border-b border-dark-700/50 hover:bg-dark-950 transition-colors">
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-2">
                            <FiFile className="text-dark-500" />
                            <span className="text-dark-100 truncate max-w-[250px]">{result.filename}</span>
                          </div>
                          <p className="text-dark-500 text-xs font-mono mt-1 truncate max-w-[300px]">{result.original_path}</p>
                        </td>
                        <td className="px-5 py-3">
                          {result.risk_score !== undefined ? (
                            <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${
                              result.risk_score <= 30 ? 'bg-green-500/20 text-green-400' :
                              result.risk_score <= 70 ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-red-500/20 text-red-400'
                            }`}>
                              {result.risk_score}
                            </span>
                          ) : (
                            <span className="text-dark-500">—</span>
                          )}
                        </td>
                        <td className="px-5 py-3">
                          {result.classification ? (
                            <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${
                              result.classification === 'malicious' ? 'bg-red-500/20 text-red-400' :
                              result.classification === 'suspicious' ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-green-500/20 text-green-400'
                            }`}>
                              {result.classification}
                            </span>
                          ) : (
                            <span className="text-dark-500">—</span>
                          )}
                        </td>
                        <td className="px-5 py-3">
                          {result.scan_id ? (
                            <a
                              href={`/scan/${result.scan_id}`}
                              className="text-cyan-400 hover:text-cyan-300 text-xs"
                            >
                              View Details
                            </a>
                          ) : result.error ? (
                            <span className="text-red-400 text-xs truncate block max-w-[200px]" title={result.error}>
                              Error
                            </span>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {!scanResults && !scanning && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-12 text-center">
          <FiServer className="mx-auto text-5xl text-dark-600 mb-4" />
          <p className="text-dark-400 text-lg">Enter a path or select a configured share to scan</p>
          <p className="text-dark-500 text-sm mt-2">
            Scan network shares, local directories, or removable drives
          </p>
        </div>
      )}

      {showBrowser && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-dark-900 border border-dark-700 rounded-xl w-full max-w-2xl max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between p-5 border-b border-dark-700">
              <h3 className="text-dark-100 font-semibold">Browse Directory</h3>
              <button
                onClick={() => setShowBrowser(false)}
                className="text-dark-400 hover:text-dark-100 text-xl"
              >
                &times;
              </button>
            </div>

            <div className="p-4 border-b border-dark-700">
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={browserPath}
                  onChange={(e) => setBrowserPath(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') browseDirectory(browserPath);
                  }}
                  className="flex-1 bg-dark-950 border border-dark-600 text-dark-100 rounded-lg px-3 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  placeholder="Enter path..."
                />
                <button
                  onClick={() => browseDirectory(browserPath)}
                  disabled={browseLoading}
                  className="p-2 bg-dark-800 hover:bg-dark-700 border border-dark-600 rounded-lg text-dark-300 disabled:opacity-50"
                >
                  {browseLoading ? <FiRefreshCw className="animate-spin" /> : <FiRefreshCw />}
                </button>
              </div>

              <div className="flex items-center gap-2 mt-3">
                {browserParent && (
                  <button
                    onClick={() => browseDirectory(browserParent)}
                    className="px-3 py-1.5 bg-dark-800 hover:bg-dark-700 border border-dark-600 rounded-lg text-dark-300 text-xs flex items-center gap-1"
                  >
                    <FiChevronLeft /> Parent
                  </button>
                )}
                <button
                  onClick={() => browseDirectory(defaultPath)}
                  className="px-3 py-1.5 bg-dark-800 hover:bg-dark-700 border border-dark-600 rounded-lg text-dark-300 text-xs flex items-center gap-1"
                >
                  <FiHome /> Root
                </button>
                <button
                  onClick={() => selectBrowserPath(browserPath)}
                  className="ml-auto px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium"
                >
                  Select This Path
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-1 min-h-[200px]">
              {browseLoading ? (
                <div className="flex items-center justify-center py-8">
                  <FiRefreshCw className="animate-spin text-dark-500" />
                  <span className="ml-2 text-dark-500 text-sm">Loading...</span>
                </div>
              ) : browserEntries.length > 0 ? (
                browserEntries.map((entry, i) => (
                  <div
                    key={i}
                    className={`flex items-center justify-between p-3 rounded-lg cursor-pointer transition-colors ${
                      entry.is_dir && entry.is_readable
                        ? 'hover:bg-dark-800'
                        : entry.is_dir
                          ? 'opacity-50 cursor-not-allowed'
                          : 'hover:bg-dark-800/50 cursor-pointer'
                    }`}
                    onClick={() => {
                      if (entry.is_dir && entry.is_readable) {
                        browseDirectory(entry.path);
                      } else if (!entry.is_dir) {
                        selectBrowserPath(entry.path);
                      }
                    }}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      {entry.is_dir ? (
                        <FiFolder className="text-cyan-400 flex-shrink-0" />
                      ) : (
                        <FiFile className="text-dark-500 flex-shrink-0" />
                      )}
                      <span className="text-dark-100 text-sm truncate">{entry.name}</span>
                      {!entry.is_readable && entry.is_dir && (
                        <span className="text-dark-500 text-xs">(no access)</span>
                      )}
                    </div>
                    {entry.is_dir && entry.is_readable && <FiChevronRight className="text-dark-500" />}
                  </div>
                ))
              ) : (
                <div className="text-center py-8">
                  <FiFolder className="mx-auto text-4xl text-dark-600 mb-2" />
                  <p className="text-dark-500 text-sm">No entries found or access denied</p>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-dark-700 flex justify-end">
              <button
                onClick={() => setShowBrowser(false)}
                className="px-4 py-2 bg-dark-800 hover:bg-dark-700 border border-dark-600 text-dark-200 rounded-lg text-sm transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {showAddModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-dark-900 border border-dark-700 rounded-xl w-full max-w-md">
            <div className="flex items-center justify-between p-5 border-b border-dark-700">
              <h3 className="text-dark-100 font-semibold">Add Network Share</h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-dark-400 hover:text-dark-100 text-xl"
              >
                &times;
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1.5">Share Name</label>
                <input
                  type="text"
                  value={newShare.name}
                  onChange={(e) => setNewShare({ ...newShare, name: e.target.value })}
                  placeholder="e.g., Office Share"
                  className="w-full bg-dark-950 border border-dark-600 text-dark-100 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1.5">Path</label>
                <input
                  type="text"
                  value={newShare.path}
                  onChange={(e) => setNewShare({ ...newShare, path: e.target.value })}
                  placeholder={`e.g., ${defaultPath}Users or \\\\server\\share`}
                  className="w-full bg-dark-950 border border-dark-600 text-dark-100 rounded-lg px-4 py-2.5 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1.5">Share Type</label>
                <select
                  value={newShare.share_type}
                  onChange={(e) => setNewShare({ ...newShare, share_type: e.target.value })}
                  className="w-full bg-dark-950 border border-dark-600 text-dark-100 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
                >
                  <option value="local">Local Directory</option>
                  <option value="smb">SMB/CIFS Share</option>
                  <option value="nfs">NFS Share</option>
                </select>
              </div>
            </div>
            <div className="p-5 border-t border-dark-700 flex justify-end gap-3">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 bg-dark-800 hover:bg-dark-700 border border-dark-600 text-dark-200 rounded-lg text-sm transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAddShare}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors"
              >
                Add Share
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
