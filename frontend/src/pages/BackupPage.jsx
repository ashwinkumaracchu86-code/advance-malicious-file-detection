import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  FiServer, FiDownload, FiUpload, FiClock, FiCheckCircle,
  FiAlertTriangle, FiRefreshCw, FiTrash2, FiMonitor,
} from 'react-icons/fi';
import { API_BASE } from '../config';

export default function BackupPage() {
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [restoring, setRestoring] = useState(null);
  const [deleting, setDeleting] = useState(null);
  const [dbInfo, setDbInfo] = useState(null);

  useEffect(() => {
    fetchBackups();
    fetchDbInfo();
  }, []);

  const fetchBackups = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE}/settings/backups`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setBackups(data.backups || []);
      }
    } catch (err) {
      console.error('Failed to fetch backups', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchDbInfo = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE}/settings/db-info`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setDbInfo(data);
      }
    } catch (err) {
      console.error('Failed to fetch db info', err);
    }
  };

  const handleCreateBackup = async () => {
    setCreating(true);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE}/settings/backup`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        toast.success('Backup created successfully');
        fetchBackups();
      } else {
        toast.error('Failed to create backup');
      }
    } catch (err) {
      toast.error('Failed to create backup');
    } finally {
      setCreating(false);
    }
  };

  const handleRestore = async (backupId) => {
    setRestoring(backupId);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE}/settings/restore/${backupId}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        toast.success('Database restored successfully');
      } else {
        toast.error('Failed to restore database');
      }
    } catch (err) {
      toast.error('Failed to restore database');
    } finally {
      setRestoring(null);
    }
  };

  const handleDeleteBackup = async (backupId) => {
    setDeleting(backupId);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE}/settings/backup/${backupId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        toast.success('Backup deleted');
        fetchBackups();
      } else {
        toast.error('Failed to delete backup');
      }
    } catch (err) {
      toast.error('Failed to delete backup');
    } finally {
      setDeleting(null);
    }
  };

  const handleDownloadBackup = async (backup) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE}/settings/backup/${backup.id}/download`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', backup.filename);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
        toast.success('Backup downloaded');
      }
    } catch (err) {
      toast.error('Failed to download backup');
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  };

  const formatSize = (bytes) => {
    if (!bytes) return '—';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-2">
            <FiServer className="text-cyan-400" /> Backup & Restore
          </h1>
          <p className="text-dark-400 text-sm mt-1">Create and manage database backups</p>
        </div>
        <button
          onClick={handleCreateBackup}
          disabled={creating}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
        >
          {creating ? (
            <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
          ) : (
            <FiDownload className="w-4 h-4" />
          )}
          {creating ? 'Creating...' : 'Create Backup'}
        </button>
      </div>

      {dbInfo && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-3">
            <FiMonitor className="text-cyan-400" />
            <h2 className="text-sm font-semibold text-dark-100">Database Information</h2>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-xs text-dark-400">Type</p>
              <p className="text-sm font-medium text-dark-100">{dbInfo.type || 'SQLite'}</p>
            </div>
            <div>
              <p className="text-xs text-dark-400">Size</p>
              <p className="text-sm font-medium text-dark-100">{formatSize(dbInfo.size)}</p>
            </div>
            <div>
              <p className="text-xs text-dark-400">Last Modified</p>
              <p className="text-sm font-medium text-dark-100">{formatDate(dbInfo.lastModified)}</p>
            </div>
            <div>
              <p className="text-xs text-dark-400">Backups</p>
              <p className="text-sm font-medium text-dark-100">{backups.length}</p>
            </div>
          </div>
        </div>
      )}

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-700 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-dark-100">Available Backups</h2>
          <button
            onClick={fetchBackups}
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
              <p className="text-dark-400 text-sm">Loading backups...</p>
            </div>
          </div>
        ) : backups.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-dark-500">
            <FiServer className="text-4xl mb-3" />
            <p className="text-lg font-medium">No backups yet</p>
            <p className="text-sm mt-1">Create your first backup to protect your data</p>
          </div>
        ) : (
          <div className="divide-y divide-dark-700/50">
            {backups.map((backup) => (
              <div key={backup.id} className="px-5 py-4 flex items-center justify-between hover:bg-dark-950 transition-colors">
                <div className="flex items-center gap-4">
                  <div className="p-2.5 rounded-lg bg-dark-800">
                    <FiServer className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-dark-100">{backup.filename}</h3>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-xs text-dark-400 flex items-center gap-1">
                        <FiClock className="w-3 h-3" /> {formatDate(backup.created_at)}
                      </span>
                      <span className="text-xs text-dark-400">{formatSize(backup.size)}</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleDownloadBackup(backup)}
                    className="p-2 rounded-lg text-dark-400 hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors"
                    title="Download"
                  >
                    <FiDownload className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleRestore(backup.id)}
                    disabled={restoring === backup.id}
                    className="p-2 rounded-lg text-dark-400 hover:text-green-400 hover:bg-green-500/10 transition-colors disabled:opacity-50"
                    title="Restore"
                  >
                    {restoring === backup.id ? (
                      <div className="animate-spin h-4 w-4 border-2 border-green-400 border-t-transparent rounded-full" />
                    ) : (
                      <FiUpload className="w-4 h-4" />
                    )}
                  </button>
                  <button
                    onClick={() => handleDeleteBackup(backup.id)}
                    disabled={deleting === backup.id}
                    className="p-2 rounded-lg text-dark-400 hover:text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-50"
                    title="Delete"
                  >
                    {deleting === backup.id ? (
                      <div className="animate-spin h-4 w-4 border-2 border-red-400 border-t-transparent rounded-full" />
                    ) : (
                      <FiTrash2 className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-dark-100 mb-3">Backup Information</h3>
        <div className="space-y-2 text-xs text-dark-400">
          <p><strong className="text-dark-200">Automatic Backups</strong> are created before major system changes.</p>
          <p><strong className="text-dark-200">Manual Backups</strong> can be created anytime using the button above.</p>
          <p><strong className="text-dark-200">Restoring</strong> will overwrite the current database with the selected backup.</p>
        </div>
      </div>
    </div>
  );
}
