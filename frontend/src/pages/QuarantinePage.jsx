import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  FiShield, FiTrash2, FiRotateCcw, FiClock, FiLock, FiUnlock,
  FiAlertTriangle, FiCheckCircle, FiX,
} from 'react-icons/fi';
import { quarantineAPI } from '../services/api';

function ConfirmModal({ open, onClose, onConfirm, title, message }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="relative bg-dark-900 border border-dark-700 rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/10 border border-red-500/20 rounded-lg">
              <FiAlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <h3 className="text-lg font-semibold text-dark-100">{title}</h3>
          </div>
          <button onClick={onClose} className="p-1 text-dark-400 hover:text-dark-100 transition-colors">
            <FiX className="w-5 h-5" />
          </button>
        </div>
        <p className="text-sm text-dark-400 mb-6">{message}</p>
        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-dark-200 rounded-lg text-sm font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm font-medium transition-colors"
          >
            Confirm Delete
          </button>
        </div>
      </div>
    </div>
  );
}

export default function QuarantinePage() {
  const [quarantineList, setQuarantineList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [restoringId, setRestoringId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);

  useEffect(() => {
    fetchQuarantine();
  }, []);

  const fetchQuarantine = async () => {
    setLoading(true);
    try {
      const res = await quarantineAPI.list();
      setQuarantineList(res.data.items || res.data.results || res.data || []);
    } catch (err) {
      console.error('Failed to fetch quarantine list', err);
      setQuarantineList([]);
    } finally {
      setLoading(false);
    }
  };

  const handleRestore = async (id) => {
    setRestoringId(id);
    try {
      await quarantineAPI.restore(id);
      toast.success('File restored successfully');
      setQuarantineList((prev) => prev.filter((item) => item.id !== id));
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to restore file');
    } finally {
      setRestoringId(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeletingId(deleteTarget.id);
    try {
      await quarantineAPI.delete(deleteTarget.id);
      toast.success('Quarantine entry deleted');
      setQuarantineList((prev) => prev.filter((item) => item.id !== deleteTarget.id));
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to delete');
    } finally {
      setDeletingId(null);
      setDeleteTarget(null);
    }
  };

  const truncateHash = (hash) => {
    if (!hash) return '—';
    if (hash.length <= 16) return hash;
    return hash.slice(0, 8) + '...' + hash.slice(-8);
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
          <h1 className="text-2xl font-bold text-dark-100">Quarantine Management</h1>
          <p className="text-dark-400 text-sm mt-1">Manage isolated files flagged as threats</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-red-500/10 border border-red-500/20 rounded-lg">
            <FiLock className="w-4 h-4 text-red-400" />
            <span className="text-sm font-medium text-red-400">{quarantineList.length} quarantined</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-dark-700 border border-dark-600 rounded-lg">
            <FiShield className="w-4 h-4 text-cyan-400" />
            <span className="text-sm text-dark-300">Admin Only</span>
          </div>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="text-center">
              <div className="animate-spin h-8 w-8 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              <p className="text-dark-400 text-sm">Loading quarantine list...</p>
            </div>
          </div>
        ) : quarantineList.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-dark-500">
            <FiShield className="text-4xl mb-3" />
            <p className="text-lg font-medium">Quarantine is empty</p>
            <p className="text-sm mt-1">No files have been quarantined yet</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700">
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Quarantine ID</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Original Filename</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">File Hash</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Quarantine Date</th>
                  <th className="text-left px-5 py-3 text-dark-400 font-medium">Status</th>
                  <th className="text-right px-5 py-3 text-dark-400 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {quarantineList.map((item) => (
                  <tr
                    key={item.id}
                    className="border-b border-dark-700/50 hover:bg-dark-950 transition-colors"
                  >
                    <td className="px-5 py-3 text-dark-400 text-xs font-mono">QRN-{String(item.id).padStart(6, '0')}</td>
                    <td className="px-5 py-3 text-dark-100 truncate max-w-[200px]">
                      <div className="flex items-center gap-2">
                        <FiLock className="w-3.5 h-3.5 text-red-400 shrink-0" />
                        <span>{item.original_filename || item.filename}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <code className="text-dark-300 text-xs font-mono">
                        {truncateHash(item.file_hash || item.hash)}
                      </code>
                    </td>
                    <td className="px-5 py-3 text-dark-400 text-xs">
                      {formatDate(item.quarantined_at || item.created_at)}
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium ${
                        item.status === 'quarantined'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : 'bg-green-500/20 text-green-400 border border-green-500/30'
                      }`}>
                        {item.status === 'quarantined' ? <FiLock className="w-3 h-3" /> : <FiUnlock className="w-3 h-3" />}
                        {item.status || 'quarantined'}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleRestore(item.id)}
                          disabled={restoringId === item.id}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-green-500/10 hover:bg-green-500/20 text-green-400 border border-green-500/20 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
                          title="Restore file"
                        >
                          <FiRotateCcw className="w-3 h-3" />
                          {restoringId === item.id ? 'Restoring...' : 'Restore'}
                        </button>
                        <button
                          onClick={() => setDeleteTarget(item)}
                          disabled={deletingId === item.id}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
                          title="Delete permanently"
                        >
                          <FiTrash2 className="w-3 h-3" />
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Delete Quarantine Entry"
        message={`Are you sure you want to permanently delete the quarantined file "${deleteTarget?.original_filename || deleteTarget?.filename}"? This action cannot be undone.`}
      />
    </div>
  );
}
