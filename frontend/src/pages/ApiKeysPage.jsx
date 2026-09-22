import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  FiLock, FiPlus, FiTrash2, FiCopy, FiEye, FiEyeOff,
  FiClock, FiCheckCircle, FiRefreshCw, FiShield,
} from 'react-icons/fi';
import { API_BASE } from '../config';

export default function ApiKeysPage() {
  const [apiKeys, setApiKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyDesc, setNewKeyDesc] = useState('');
  const [visibleKeys, setVisibleKeys] = useState({});
  const [deleting, setDeleting] = useState(null);

  useEffect(() => {
    fetchApiKeys();
  }, []);

  const fetchApiKeys = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE}/settings/api-keys`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setApiKeys(data.keys || []);
      }
    } catch (err) {
      console.error('Failed to fetch API keys', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateKey = async () => {
    if (!newKeyName.trim()) {
      toast.error('Please enter a name for the API key');
      return;
    }
    setCreating(true);
    try {
      const token = localStorage.getItem('token');
      const formData = new FormData();
      formData.append('name', newKeyName);
      formData.append('description', newKeyDesc);
      const res = await fetch(`${API_BASE}/settings/api-keys`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });
      if (res.ok) {
        const data = await res.json();
        toast.success('API key created');
        setNewKeyName('');
        setNewKeyDesc('');
        setShowForm(false);
        fetchApiKeys();
        if (data.key) {
          toast.success(`Your new key: ${data.key.substring(0, 20)}...`, { duration: 10000 });
        }
      } else {
        toast.error('Failed to create API key');
      }
    } catch (err) {
      toast.error('Failed to create API key');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteKey = async (keyId) => {
    setDeleting(keyId);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE}/settings/api-keys/${keyId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        toast.success('API key deleted');
        fetchApiKeys();
      } else {
        toast.error('Failed to delete API key');
      }
    } catch (err) {
      toast.error('Failed to delete API key');
    } finally {
      setDeleting(null);
    }
  };

  const handleCopyKey = (key) => {
    navigator.clipboard.writeText(key);
    toast.success('API key copied to clipboard');
  };

  const toggleKeyVisibility = (keyId) => {
    setVisibleKeys((prev) => ({ ...prev, [keyId]: !prev[keyId] }));
  };

  const maskKey = (key) => {
    if (!key) return '••••••••••••••••••••';
    return key.substring(0, 8) + '••••••••' + key.substring(key.length - 4);
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
          <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-2">
            <FiLock className="text-cyan-400" /> API Key Management
          </h1>
          <p className="text-dark-400 text-sm mt-1">Generate and manage API keys for external integrations</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <FiPlus className="w-4 h-4" />
          Generate New Key
        </button>
      </div>

      {showForm && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-dark-100 mb-4">Create New API Key</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-xs text-dark-400 mb-1.5">Key Name *</label>
              <input
                type="text"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="e.g., Integration Key"
                className="w-full bg-dark-950 border border-dark-700 rounded-lg px-3 py-2 text-dark-100 text-sm focus:outline-none focus:border-cyan-500/50"
              />
            </div>
            <div>
              <label className="block text-xs text-dark-400 mb-1.5">Description (optional)</label>
              <input
                type="text"
                value={newKeyDesc}
                onChange={(e) => setNewKeyDesc(e.target.value)}
                placeholder="What will this key be used for?"
                className="w-full bg-dark-950 border border-dark-700 rounded-lg px-3 py-2 text-dark-100 text-sm focus:outline-none focus:border-cyan-500/50"
              />
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCreateKey}
                disabled={creating || !newKeyName.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
              >
                {creating ? (
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                ) : (
                  <FiLock className="w-4 h-4" />
                )}
                {creating ? 'Creating...' : 'Generate Key'}
              </button>
              <button
                onClick={() => { setShowForm(false); setNewKeyName(''); setNewKeyDesc(''); }}
                className="px-4 py-2 bg-dark-800 hover:bg-dark-700 text-dark-300 rounded-lg text-sm transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-cyan-500/10">
              <FiLock className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-dark-100">{apiKeys.length}</p>
              <p className="text-xs text-dark-400">Total Keys</p>
            </div>
          </div>
        </div>
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-green-500/10">
              <FiCheckCircle className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-dark-100">{apiKeys.filter(k => k.active).length}</p>
              <p className="text-xs text-dark-400">Active Keys</p>
            </div>
          </div>
        </div>
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-yellow-500/10">
              <FiClock className="w-6 h-6 text-yellow-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-dark-100">{apiKeys.filter(k => !k.active).length}</p>
              <p className="text-xs text-dark-400">Revoked Keys</p>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-700 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-dark-100">API Keys</h2>
          <button
            onClick={fetchApiKeys}
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
              <p className="text-dark-400 text-sm">Loading API keys...</p>
            </div>
          </div>
        ) : apiKeys.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-dark-500">
            <FiLock className="text-4xl mb-3" />
            <p className="text-lg font-medium">No API keys</p>
            <p className="text-sm mt-1">Generate your first API key to get started</p>
          </div>
        ) : (
          <div className="divide-y divide-dark-700/50">
            {apiKeys.map((apiKey) => (
              <div key={apiKey.id} className="px-5 py-4 hover:bg-dark-950 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="p-2.5 rounded-lg bg-dark-800">
                      <FiLock className="w-5 h-5 text-cyan-400" />
                    </div>
                    <div>
                      <h3 className="text-sm font-medium text-dark-100">{apiKey.name}</h3>
                      <p className="text-xs text-dark-400 mt-0.5">{apiKey.description || 'No description'}</p>
                      <div className="flex items-center gap-3 mt-1.5">
                        <span className="text-[10px] text-dark-500 font-mono">
                          {visibleKeys[apiKey.id] ? apiKey.key : maskKey(apiKey.key)}
                        </span>
                        <span className="text-xs text-dark-400 flex items-center gap-1">
                          <FiClock className="w-3 h-3" /> {formatDate(apiKey.created_at)}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {apiKey.active ? (
                      <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium bg-green-500/20 text-green-400 border border-green-500/30">
                        <FiCheckCircle className="w-3 h-3" /> Active
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30">
                        <FiShield className="w-3 h-3" /> Revoked
                      </span>
                    )}
                    <button
                      onClick={() => toggleKeyVisibility(apiKey.id)}
                      className="p-2 rounded-lg text-dark-400 hover:text-dark-100 hover:bg-dark-800 transition-colors"
                      title={visibleKeys[apiKey.id] ? 'Hide key' : 'Show key'}
                    >
                      {visibleKeys[apiKey.id] ? <FiEyeOff className="w-4 h-4" /> : <FiEye className="w-4 h-4" />}
                    </button>
                    <button
                      onClick={() => handleCopyKey(apiKey.key)}
                      className="p-2 rounded-lg text-dark-400 hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors"
                      title="Copy key"
                    >
                      <FiCopy className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDeleteKey(apiKey.id)}
                      disabled={deleting === apiKey.id}
                      className="p-2 rounded-lg text-dark-400 hover:text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-50"
                      title="Delete key"
                    >
                      {deleting === apiKey.id ? (
                        <div className="animate-spin h-4 w-4 border-2 border-red-400 border-t-transparent rounded-full" />
                      ) : (
                        <FiTrash2 className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-dark-100 mb-3">API Key Security</h3>
        <div className="space-y-2 text-xs text-dark-400">
          <p><strong className="text-dark-200">Keep your API keys secure.</strong> Never share them in public repositories or client-side code.</p>
          <p><strong className="text-dark-200">Rotate keys regularly</strong> to maintain security best practices.</p>
          <p><strong className="text-dark-200">Revoke unused keys</strong> immediately if you suspect a security breach.</p>
        </div>
      </div>
    </div>
  );
}
