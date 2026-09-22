import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FiShield,
  FiAlertTriangle,
  FiCheckCircle,
  FiTrash2,
  FiEye,
  FiArrowLeft,
  FiRefreshCw,
  FiLock,
  FiMail,
  FiClock,
} from 'react-icons/fi';
import { emailSecurityAPI } from '../services/api';

const getRiskScoreColor = (score) => {
  if (score >= 80) return 'bg-red-500/20 text-red-400 border-red-500/30';
  if (score >= 50) return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
  if (score >= 30) return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
  return 'bg-green-500/20 text-green-400 border-green-500/30';
};

const getStatusColor = (status) => {
  switch (status?.toLowerCase()) {
    case 'quarantined':
      return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'released':
      return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'deleted':
      return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    default:
      return 'bg-dark-700 text-dark-400 border-dark-600';
  }
};

const formatDate = (dateString) => {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
};

export default function EmailQuarantinePage() {
  const navigate = useNavigate();
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [actionLoading, setActionLoading] = useState(null);

  const fetchQuarantine = useCallback(async (showRefresh = false) => {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      setError(null);

      const response = await emailSecurityAPI.getQuarantine({ limit: 50 });
      setEmails(response.data?.emails || response.emails || []);
    } catch (err) {
      console.error('Failed to fetch quarantine data:', err);
      setError(err.message || 'Failed to load quarantined emails');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchQuarantine();
  }, [fetchQuarantine]);

  const handleRelease = async (id) => {
    if (!window.confirm('Are you sure you want to release this email? It will be delivered to the recipient.')) {
      return;
    }

    try {
      setActionLoading(id);
      await emailSecurityAPI.quarantineAction(id, {
        action: 'release',
        reason: 'Released by administrator',
      });
      await fetchQuarantine(true);
    } catch (err) {
      console.error('Failed to release email:', err);
      alert('Failed to release email: ' + (err.message || 'Unknown error'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to permanently delete this email? This action cannot be undone.')) {
      return;
    }

    try {
      setActionLoading(id);
      await emailSecurityAPI.quarantineAction(id, {
        action: 'delete',
        reason: 'Deleted by administrator',
      });
      await fetchQuarantine(true);
    } catch (err) {
      console.error('Failed to delete email:', err);
      alert('Failed to delete email: ' + (err.message || 'Unknown error'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleView = (id) => {
    navigate(`/email-security/email/${id}`);
  };

  const filteredEmails = emails.filter((email) => {
    const matchesStatus =
      statusFilter === 'all' || email.status?.toLowerCase() === statusFilter;
    const matchesSearch =
      !searchQuery ||
      email.sender?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      email.subject?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      email.id?.toString().includes(searchQuery);
    return matchesStatus && matchesSearch;
  });

  const stats = {
    total: emails.length,
    quarantined: emails.filter((e) => e.status?.toLowerCase() === 'quarantined').length,
    released: emails.filter((e) => e.status?.toLowerCase() === 'released').length,
    deleted: emails.filter((e) => e.status?.toLowerCase() === 'deleted').length,
  };

  const statCards = [
    {
      label: 'Total Quarantined',
      value: stats.total,
      icon: FiMail,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/30',
    },
    {
      label: 'Pending Review',
      value: stats.quarantined,
      icon: FiClock,
      color: 'text-orange-400',
      bg: 'bg-orange-500/10',
      border: 'border-orange-500/30',
    },
    {
      label: 'Released',
      value: stats.released,
      icon: FiCheckCircle,
      color: 'text-green-400',
      bg: 'bg-green-500/10',
      border: 'border-green-500/30',
    },
    {
      label: 'Deleted',
      value: stats.deleted,
      icon: FiTrash2,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
      border: 'border-red-500/30',
    },
  ];

  if (loading) {
    return (
      <div className="min-h-screen bg-dark-900 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-dark-400 text-lg">Loading quarantined emails...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-dark-900 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4 max-w-md text-center">
          <FiAlertTriangle className="w-16 h-16 text-red-400" />
          <h2 className="text-xl font-semibold text-dark-100">Error Loading Data</h2>
          <p className="text-dark-400">{error}</p>
          <button
            onClick={() => fetchQuarantine()}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            <FiRefreshCw className="w-4 h-4" />
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-dark-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate(-1)}
              className="p-2 text-dark-400 hover:text-dark-100 hover:bg-dark-700 rounded-lg transition-colors"
            >
              <FiArrowLeft className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-500/10 border border-red-500/30 rounded-lg">
                <FiLock className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-dark-100">Email Quarantine</h1>
                <p className="text-dark-400 text-sm">Review and manage quarantined emails</p>
              </div>
            </div>
          </div>
          <button
            onClick={() => fetchQuarantine(true)}
            disabled={refreshing}
            className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 text-dark-100 rounded-lg transition-colors disabled:opacity-50"
          >
            <FiRefreshCw
              className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`}
            />
            Refresh
          </button>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {statCards.map((stat) => {
            const Icon = stat.icon;
            return (
              <div
                key={stat.label}
                className={`${stat.bg} border ${stat.border} rounded-xl p-5`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-dark-400 mb-1">{stat.label}</p>
                    <p className={`text-3xl font-bold ${stat.color}`}>{stat.value}</p>
                  </div>
                  <Icon className={`w-8 h-8 ${stat.color} opacity-60`} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Filters */}
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4 mb-6">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <FiMail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
                <input
                  type="text"
                  placeholder="Search by sender, subject, or ID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-dark-900 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
            <div className="flex gap-2">
              {['all', 'quarantined', 'released', 'deleted'].map((status) => (
                <button
                  key={status}
                  onClick={() => setStatusFilter(status)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors capitalize ${
                    statusFilter === status
                      ? 'bg-blue-600 text-white'
                      : 'bg-dark-700 text-dark-400 hover:text-dark-100 hover:bg-dark-600'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Email Table */}
        {filteredEmails.length === 0 ? (
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-12">
            <div className="flex flex-col items-center gap-4">
              <div className="p-4 bg-dark-700 rounded-full">
                <FiShield className="w-12 h-12 text-dark-400" />
              </div>
              <h3 className="text-lg font-semibold text-dark-100">No Quarantined Emails</h3>
              <p className="text-dark-400 text-center max-w-md">
                {searchQuery || statusFilter !== 'all'
                  ? 'No emails match your current filters. Try adjusting your search or filter criteria.'
                  : 'The quarantine is currently empty. Threatened emails will appear here when detected.'}
              </p>
              {(searchQuery || statusFilter !== 'all') && (
                <button
                  onClick={() => {
                    setSearchQuery('');
                    setStatusFilter('all');
                  }}
                  className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-dark-100 rounded-lg transition-colors text-sm"
                >
                  Clear Filters
                </button>
              )}
            </div>
          </div>
        ) : (
          <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-dark-700">
                    <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase tracking-wider">
                      ID
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase tracking-wider">
                      Sender
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase tracking-wider">
                      Subject
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase tracking-wider">
                      Risk Score
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase tracking-wider">
                      Classification
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-dark-400 uppercase tracking-wider">
                      Date
                    </th>
                    <th className="px-6 py-4 text-right text-xs font-semibold text-dark-400 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-700">
                  {filteredEmails.map((email) => (
                    <tr
                      key={email.id}
                      className="hover:bg-dark-700/50 transition-colors"
                    >
                      <td className="px-6 py-4">
                        <span className="text-sm font-mono text-dark-400">
                          #{email.id}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <FiMail className="w-4 h-4 text-dark-500 flex-shrink-0" />
                          <span className="text-sm text-dark-100 truncate max-w-[200px]">
                            {email.sender || 'Unknown'}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-dark-100 truncate max-w-[250px] block">
                          {email.subject || 'No Subject'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold border ${getRiskScoreColor(
                            email.risk_score
                          )}`}
                        >
                          {email.risk_score ?? 'N/A'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-dark-300 capitalize">
                          {email.classification || 'Unknown'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold border capitalize ${getStatusColor(
                            email.status
                          )}`}
                        >
                          {email.status || 'Unknown'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-sm text-dark-400">
                          {formatDate(email.quarantined_at || email.created_at || email.date)}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => handleView(email.id)}
                            className="p-2 text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors"
                            title="View Details"
                          >
                            <FiEye className="w-4 h-4" />
                          </button>
                          {(email.status?.toLowerCase() === 'quarantined') && (
                            <>
                              <button
                                onClick={() => handleRelease(email.id)}
                                disabled={actionLoading === email.id}
                                className="p-2 text-green-400 hover:bg-green-500/10 rounded-lg transition-colors disabled:opacity-50"
                                title="Release Email"
                              >
                                <FiCheckCircle className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => handleDelete(email.id)}
                                disabled={actionLoading === email.id}
                                className="p-2 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors disabled:opacity-50"
                                title="Delete Email"
                              >
                                <FiTrash2 className="w-4 h-4" />
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Table Footer */}
            <div className="px-6 py-4 border-t border-dark-700">
              <p className="text-sm text-dark-400">
                Showing {filteredEmails.length} of {emails.length} emails
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
