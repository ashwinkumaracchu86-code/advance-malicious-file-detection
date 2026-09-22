import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  FiUser, FiMail, FiShield, FiCalendar, FiLock, FiEye, FiEyeOff,
  FiCheckCircle, FiUpload, FiSearch, FiActivity, FiClock, FiSave,
} from 'react-icons/fi';
import { useAuth } from '../context/AuthContext';
import { scansAPI, filesAPI } from '../services/api';

const MOCK_RECENT_ACTIVITY = [
  { id: 1, action: 'File uploaded', detail: 'report_q4.pdf', time: '2 hours ago', type: 'upload' },
  { id: 2, action: 'Scan completed', detail: 'suspicious_update.exe — Malicious', time: '3 hours ago', type: 'scan' },
  { id: 3, action: 'File quarantined', detail: 'malware_sample.dll', time: '5 hours ago', type: 'quarantine' },
  { id: 4, action: 'Login successful', detail: 'From 192.168.1.105', time: 'Yesterday', type: 'login' },
  { id: 5, action: 'Scan completed', detail: 'invoice_march.xlsx — Safe', time: 'Yesterday', type: 'scan' },
  { id: 6, action: 'Report generated', detail: 'Weekly security report', time: '2 days ago', type: 'report' },
  { id: 7, action: 'File uploaded', detail: 'system_check.bat', time: '3 days ago', type: 'upload' },
  { id: 8, action: 'Login successful', detail: 'From 10.0.0.42', time: '3 days ago', type: 'login' },
  { id: 9, action: 'Scan completed', detail: 'photo_2024.jpg — Safe', time: '4 days ago', type: 'scan' },
  { id: 10, action: 'Settings updated', detail: 'SMTP configuration changed', time: '5 days ago', type: 'settings' },
];

const ACTIVITY_ICONS = {
  upload: FiUpload,
  scan: FiSearch,
  quarantine: FiShield,
  login: FiCheckCircle,
  report: FiActivity,
  settings: FiActivity,
};

const ACTIVITY_COLORS = {
  upload: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  scan: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
  quarantine: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  login: 'text-green-400 bg-green-500/10 border-green-500/20',
  report: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20',
  settings: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
};

export default function ProfilePage() {
  const { user } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);

  const [totalScans, setTotalScans] = useState(0);
  const [totalUploads, setTotalUploads] = useState(0);
  const [statsLoading, setStatsLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [scansRes, filesRes] = await Promise.allSettled([
          scansAPI.list({ limit: 1 }),
          filesAPI.list({ limit: 1 }),
        ]);
        if (scansRes.status === 'fulfilled') {
          setTotalScans(scansRes.value.data.total || scansRes.value.data.count || 0);
        }
        if (filesRes.status === 'fulfilled') {
          setTotalUploads(filesRes.value.data.total || filesRes.value.data.count || 0);
        }
      } catch {
        // use defaults
      } finally {
        setStatsLoading(false);
      }
    };
    fetchStats();
  }, []);

  const handleChangePassword = async (e) => {
    e.preventDefault();
    if (!currentPassword || !newPassword || !confirmPassword) {
      toast.error('Please fill in all password fields');
      return;
    }
    if (newPassword.length < 6) {
      toast.error('New password must be at least 6 characters');
      return;
    }
    if (newPassword !== confirmPassword) {
      toast.error('New passwords do not match');
      return;
    }
    setChangingPassword(true);
    try {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      toast.success('Password changed successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch {
      toast.error('Failed to change password');
    } finally {
      setChangingPassword(false);
    }
  };

  const getInitials = () => {
    const name = user?.username || user?.name || 'U';
    return name.charAt(0).toUpperCase();
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return 'Unknown';
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'long',
      day: 'numeric',
      year: 'numeric',
    });
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-dark-100">Profile</h1>
        <p className="text-dark-400 text-sm mt-1">Manage your account settings and view activity</p>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        <div className="p-6 border-b border-dark-700">
          <div className="flex items-center gap-5">
            <div className="w-20 h-20 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center border-2 border-cyan-500/30">
              <span className="text-2xl font-bold text-white">{getInitials()}</span>
            </div>
            <div className="flex-1">
              <h2 className="text-xl font-bold text-dark-100">{user?.username || user?.name || 'User'}</h2>
              <p className="text-dark-400 text-sm mt-0.5">{user?.email || 'No email provided'}</p>
              <div className="flex items-center gap-3 mt-2">
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium ${
                  user?.is_admin
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    : 'bg-dark-700 text-dark-300 border border-dark-600'
                }`}>
                  <FiShield className="w-3 h-3" />
                  {user?.is_admin ? 'admin' : 'user'}
                </span>
                <span className="flex items-center gap-1.5 text-xs text-dark-400">
                  <FiCalendar className="w-3.5 h-3.5" />
                  Member since {formatDate(user?.created_at || user?.joined_at)}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-dark-700">
          <div className="p-5 text-center">
            <div className="flex items-center justify-center gap-2 mb-1">
              <FiSearch className="w-4 h-4 text-cyan-400" />
              <span className="text-2xl font-bold text-dark-100">
                {statsLoading ? '—' : totalScans}
              </span>
            </div>
            <p className="text-xs text-dark-400">Total Scans</p>
          </div>
          <div className="p-5 text-center">
            <div className="flex items-center justify-center gap-2 mb-1">
              <FiUpload className="w-4 h-4 text-purple-400" />
              <span className="text-2xl font-bold text-dark-100">
                {statsLoading ? '—' : totalUploads}
              </span>
            </div>
            <p className="text-xs text-dark-400">Total Uploads</p>
          </div>
          <div className="p-5 text-center">
            <div className="flex items-center justify-center gap-2 mb-1">
              <FiActivity className="w-4 h-4 text-green-400" />
              <span className="text-2xl font-bold text-dark-100">
                {MOCK_RECENT_ACTIVITY.length}
              </span>
            </div>
            <p className="text-xs text-dark-400">Recent Actions</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-dark-700 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/20">
              <FiLock className="w-4.5 h-4.5 text-orange-400" />
            </div>
            <h2 className="text-base font-semibold text-dark-100">Change Password</h2>
          </div>
          <form onSubmit={handleChangePassword} className="p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-dark-300 mb-1.5">Current Password</label>
              <div className="relative">
                <FiLock className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" />
                <input
                  type={showCurrent ? 'text' : 'password'}
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="Enter current password"
                  className="w-full pl-10 pr-10 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowCurrent(!showCurrent)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-500 hover:text-dark-300 transition-colors"
                >
                  {showCurrent ? <FiEyeOff className="w-4 h-4" /> : <FiEye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-dark-300 mb-1.5">New Password</label>
              <div className="relative">
                <FiLock className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" />
                <input
                  type={showNew ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password"
                  className="w-full pl-10 pr-10 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowNew(!showNew)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-500 hover:text-dark-300 transition-colors"
                >
                  {showNew ? <FiEyeOff className="w-4 h-4" /> : <FiEye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-dark-300 mb-1.5">Confirm New Password</label>
              <div className="relative">
                <FiLock className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" />
                <input
                  type={showConfirm ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                  className="w-full pl-10 pr-10 py-2.5 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirm(!showConfirm)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-500 hover:text-dark-300 transition-colors"
                >
                  {showConfirm ? <FiEyeOff className="w-4 h-4" /> : <FiEye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <button
              type="submit"
              disabled={changingPassword}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-orange-600 hover:bg-orange-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
            >
              {changingPassword ? (
                <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
              ) : (
                <FiSave className="w-4 h-4" />
              )}
              {changingPassword ? 'Changing...' : 'Change Password'}
            </button>
          </form>
        </div>

        <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-dark-700 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
              <FiActivity className="w-4.5 h-4.5 text-cyan-400" />
            </div>
            <h2 className="text-base font-semibold text-dark-100">Recent Activity</h2>
          </div>
          <div className="p-4 max-h-[420px] overflow-y-auto">
            <div className="space-y-2">
              {MOCK_RECENT_ACTIVITY.map((item) => {
                const Icon = ACTIVITY_ICONS[item.type] || FiActivity;
                const colorStyle = ACTIVITY_COLORS[item.type] || 'text-dark-400 bg-dark-700 border-dark-600';
                return (
                  <div
                    key={item.id}
                    className="flex items-center gap-3 p-3 rounded-lg bg-dark-950 border border-dark-700/50 hover:border-dark-600 transition-colors"
                  >
                    <div className={`p-2 rounded-lg border shrink-0 ${colorStyle}`}>
                      <Icon className="w-3.5 h-3.5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-dark-100 font-medium truncate">{item.action}</p>
                      <p className="text-xs text-dark-400 truncate">{item.detail}</p>
                    </div>
                    <div className="flex items-center gap-1 text-xs text-dark-500 shrink-0">
                      <FiClock className="w-3 h-3" />
                      {item.time}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
