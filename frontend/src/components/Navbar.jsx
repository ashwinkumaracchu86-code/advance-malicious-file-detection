import { useState, useRef, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';
import {
  FiSearch, FiBell, FiUser, FiSettings, FiLogOut, FiChevronRight,
  FiMenu, FiX, FiCheckCircle, FiAlertTriangle, FiShield, FiActivity, FiXOctagon,
} from 'react-icons/fi';
import { antivirusAPI } from '../services/api';

const PAGE_TITLES = {
  '/': 'Dashboard',
  '/antivirus': 'Antivirus Protection',
  '/scanner': 'File Scanner',
  '/sandbox': 'File Sandbox',
  '/scan': 'File Scanner',
  '/history': 'Scan History',
  '/quarantine': 'Quarantine',
  '/usb-scanner': 'USB Scanner',
  '/folder-monitor': 'Folder Monitor',
  '/scheduled-scans': 'Scheduled Scans',
  '/reports': 'Reports',
  '/export': 'Export Data',
  '/webhooks': 'Webhooks',
  '/backup': 'Backup & Restore',
  '/api-keys': 'API Keys',
  '/hash-lookup': 'Hash Lookup',
  '/threat-intel': 'Threat Intel',
  '/network-share': 'Network Scanner',
  '/system-health': 'System Health',
  '/security-logs': 'Security Logs',
  '/settings': 'Settings',
  '/profile': 'Profile',
  '/email-security': 'Email Security',
  '/email-monitor': 'Live Monitor',
  '/email-settings': 'Email Settings',
  '/email-quarantine': 'Email Quarantine',
};

const BREADCRUMB_NAMES = {
  '/': 'Home',
  '/antivirus': 'Antivirus',
  '/scanner': 'File Scanner',
  '/sandbox': 'File Sandbox',
  '/scan': 'File Scanner',
  '/history': 'Scan History',
  '/quarantine': 'Quarantine',
  '/usb-scanner': 'USB Scanner',
  '/folder-monitor': 'Folder Monitor',
  '/scheduled-scans': 'Scheduled Scans',
  '/reports': 'Reports',
  '/export': 'Export Data',
  '/webhooks': 'Webhooks',
  '/backup': 'Backup & Restore',
  '/api-keys': 'API Keys',
  '/hash-lookup': 'Hash Lookup',
  '/threat-intel': 'Threat Intel',
  '/network-share': 'Network Scanner',
  '/system-health': 'System Health',
  '/security-logs': 'Security Logs',
  '/settings': 'Settings',
  '/profile': 'Profile',
  '/email-security': 'Email Security',
  '/email-monitor': 'Live Monitor',
  '/email-settings': 'Email Settings',
  '/email-quarantine': 'Email Quarantine',
};

export default function Navbar({ title, onMenuClick }) {
  const { user, logout, isAdmin } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [showDropdown, setShowDropdown] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const dropdownRef = useRef(null);
  const notifRef = useRef(null);

  const pageTitle = title || PAGE_TITLES[location.pathname] || 'Dashboard';
  const unreadCount = notifications.filter((n) => !n.read).length;

  const breadcrumbParts = location.pathname.split('/').filter(Boolean);

  useEffect(() => {
    const fetchNotifications = async () => {
      try {
        const res = await antivirusAPI.getNotifications({ limit: 20 });
        setNotifications(res.data.notifications || []);
      } catch (err) {
        // Silently fail - notifications are non-critical
      }
    };
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setShowDropdown(false);
      }
      if (notifRef.current && !notifRef.current.contains(e.target)) {
        setShowNotifications(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogout = () => {
    logout();
    toast.success('Logged out successfully');
    navigate('/login');
  };

  const markAllRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    toast.success('All notifications marked as read');
  };

  const getInitials = () => {
    const name = user?.username || user?.name || 'U';
    return name.charAt(0).toUpperCase();
  };

  return (
    <header className="sticky top-0 z-40 h-16 bg-dark-900/80 backdrop-blur-md border-b border-dark-700 flex items-center justify-between px-4 lg:px-6">
      <div className="flex items-center gap-3">
        <button
          onClick={onMenuClick}
          className="lg:hidden p-2 rounded-lg text-dark-400 hover:text-dark-100 hover:bg-dark-800 transition-colors"
        >
          <FiMenu className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-lg font-semibold text-dark-100">{pageTitle}</h1>
          {breadcrumbParts.length > 0 && (
            <div className="flex items-center gap-1 text-[11px] text-dark-500">
              <span
                className="hover:text-dark-300 cursor-pointer transition-colors"
                onClick={() => navigate('/')}
              >
                Home
              </span>
              {breadcrumbParts.map((part, i) => (
                <span key={i} className="flex items-center gap-1">
                  <FiChevronRight className="w-3 h-3" />
                  <span className={i === breadcrumbParts.length - 1 ? 'text-dark-300' : 'hover:text-dark-300 cursor-pointer transition-colors'}>
                    {BREADCRUMB_NAMES[`/${part}`] || part}
                  </span>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2">
        <div className="hidden md:flex items-center relative">
          <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search..."
            className="pl-10 pr-4 py-2 w-64 bg-dark-950 border border-dark-700 rounded-lg text-dark-100 placeholder-dark-500 focus:outline-none focus:border-cyan-500/50 text-sm"
          />
        </div>

        <div className="relative" ref={notifRef}>
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-lg text-dark-400 hover:text-dark-100 hover:bg-dark-800 transition-colors"
          >
            <FiBell className="w-5 h-5" />
            {unreadCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 w-4.5 h-4.5 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center border border-dark-900">
                {unreadCount}
              </span>
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 top-full mt-2 w-80 bg-dark-900 border border-dark-700 rounded-xl shadow-2xl overflow-hidden">
              <div className="px-4 py-3 border-b border-dark-700 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-dark-100">Notifications</h3>
                {unreadCount > 0 && (
                  <button
                    onClick={markAllRead}
                    className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                  >
                    Mark all read
                  </button>
                )}
              </div>
              <div className="max-h-80 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="p-6 text-center text-dark-500 text-sm">No notifications</div>
                ) : (
                  notifications.map((notif) => (
                    <div
                      key={notif.id}
                      className={`px-4 py-3 border-b border-dark-700/50 hover:bg-dark-950 transition-colors ${
                        !notif.read ? 'bg-dark-950/50' : ''
                      }`}
                    >
                        <div className="flex items-start gap-3">
                        <div className={`mt-0.5 shrink-0 ${
                          notif.type === 'threat' ? 'text-red-400' :
                          notif.type === 'success' ? 'text-green-400' :
                          notif.type === 'warning' ? 'text-yellow-400' :
                          notif.type === 'error' ? 'text-red-400' :
                          'text-cyan-400'
                        }`}>
                          {notif.type === 'threat' ? (
                            <FiAlertTriangle className="w-4 h-4" />
                          ) : notif.type === 'success' ? (
                            <FiCheckCircle className="w-4 h-4" />
                          ) : notif.type === 'warning' ? (
                            <FiAlertTriangle className="w-4 h-4" />
                          ) : notif.type === 'error' ? (
                            <FiXOctagon className="w-4 h-4" />
                          ) : (
                            <FiActivity className="w-4 h-4" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className={`text-sm ${!notif.read ? 'text-dark-100 font-medium' : 'text-dark-300'}`}>
                            {notif.message}
                          </p>
                          <p className="text-[11px] text-dark-500 mt-0.5">
                            {notif.timestamp ? new Date(notif.timestamp).toLocaleTimeString() : ''}
                          </p>
                        </div>
                        {!notif.read && (
                          <span className="w-2 h-2 rounded-full bg-cyan-400 shrink-0 mt-1.5" />
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setShowDropdown(!showDropdown)}
            className="flex items-center gap-2 p-1.5 rounded-lg hover:bg-dark-800 transition-colors"
          >
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
              <span className="text-sm font-bold text-white">{getInitials()}</span>
            </div>
          </button>

          {showDropdown && (
            <div className="absolute right-0 top-full mt-2 w-56 bg-dark-900 border border-dark-700 rounded-xl shadow-2xl overflow-hidden">
              <div className="px-4 py-3 border-b border-dark-700">
                <p className="text-sm font-medium text-dark-100">{user?.username || user?.name || 'User'}</p>
                <p className="text-xs text-dark-400">{user?.email || 'user@example.com'}</p>
              </div>
              <div className="py-1">
                <button
                  onClick={() => {
                    setShowDropdown(false);
                    navigate('/profile');
                  }}
                  className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-dark-300 hover:text-dark-100 hover:bg-dark-800 transition-colors"
                >
                  <FiUser className="w-4 h-4" />
                  Profile
                </button>
                <button
                    onClick={() => {
                      setShowDropdown(false);
                      navigate('/settings');
                    }}
                    className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-dark-300 hover:text-dark-100 hover:bg-dark-800 transition-colors"
                  >
                    <FiSettings className="w-4 h-4" />
                    Settings
                  </button>
              </div>
              <div className="border-t border-dark-700 py-1">
                <button
                  onClick={handleLogout}
                  className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
                >
                  <FiLogOut className="w-4 h-4" />
                  Logout
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
