import { useEffect, useRef } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';
import {
  FiGrid, FiUpload, FiClock, FiShield, FiCpu, FiFolder, FiFileText,
  FiActivity, FiSettings, FiChevronLeft, FiChevronRight, FiLogOut,
  FiUser, FiX, FiShieldOff, FiUsers,
  FiMonitor, FiCalendar, FiDownload, FiHash, FiTrendingUp, FiServer, FiMail,
  FiLink, FiLock, FiDatabase,
} from 'react-icons/fi';

const NAV_SECTIONS = [
  {
    title: null,
    items: [
      { path: '/', label: 'Dashboard', icon: FiGrid },
    ],
  },
  {
    title: 'Protection',
    items: [
      { path: '/antivirus', label: 'Antivirus', icon: FiShieldOff },
      { path: '/firewall', label: 'Firewall', icon: FiLock },
      { path: '/sandbox', label: 'File Sandbox', icon: FiShield },
      { path: '/hash-lookup', label: 'Hash Lookup', icon: FiHash },
    ],
  },
  {
    title: 'Scanning',
    items: [
      { path: '/scanner', label: 'File Scanner', icon: FiUpload },
      { path: '/threat-intel', label: 'Threat Intel', icon: FiTrendingUp },
      { path: '/network-share', label: 'Network Scanner', icon: FiServer },
      { path: '/usb-scanner', label: 'USB Scanner', icon: FiCpu },
      { path: '/folder-monitor', label: 'Folder Monitor', icon: FiFolder },
    ],
  },
  {
    title: 'Email',
    items: [
      { path: '/email-security', label: 'Email Security', icon: FiMail },
      { path: '/email-monitor', label: 'Live Monitor', icon: FiActivity },
      { path: '/email-quarantine', label: 'Email Quarantine', icon: FiShield },
      { path: '/email-settings', label: 'Email Settings', icon: FiSettings },
    ],
  },
  {
    title: 'History',
    items: [
      { path: '/history', label: 'Scan History', icon: FiClock },
      { path: '/quarantine', label: 'Quarantine', icon: FiShield },
      { path: '/scheduled-scans', label: 'Scheduled Scans', icon: FiCalendar },
    ],
  },
  {
    title: 'Management',
    items: [
      { path: '/reports', label: 'Reports', icon: FiFileText },
      { path: '/export', label: 'Export Data', icon: FiDownload },
      { path: '/webhooks', label: 'Webhooks', icon: FiLink },
      { path: '/backup', label: 'Backup & Restore', icon: FiDatabase },
      { path: '/api-keys', label: 'API Keys', icon: FiLock },
    ],
  },
  {
    title: 'System',
    items: [
      { path: '/users', label: 'User Management', icon: FiUsers },
      { path: '/system-health', label: 'System Health', icon: FiMonitor },
      { path: '/security-logs', label: 'Security Logs', icon: FiActivity },
      { path: '/settings', label: 'Settings', icon: FiSettings },
    ],
  },
];

export default function Sidebar({ collapsed, onToggle, mobileOpen = false, onMobileClose = () => {} }) {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navRef = useRef(null);

  useEffect(() => {
    if (!navRef.current) return;
    const active = navRef.current.querySelector('[aria-current="page"]');
    if (active) {
      active.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }, [location.pathname]);

  const handleLogout = () => {
    logout();
    toast.success('Logged out successfully');
  };

  const getInitials = () => {
    const name = user?.username || user?.name || 'U';
    return name.charAt(0).toUpperCase();
  };

  return (
    <>
      {mobileOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden transition-opacity" onClick={onMobileClose} />
      )}
      <aside
        className={`fixed top-0 left-0 z-50 h-full bg-dark-900/95 backdrop-blur-md border-r border-dark-700/50 flex flex-col transition-all duration-300 ease-in-out ${
          collapsed ? 'w-[68px]' : 'w-64'
        } ${mobileOpen ? 'translate-x-0 shadow-2xl shadow-black/40' : '-translate-x-full lg:translate-x-0'}`}
      >
        {/* Header */}
        <div className={`flex items-center h-16 px-4 border-b border-dark-700/50 shrink-0 ${collapsed ? 'justify-center' : 'justify-between'}`}>
          {!collapsed && (
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                <FiShield className="w-4 h-4 text-white" />
              </div>
              <div>
                <span className="font-bold text-dark-100 text-sm tracking-tight">MFDS</span>
                <span className="block text-[10px] text-dark-500 -mt-0.5">Security Scanner</span>
              </div>
            </div>
          )}
          {collapsed && (
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <FiShield className="w-4 h-4 text-white" />
            </div>
          )}
          <div className="flex items-center gap-1">
            {mobileOpen && (
              <button onClick={onMobileClose} className="lg:hidden p-1.5 rounded-md text-dark-400 hover:text-dark-100 hover:bg-dark-800 transition-colors">
                <FiX className="w-4 h-4" />
              </button>
            )}
            <button
              onClick={onToggle}
              className="hidden lg:flex p-1.5 rounded-md text-dark-400 hover:text-dark-100 hover:bg-dark-800 transition-colors"
              title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {collapsed ? <FiChevronRight className="w-4 h-4" /> : <FiChevronLeft className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Navigation */}
        <nav ref={navRef} className={`flex-1 overflow-y-auto py-3 ${collapsed ? 'px-2' : 'px-3'} space-y-1 scrollbar-thin scrollbar-thumb-dark-700 scrollbar-track-transparent`}>
          {NAV_SECTIONS.map((section, si) => (
            <div key={si}>
              {section.title && !collapsed && (
                <p className="px-3 pt-4 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-dark-500">
                  {section.title}
                </p>
              )}
              {section.title && collapsed && si > 0 && (
                <div className="mx-2 my-2 border-t border-dark-700/50" />
              )}
              {section.items.map(({ path, label, icon: Icon }) => {
                const isActive = location.pathname === path || (path !== '/' && location.pathname.startsWith(path));
                return (
                  <NavLink
                    key={path}
                    to={path}
                    title={collapsed ? label : undefined}
                    onClick={onMobileClose}
                    className={`group flex items-center gap-3 rounded-lg text-sm font-medium transition-all duration-200 relative ${
                      collapsed ? 'justify-center px-2 py-2.5' : 'px-3 py-2.5'
                    } ${
                      isActive
                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-[0_0_12px_rgba(6,182,212,0.08)]'
                        : 'text-dark-400 hover:text-dark-100 hover:bg-dark-800/60 border border-transparent'
                    }`}
                  >
                    {isActive && (
                      <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 bg-cyan-400 rounded-r-full" />
                    )}
                    <Icon className={`w-[18px] h-[18px] shrink-0 transition-colors ${isActive ? 'text-cyan-400' : 'text-dark-400 group-hover:text-dark-200'}`} />
                    {!collapsed && <span className="truncate">{label}</span>}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>

        {/* User Profile */}
        <div className={`border-t border-dark-700/50 p-3 shrink-0 ${collapsed ? 'px-2' : ''}`}>
          {!collapsed ? (
            <div className="flex items-center gap-3 p-2 rounded-lg bg-dark-800/50 border border-dark-700/50">
              <div className="w-9 h-9 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shrink-0 shadow-md shadow-cyan-500/20">
                <span className="text-sm font-bold text-white">{getInitials()}</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-dark-100 truncate">
                  {user?.username || user?.name || 'User'}
                </p>
                <p className="text-[11px] text-dark-500 truncate">
                  {user?.role || 'User'}
                </p>
              </div>
              <button
                onClick={handleLogout}
                className="p-1.5 rounded-md text-dark-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                title="Logout"
              >
                <FiLogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-2">
              <div className="w-9 h-9 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-md shadow-cyan-500/20">
                <span className="text-sm font-bold text-white">{getInitials()}</span>
              </div>
              <button
                onClick={handleLogout}
                className="p-1.5 rounded-md text-dark-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                title="Logout"
              >
                <FiLogOut className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
