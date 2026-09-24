import { useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Navbar from './Navbar';
import { GalaxyBackground } from './GalaxyBackground';
import './GalaxyBackground/galaxy.css';

const pageTitles = {
  '/dashboard': 'Security Dashboard',
  '/antivirus': 'Antivirus Protection',
  '/scanner': 'File Scanner',
  '/sandbox': 'File Sandbox',
  '/hash-lookup': 'Hash Reputation Lookup',
  '/threat-intel': 'Threat Intelligence',
  '/network-share': 'Network Share Scanner',
  '/email-security': 'Email Security Dashboard',
  '/email-monitor': 'Live Email Monitor',
  '/email-settings': 'Email Settings',
  '/email-quarantine': 'Email Quarantine',
  '/firewall': 'Firewall',
  '/history': 'Scan History',
  '/quarantine': 'Quarantine',
  '/usb-scanner': 'USB Scanner',
  '/folder-monitor': 'Folder Monitor',
  '/scheduled-scans': 'Scheduled Scans',
  '/reports': 'Reports',
  '/export': 'Export Data',
  '/webhooks': 'Webhook Management',
  '/backup': 'Backup & Restore',
  '/api-keys': 'API Key Management',
  '/system-health': 'System Health',
  '/security-logs': 'Security Logs',
  '/settings': 'Settings',
  '/profile': 'Profile',
};

export default function Layout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  const pathKey = Object.keys(pageTitles).find((key) =>
    location.pathname.startsWith(key)
  );
  const title = pageTitles[pathKey] || 'Advanced Malicious File Detection System';

  return (
    <div className="min-h-screen bg-dark-950 relative">
      <GalaxyBackground />
      <div className="relative z-10">
        <Sidebar collapsed={sidebarCollapsed} mobileOpen={mobileOpen} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} onMobileClose={() => setMobileOpen(false)} />
        <div className={`transition-all duration-300 ${sidebarCollapsed ? 'lg:ml-[68px]' : 'lg:ml-64'}`}>
          <Navbar title={title} onMenuClick={() => setMobileOpen(!mobileOpen)} />
          <main className="p-6 pt-20">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}
