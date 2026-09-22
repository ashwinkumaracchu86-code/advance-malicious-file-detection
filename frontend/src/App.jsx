import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import Layout from './components/Layout';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import ScannerPage from './pages/ScannerPage';
import ScanHistoryPage from './pages/ScanHistoryPage';
import ScanDetailPage from './pages/ScanDetailPage';
import QuarantinePage from './pages/QuarantinePage';
import USBScannerPage from './pages/USBScannerPage';
import FolderMonitorPage from './pages/FolderMonitorPage';
import AntivirusPage from './pages/AntivirusPage';
import ReportsPage from './pages/ReportsPage';
import SecurityLogsPage from './pages/SecurityLogsPage';
import SettingsPage from './pages/SettingsPage';
import ProfilePage from './pages/ProfilePage';
import SystemHealthPage from './pages/SystemHealthPage';
import ScheduledScansPage from './pages/ScheduledScansPage';
import ExportPage from './pages/ExportPage';
import HashLookupPage from './pages/HashLookupPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import NetworkSharePage from './pages/NetworkSharePage';
import EmailSecurityDashboard from './pages/EmailSecurityDashboard';
import EmailLiveMonitorPage from './pages/EmailLiveMonitorPage';
import EmailSettingsPage from './pages/EmailSettingsPage';
import EmailDetailPage from './pages/EmailDetailPage';
import EmailQuarantinePage from './pages/EmailQuarantinePage';
import UserManagementPage from './pages/UserManagementPage';
import WebhooksPage from './pages/WebhooksPage';
import BackupPage from './pages/BackupPage';
import ApiKeysPage from './pages/ApiKeysPage';
import SandboxPage from './pages/SandboxPage';
import FirewallPage from './pages/FirewallPage';

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-dark-950 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500"></div>
      </div>
    );
  }
  return user ? children : <Navigate to="/login" replace />;
}

function AdminRoute({ children }) {
  const { user, loading, isAdmin } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-dark-950 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500"></div>
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  if (!isAdmin) return <Navigate to="/dashboard" replace />;
  return children;
}

function UserRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-dark-950 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500"></div>
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function PublicRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  return user ? <Navigate to="/dashboard" replace /> : children;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />
      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="antivirus" element={<AntivirusPage />} />
        <Route path="scanner" element={<ScannerPage />} />
        <Route path="firewall" element={<FirewallPage />} />
        <Route path="sandbox" element={<SandboxPage />} />
        <Route path="history" element={<ScanHistoryPage />} />
        <Route path="scan/:id" element={<ScanDetailPage />} />
        <Route path="quarantine" element={<QuarantinePage />} />
        <Route path="usb-scanner" element={<USBScannerPage />} />
        <Route path="folder-monitor" element={<FolderMonitorPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="security-logs" element={<SecurityLogsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="profile" element={<UserRoute><ProfilePage /></UserRoute>} />
        <Route path="system-health" element={<SystemHealthPage />} />
        <Route path="scheduled-scans" element={<ScheduledScansPage />} />
        <Route path="export" element={<ExportPage />} />
        <Route path="webhooks" element={<WebhooksPage />} />
        <Route path="backup" element={<BackupPage />} />
        <Route path="api-keys" element={<ApiKeysPage />} />
        <Route path="hash-lookup" element={<HashLookupPage />} />
        <Route path="threat-intel" element={<ThreatIntelPage />} />
        <Route path="network-share" element={<NetworkSharePage />} />
        <Route path="email-security" element={<EmailSecurityDashboard />} />
        <Route path="email-monitor" element={<EmailLiveMonitorPage />} />
        <Route path="email-settings" element={<EmailSettingsPage />} />
        <Route path="email-security/email/:id" element={<EmailDetailPage />} />
        <Route path="email-quarantine" element={<EmailQuarantinePage />} />
        <Route path="users" element={<UserManagementPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Router>
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: '#1e293b',
              color: '#f1f5f9',
              border: '1px solid #334155',
            },
            success: {
              iconTheme: { primary: '#22c55e', secondary: '#f1f5f9' },
            },
            error: {
              iconTheme: { primary: '#ef4444', secondary: '#f1f5f9' },
            },
          }}
        />
        <AppRoutes />
      </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}
