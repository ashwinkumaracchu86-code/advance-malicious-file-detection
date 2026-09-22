import axios from 'axios';
import { API_BASE } from '../config';

const LOGIN_PATH = `${import.meta.env.BASE_URL || '/'}login`;

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      const refreshToken = localStorage.getItem('refreshToken');

      if (!refreshToken) {
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
        window.location.href = LOGIN_PATH;
        return Promise.reject(error);
      }

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            originalRequest.headers.Authorization = `Bearer ${token}`;
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const res = await axios.post(`${API_BASE}/auth/refresh`, {
          refresh_token: refreshToken,
        });

        const { access_token, refresh_token: newRefreshToken } = res.data;
        localStorage.setItem('token', access_token);
        if (newRefreshToken) {
          localStorage.setItem('refreshToken', newRefreshToken);
        }

        processQueue(null, access_token);
        originalRequest.headers.Authorization = `Bearer ${access_token}`;
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
        window.location.href = LOGIN_PATH;
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export const authAPI = {
  login: (username, password) => api.post('/auth/login', { username, password }),
  register: (data) => api.post('/auth/register', data),
  getMe: () => api.get('/auth/me'),
  refresh: (refreshToken) =>
    axios.post(`${API_BASE}/auth/refresh`, { refresh_token: refreshToken }),
};

export const filesAPI = {
  upload: (formData, onProgress) =>
    api.post('/files/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: onProgress,
    }),
  list: (params) => api.get('/files', { params }),
  get: (id) => api.get(`/files/${id}`),
};

export const scansAPI = {
  scan: (fileId) => api.post(`/scan/${fileId}`),
  get: (scanId) => api.get(`/scan/${scanId}`),
  list: (params) => api.get('/scans', { params }),
};

export const dashboardAPI = {
  getStats: () => api.get('/dashboard/statistics'),
};

export const quarantineAPI = {
  quarantine: (fileId) => api.post(`/quarantine/${fileId}`),
  list: (params) => api.get('/quarantine', { params }),
  restore: (id) => api.post(`/quarantine/${id}/restore`),
  delete: (id) => api.delete(`/quarantine/${id}`),
};

export const reportsAPI = {
  getPDF: (scanId) =>
    api.get(`/reports/${scanId}`, { responseType: 'blob' }),
};

export const logsAPI = {
  list: (params) => api.get('/logs', { params }),
};

export const antivirusAPI = {
  getStatus: () => api.get('/antivirus/status'),
  getStats: () => api.get('/antivirus/stats'),
  scanShared: (formData, onProgress) =>
    api.post('/antivirus/scan-shared', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: onProgress,
    }),
  scanFolder: (formData) =>
    api.post('/antivirus/scan-folder', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  enableProtection: () => api.post('/antivirus/protection/enable'),
  disableProtection: () => api.post('/antivirus/protection/disable'),
  enableAutoScan: () => api.post('/antivirus/auto-scan/enable'),
  disableAutoScan: () => api.post('/antivirus/auto-scan/disable'),
  enableAutoQuarantine: () => api.post('/antivirus/auto-quarantine/enable'),
  disableAutoQuarantine: () => api.post('/antivirus/auto-quarantine/disable'),
  getNotifications: (params) => api.get('/antivirus/notifications', { params }),
  markNotificationsRead: () => api.post('/antivirus/notifications/mark-read'),
  clearNotifications: () => api.delete('/antivirus/notifications'),
  getScanHistory: (params) => api.get('/antivirus/scan-history', { params }),
  addMonitoredPath: (path) => api.post(`/antivirus/monitored-paths?path=${encodeURIComponent(path)}`),
  removeMonitoredPath: (path) => api.delete(`/antivirus/monitored-paths?path=${encodeURIComponent(path)}`),
  getFirewallStatus: () => api.get('/antivirus/firewall-status'),
  enableFirewallIntegration: () => api.post('/antivirus/firewall/enable'),
  disableFirewallIntegration: () => api.post('/antivirus/firewall/disable'),
  blockThreatIp: (ip, reason) => api.post(`/antivirus/firewall/block-ip?ip=${encodeURIComponent(ip)}&reason=${encodeURIComponent(reason || 'Manual block')}`),
  unblockThreatIp: (ip) => api.post(`/antivirus/firewall/unblock-ip?ip=${encodeURIComponent(ip)}`),
  getThreatLog: (params) => api.get('/antivirus/firewall/threat-log', { params }),
};

export const folderMonitorAPI = {
  getStatus: () => api.get('/antivirus/status'),
  startMonitoring: (path) => api.post(`/antivirus/monitored-paths?path=${encodeURIComponent(path)}`),
  stopMonitoring: (path) => api.delete(`/antivirus/monitored-paths?path=${encodeURIComponent(path)}`),
  getNotifications: () => api.get('/antivirus/notifications'),
  getScanHistory: () => api.get('/antivirus/scan-history'),
};

export const realtimeAPI = {
  startAutoScan: () => api.post('/realtime/auto-scan/start'),
  stopAutoScan: () => api.post('/realtime/auto-scan/stop'),
  getStatus: () => api.get('/realtime/status'),
};

export const hashLookupAPI = {
  lookup: (data) => api.post('/hash-lookup/lookup', data),
  getRecent: (params) => api.get('/hash-lookup/recent', { params }),
};

export const threatIntelAPI = {
  getDashboard: (days) => api.get('/threat-intel/dashboard', { params: { days } }),
  getTrends: (days) => api.get('/threat-intel/trends', { params: { days } }),
  getStats: () => api.get('/threat-intel/stats'),
};

export const networkShareAPI = {
  listShares: () => api.get('/network-share/shares'),
  addShare: (data) => api.post('/network-share/shares', data),
  removeShare: (shareId) => api.delete(`/network-share/shares/${shareId}`),
  scanPath: (data) => api.post('/network-share/scan', data),
  browsePath: (path) => api.get('/network-share/browse', { params: { path } }),
};

export const usbScannerAPI = {
  getDrives: () => api.get('/usb-scanner/drives'),
  scanDrive: (drivePath) => api.post('/usb-scanner/scan', null, { params: { drive_path: drivePath } }),
  getFiles: (drivePath) => api.get('/usb-scanner/files', { params: { drive_path: drivePath } }),
};

export const featuresAPI = {
  getSystemHealth: () => api.get('/health/public'),
  getWebhookStatus: () => api.get('/webhooks/status'),
  saveWebhookConfig: (data) => api.post('/webhooks/save', null, { params: data }),
  testWebhooks: () => api.post('/webhooks/test'),
  getScheduledScans: () => api.get('/scheduler/jobs'),
  getCommonPaths: () => api.get('/scheduler/common-paths'),
  addScheduledScan: (params) => api.post('/scheduler/add', null, { params }),
  removeScheduledScan: (jobId) => api.delete(`/scheduler/${jobId}`),
  toggleScheduledScan: (jobId, enabled) => api.post(`/scheduler/${jobId}/toggle`, null, { params: { enabled } }),
  exportScansCSV: () => api.get('/export/scans/csv', { responseType: 'blob' }),
  exportScansJSON: () => api.get('/export/scans/json', { responseType: 'blob' }),
  exportScansExcel: () => api.get('/export/scans/excel', { responseType: 'blob' }),
  exportThreatsCSV: () => api.get('/export/threats/csv', { responseType: 'blob' }),
  exportThreatsExcel: () => api.get('/export/threats/excel', { responseType: 'blob' }),
  exportQuarantineCSV: () => api.get('/export/quarantine/csv', { responseType: 'blob' }),
  exportLogsCSV: () => api.get('/export/logs/csv', { responseType: 'blob' }),
};

export const emailSecurityAPI = {
  scan: (formData, onProgress) =>
    api.post('/email-security/scan', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: onProgress,
    }),
  listEmails: (params) => api.get('/email-security/emails', { params }),
  getEmail: (id) => api.get(`/email-security/emails/${id}`),
  getStats: (days) => api.get('/email-security/stats', { params: { days } }),
  getAlerts: (params) => api.get('/email-security/alerts', { params }),
  markAlertRead: (id) => api.post(`/email-security/alerts/${id}/read`),
  markAllAlertsRead: () => api.post('/email-security/alerts/read-all'),
  getQuarantine: (params) => api.get('/email-security/quarantine', { params }),
  quarantineAction: (id, data) => api.post(`/email-security/quarantine/${id}/action`, data),
  getEvents: (params) => api.get('/email-security/events', { params }),
  getMonitoringConfig: () => api.get('/email-security/monitoring/config'),
  saveMonitoringConfig: (data) => api.post('/email-security/monitoring/config', data),
  startMonitoring: () => api.post('/email-security/monitoring/start'),
  stopMonitoring: () => api.post('/email-security/monitoring/stop'),
  getMonitoringStatus: () => api.get('/email-security/monitoring/status'),
};

export const settingsAPI = {
  getSettings: () => api.get('/settings'),
  getSetting: (key) => api.get(`/settings/${key}`),
  updateSetting: (key, value) => api.put(`/settings/${key}`, { value }),
  updateSettings: (settings) => api.put('/settings', settings),
  getBackups: () => api.get('/settings/backups'),
  createBackup: () => api.post('/settings/backup'),
  restoreBackup: (id) => api.post(`/settings/restore/${id}`),
  deleteBackup: (id) => api.delete(`/settings/backup/${id}`),
  downloadBackup: (id) => api.get(`/settings/backup/${id}/download`, { responseType: 'blob' }),
  getDbInfo: () => api.get('/settings/db-info'),
  getSystemInfo: () => api.get('/settings/system/info'),
  getApiKeys: () => api.get('/settings/api-keys'),
  createApiKey: (data) => api.post('/settings/api-keys', data),
  deleteApiKey: (id) => api.delete(`/settings/api-keys/${id}`),
};

export const firewallAPI = {
  getStatus: () => api.get('/firewall/status'),
  enable: () => api.post('/firewall/enable'),
  disable: () => api.post('/firewall/disable'),
  getZones: () => api.get('/firewall/zones'),
  createZone: (data) => api.post('/firewall/zones', data),
  updateZone: (id, data) => api.put(`/firewall/zones/${id}`, data),
  deleteZone: (id) => api.delete(`/firewall/zones/${id}`),
  toggleZone: (id) => api.post(`/firewall/zones/${id}/toggle`),
  getRules: () => api.get('/firewall/rules'),
  createRule: (data) => api.post('/firewall/rules', data),
  updateRule: (id, data) => api.put(`/firewall/rules/${id}`, data),
  deleteRule: (id) => api.delete(`/firewall/rules/${id}`),
  toggleRule: (id) => api.post(`/firewall/rules/${id}/toggle`),
  getServices: () => api.get('/firewall/services'),
  createService: (data) => api.post('/firewall/services', data),
  updateService: (id, data) => api.put(`/firewall/services/${id}`, data),
  deleteService: (id) => api.delete(`/firewall/services/${id}`),
  getConnections: () => api.get('/firewall/connections'),
  getBlockedIps: () => api.get('/firewall/blocked-ips'),
  unblockIp: (ip) => api.post(`/firewall/unblock-ip?ip=${encodeURIComponent(ip)}`),
  getLogs: (params) => api.get('/firewall/logs', { params }),
  clearLogs: () => api.post('/firewall/logs/clear'),
  getTrafficMatrix: () => api.get('/firewall/traffic-matrix'),
  getZoneConnections: (zoneName) => api.get(`/firewall/zone-connections/${encodeURIComponent(zoneName)}`),
  checkConnection: (remoteIp, remotePort, localIp, localPort, protocol) =>
    api.get('/firewall/check', { params: { remote_ip: remoteIp, remote_port: remotePort, local_ip: localIp, local_port: localPort, protocol } }),
};

export const sandboxAPI = {
  getJobs: () => api.get('/sandbox/jobs'),
  submitFile: (formData) => api.post('/sandbox/submit', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
  getJob: (id) => api.get(`/sandbox/jobs/${id}`),
  deleteJob: (id) => api.delete(`/sandbox/jobs/${id}`),
};

export const adminUsersAPI = {
  list: (params) => api.get('/admin/users', { params }),
  get: (id) => api.get(`/admin/users/${id}`),
  create: (data) => api.post('/admin/users', data),
  update: (id, data) => api.put(`/admin/users/${id}`, data),
  delete: (id) => api.delete(`/admin/users/${id}`),
};

export default api;
