import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import {
  FiArrowLeft,
  FiMail,
  FiShield,
  FiAlertTriangle,
  FiCheckCircle,
  FiLink,
  FiHash,
  FiLock,
  FiDownload,
  FiEye,
  FiClock,
  FiUser,
  FiGlobe,
  FiFile,
} from 'react-icons/fi';
import { emailSecurityAPI } from '../services/api';

function RiskBadge({ score }) {
  const num = typeof score === 'number' ? score : parseFloat(score) || 0;

  let colors, label;
  if (num <= 30) {
    colors = 'bg-green-500/15 text-green-400 border border-green-500/30';
    label = 'LOW';
  } else if (num <= 60) {
    colors = 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30';
    label = 'MEDIUM';
  } else if (num <= 80) {
    colors = 'bg-orange-500/15 text-orange-400 border border-orange-500/30';
    label = 'HIGH';
  } else {
    colors = 'bg-red-500/15 text-red-400 border border-red-500/30';
    label = 'CRITICAL';
  }

  return (
    <span className={`px-2.5 py-1 rounded text-xs font-semibold ${colors}`}>
      {num.toFixed(1)} — {label}
    </span>
  );
}

function ClassificationBadge({ classification }) {
  const c = (classification || 'unknown').toLowerCase();

  const map = {
    safe: 'bg-green-500/15 text-green-400 border border-green-500/30',
    clean: 'bg-green-500/15 text-green-400 border border-green-500/30',
    low: 'bg-green-500/15 text-green-400 border border-green-500/30',
    suspicious: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
    spam: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
    medium: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
    phishing: 'bg-red-500/15 text-red-400 border border-red-500/30',
    malware: 'bg-red-500/15 text-red-400 border border-red-500/30',
    malicious: 'bg-red-500/15 text-red-400 border border-red-500/30',
    high: 'bg-red-500/15 text-red-400 border border-red-500/30',
    critical: 'bg-red-700/20 text-red-300 border border-red-500/40',
  };

  return (
    <span className={`px-2.5 py-1 rounded text-xs font-semibold ${map[c] || 'bg-dark-700 text-dark-400 border border-dark-600'}`}>
      {(classification || 'UNKNOWN').toUpperCase()}
    </span>
  );
}

function SectionCard({ icon: Icon, title, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="bg-dark-800 border border-dark-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-dark-700/30 transition-colors"
      >
        <div className="flex items-center gap-2.5">
          <Icon className="w-4 h-4 text-cyan-400" />
          <h2 className="text-dark-100 font-semibold text-sm">{title}</h2>
        </div>
        <svg
          className={`w-4 h-4 text-dark-400 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && <div className="px-5 pb-5 border-t border-dark-700/50 pt-4">{children}</div>}
    </div>
  );
}

function InfoRow({ label, value, mono = false }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-dark-700/50 last:border-0">
      <span className="text-xs text-dark-400">{label}</span>
      <span className={`text-sm text-dark-100 text-right max-w-[65%] truncate ${mono ? 'font-mono text-xs' : ''}`}>
        {value || '—'}
      </span>
    </div>
  );
}

function AuthStatusRow({ label, passed }) {
  const isPass = passed === true || (typeof passed === 'string' && passed.toUpperCase() === 'PASS');

  return (
    <div className="flex items-center justify-between py-2.5 border-b border-dark-700/50 last:border-0">
      <span className="text-sm text-dark-300">{label}</span>
      <div className="flex items-center gap-2">
        {isPass ? (
          <>
            <FiCheckCircle className="w-4 h-4 text-green-400" />
            <span className="text-xs font-semibold text-green-400 bg-green-500/10 border border-green-500/30 px-2 py-0.5 rounded">
              PASS
            </span>
          </>
        ) : (
          <>
            <FiAlertTriangle className="w-4 h-4 text-red-400" />
            <span className="text-xs font-semibold text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded">
              FAIL
            </span>
          </>
        )}
      </div>
    </div>
  );
}

function SeverityIcon({ severity }) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical' || s === 'high') {
    return <FiAlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />;
  }
  if (s === 'medium' || s === 'warning') {
    return <FiAlertTriangle className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0" />;
  }
  return <FiCheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />;
}

function SeverityBadge({ severity }) {
  const s = (severity || 'info').toLowerCase();
  const map = {
    critical: 'bg-red-700/20 text-red-300 border border-red-500/40',
    high: 'bg-red-500/15 text-red-400 border border-red-500/30',
    medium: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
    warning: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
    low: 'bg-green-500/15 text-green-400 border border-green-500/30',
    info: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${map[s] || 'bg-dark-700 text-dark-400 border border-dark-600'}`}>
      {(severity || 'info').toUpperCase()}
    </span>
  );
}

function getRiskRowColor(score) {
  const num = typeof score === 'number' ? score : parseFloat(score) || 0;
  if (num >= 70) return 'bg-red-500/5 border-l-2 border-l-red-500';
  if (num >= 40) return 'bg-yellow-500/5 border-l-2 border-l-yellow-500';
  return 'bg-transparent border-l-2 border-l-green-500';
}

function formatDate(dateStr) {
  if (!dateStr) return '—';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return dateStr;
  }
}

function formatSize(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}

function TruncateHash({ hash }) {
  if (!hash) return <span className="text-dark-400">—</span>;
  const display = hash.length > 24 ? `${hash.substring(0, 12)}...${hash.substring(hash.length - 12)}` : hash;
  return (
    <span className="font-mono text-xs text-dark-300" title={hash}>
      {display}
    </span>
  );
}

export default function EmailDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [email, setEmail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionLoading, setActionLoading] = useState('');
  const [bodyExpanded, setBodyExpanded] = useState(false);

  const fetchEmail = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await emailSecurityAPI.getEmail(id);
      setEmail(res?.data || res);
    } catch (err) {
      console.error('Failed to fetch email:', err);
      setError('Failed to load email details. Please try again.');
      toast.error('Failed to load email');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEmail();
  }, [id]);

  const handleQuarantine = async () => {
    try {
      setActionLoading('quarantine');
      await emailSecurityAPI.quarantineAction(id, { action: 'quarantine' });
      toast.success('Email quarantined successfully');
      setEmail((prev) => ({ ...prev, is_quarantined: true, quarantine_status: 'quarantined' }));
    } catch (err) {
      console.error('Quarantine failed:', err);
      toast.error('Failed to quarantine email');
    } finally {
      setActionLoading('');
    }
  };

  const handleRelease = async () => {
    try {
      setActionLoading('release');
      await emailSecurityAPI.quarantineAction(id, { action: 'release' });
      toast.success('Email released successfully');
      setEmail((prev) => ({ ...prev, is_quarantined: false, quarantine_status: 'released' }));
    } catch (err) {
      console.error('Release failed:', err);
      toast.error('Failed to release email');
    } finally {
      setActionLoading('');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-dark-900 flex items-center justify-center">
        <div className="text-center">
          <div className="w-10 h-10 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-dark-400 text-sm">Loading email details...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-dark-900 p-6">
        <div className="max-w-4xl mx-auto">
          <button
            onClick={() => navigate(-1)}
            className="flex items-center gap-2 text-dark-400 hover:text-dark-100 transition-colors mb-6"
          >
            <FiArrowLeft className="w-4 h-4" />
            <span className="text-sm">Back</span>
          </button>
          <div className="bg-dark-800 border border-red-500/30 rounded-lg p-8 text-center">
            <FiAlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
            <p className="text-red-400 font-medium mb-2">{error}</p>
            <button
              onClick={fetchEmail}
              className="mt-3 px-4 py-2 bg-dark-700 border border-dark-600 rounded-lg text-dark-100 text-sm hover:bg-dark-600 transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!email) {
    return (
      <div className="min-h-screen bg-dark-900 p-6">
        <div className="max-w-4xl mx-auto">
          <button
            onClick={() => navigate(-1)}
            className="flex items-center gap-2 text-dark-400 hover:text-dark-100 transition-colors mb-6"
          >
            <FiArrowLeft className="w-4 h-4" />
            <span className="text-sm">Back</span>
          </button>
          <div className="bg-dark-800 border border-dark-700 rounded-lg p-8 text-center">
            <FiMail className="w-10 h-10 text-dark-500 mx-auto mb-3" />
            <p className="text-dark-400">Email not found.</p>
          </div>
        </div>
      </div>
    );
  }

  const riskScore = email.risk_score ?? email.risk ?? email.score ?? 0;
  const classification = email.classification ?? email.risk_level ?? email.label ?? 'unknown';
  const isQuarantined = email.is_quarantined ?? email.quarantined ?? (email.quarantine_status === 'quarantined');
  const quarantineStatus = email.quarantine_status ?? (isQuarantined ? 'quarantined' : 'none');

  const sender = email.sender ?? email.from ?? email.sender_address ?? '';
  const recipient = email.recipient ?? email.to ?? email.recipient_address ?? '';
  const subject = email.subject ?? email.title ?? 'No Subject';
  const date = email.date ?? email.received_at ?? email.timestamp ?? email.created_at ?? '';

  const authentication = email.authentication ?? email.auth_results ?? email.authentication_results ?? {};
  const spf = authentication.spf ?? authentication.spf_result;
  const dkim = authentication.dkim ?? authentication.dkim_result;
  const dmarc = authentication.dmarc ?? authentication.dmarc_result;

  const senderAnalysis = email.sender_analysis ?? email.sender_info ?? {};
  const senderDomain = senderAnalysis.domain ?? email.sender_domain ?? email.domain ?? '';
  const displayName = senderAnalysis.display_name ?? senderAnalysis.displayname ?? email.display_name ?? '';
  const spoofing = senderAnalysis.spoofing ?? senderAnalysis.spoofing_detected ?? email.spoofing_detected ?? null;
  const returnPath = senderAnalysis.return_path ?? email.return_path ?? email.return_path_mismatch ?? null;

  const urls = email.urls ?? email.links ?? email.extracted_urls ?? email.url_analysis ?? [];
  const attachments = email.attachments ?? email.attachment_analysis ?? email.attachment_details ?? [];
  const reasons = email.reasons ?? email.detection_reasons ?? email.security_indicators ?? email.indicators ?? [];
  const body = email.body ?? email.body_text ?? email.body_preview ?? email.text_body ?? '';

  const isQuarantineActionDisabled = isQuarantined || actionLoading === 'quarantine';
  const isReleaseActionDisabled = !isQuarantined || actionLoading === 'release';

  return (
    <div className="min-h-screen bg-dark-900 p-6 space-y-6">
      <div className="max-w-5xl mx-auto">
        {/* Top navigation */}
        <div className="flex items-center justify-between mb-2">
          <button
            onClick={() => navigate(-1)}
            className="flex items-center gap-2 text-dark-400 hover:text-dark-100 transition-colors"
          >
            <FiArrowLeft className="w-4 h-4" />
            <span className="text-sm">Back to Email List</span>
          </button>
          <div className="flex items-center gap-2 text-dark-400 text-xs">
            <FiClock className="w-3.5 h-3.5" />
            <span>Scanned {formatDate(date)}</span>
          </div>
        </div>

        {/* Section 1: Email Header */}
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-5">
          <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-3">
                <FiMail className="w-5 h-5 text-cyan-400 flex-shrink-0" />
                <h1 className="text-dark-100 text-lg font-bold truncate">{subject}</h1>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <FiUser className="w-3.5 h-3.5 text-dark-400 flex-shrink-0" />
                  <span className="text-xs text-dark-400 w-20 flex-shrink-0">From:</span>
                  <span className="text-sm text-dark-100 truncate">{sender || '—'}</span>
                </div>
                <div className="flex items-center gap-2">
                  <FiMail className="w-3.5 h-3.5 text-dark-400 flex-shrink-0" />
                  <span className="text-xs text-dark-400 w-20 flex-shrink-0">To:</span>
                  <span className="text-sm text-dark-100 truncate">{recipient || '—'}</span>
                </div>
                <div className="flex items-center gap-2">
                  <FiClock className="w-3.5 h-3.5 text-dark-400 flex-shrink-0" />
                  <span className="text-xs text-dark-400 w-20 flex-shrink-0">Date:</span>
                  <span className="text-sm text-dark-100">{formatDate(date)}</span>
                </div>
              </div>
            </div>
            <div className="flex flex-row md:flex-col items-start md:items-end gap-2 flex-shrink-0">
              <RiskBadge score={riskScore} />
              <ClassificationBadge classification={classification} />
              <span
                className={`px-2.5 py-1 rounded text-xs font-semibold ${
                  isQuarantined
                    ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30'
                    : 'bg-dark-700 text-dark-400 border border-dark-600'
                }`}
              >
                {quarantineStatus === 'quarantined' ? 'QUARANTINED' : quarantineStatus === 'released' ? 'RELEASED' : 'NOT QUARANTINED'}
              </span>
            </div>
          </div>
        </div>

        {/* Section 2: Authentication Results */}
        <SectionCard icon={FiShield} title="Authentication Results">
          <div className="bg-dark-900/50 rounded-lg border border-dark-700/50 p-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center">
                <div className={`inline-flex items-center justify-center w-16 h-16 rounded-full mb-2 ${
                  spf === true || (typeof spf === 'string' && spf.toUpperCase() === 'PASS')
                    ? 'bg-green-500/10 border border-green-500/30'
                    : 'bg-red-500/10 border border-red-500/30'
                }`}>
                  {spf === true || (typeof spf === 'string' && spf.toUpperCase() === 'PASS') ? (
                    <FiCheckCircle className="w-8 h-8 text-green-400" />
                  ) : (
                    <FiAlertTriangle className="w-8 h-8 text-red-400" />
                  )}
                </div>
                <p className="text-dark-100 text-sm font-semibold">SPF</p>
                <p className={`text-xs mt-0.5 ${
                  spf === true || (typeof spf === 'string' && spf.toUpperCase() === 'PASS')
                    ? 'text-green-400'
                    : 'text-red-400'
                }`}>
                  {spf === true || (typeof spf === 'string' && spf.toUpperCase() === 'PASS') ? 'PASS' : 'FAIL'}
                </p>
              </div>
              <div className="text-center">
                <div className={`inline-flex items-center justify-center w-16 h-16 rounded-full mb-2 ${
                  dkim === true || (typeof dkim === 'string' && dkim.toUpperCase() === 'PASS')
                    ? 'bg-green-500/10 border border-green-500/30'
                    : 'bg-red-500/10 border border-red-500/30'
                }`}>
                  {dkim === true || (typeof dkim === 'string' && dkim.toUpperCase() === 'PASS') ? (
                    <FiCheckCircle className="w-8 h-8 text-green-400" />
                  ) : (
                    <FiAlertTriangle className="w-8 h-8 text-red-400" />
                  )}
                </div>
                <p className="text-dark-100 text-sm font-semibold">DKIM</p>
                <p className={`text-xs mt-0.5 ${
                  dkim === true || (typeof dkim === 'string' && dkim.toUpperCase() === 'PASS')
                    ? 'text-green-400'
                    : 'text-red-400'
                }`}>
                  {dkim === true || (typeof dkim === 'string' && dkim.toUpperCase() === 'PASS') ? 'PASS' : 'FAIL'}
                </p>
              </div>
              <div className="text-center">
                <div className={`inline-flex items-center justify-center w-16 h-16 rounded-full mb-2 ${
                  dmarc === true || (typeof dmarc === 'string' && dmarc.toUpperCase() === 'PASS')
                    ? 'bg-green-500/10 border border-green-500/30'
                    : 'bg-red-500/10 border border-red-500/30'
                }`}>
                  {dmarc === true || (typeof dmarc === 'string' && dmarc.toUpperCase() === 'PASS') ? (
                    <FiCheckCircle className="w-8 h-8 text-green-400" />
                  ) : (
                    <FiAlertTriangle className="w-8 h-8 text-red-400" />
                  )}
                </div>
                <p className="text-dark-100 text-sm font-semibold">DMARC</p>
                <p className={`text-xs mt-0.5 ${
                  dmarc === true || (typeof dmarc === 'string' && dmarc.toUpperCase() === 'PASS')
                    ? 'text-green-400'
                    : 'text-red-400'
                }`}>
                  {dmarc === true || (typeof dmarc === 'string' && dmarc.toUpperCase() === 'PASS') ? 'PASS' : 'FAIL'}
                </p>
              </div>
            </div>
            {/* Horizontal progress bar */}
            <div className="mt-4">
              <div className="flex h-2 rounded-full overflow-hidden bg-dark-700/50">
                {(spf === true || (typeof spf === 'string' && spf.toUpperCase() === 'PASS')) && (
                  <div className="flex-1 bg-green-500" />
                )}
                {(dkim === true || (typeof dkim === 'string' && dkim.toUpperCase() === 'PASS')) && (
                  <div className="flex-1 bg-green-500" />
                )}
                {(dmarc === true || (typeof dmarc === 'string' && dmarc.toUpperCase() === 'PASS')) && (
                  <div className="flex-1 bg-green-500" />
                )}
                {!(spf === true || (typeof spf === 'string' && spf.toUpperCase() === 'PASS')) && (
                  <div className="flex-1 bg-red-500" />
                )}
                {!(dkim === true || (typeof dkim === 'string' && dkim.toUpperCase() === 'PASS')) && (
                  <div className="flex-1 bg-red-500" />
                )}
                {!(dmarc === true || (typeof dmarc === 'string' && dmarc.toUpperCase() === 'PASS')) && (
                  <div className="flex-1 bg-red-500" />
                )}
              </div>
            </div>
          </div>
        </SectionCard>

        {/* Section 3: Sender Analysis */}
        <SectionCard icon={FiUser} title="Sender Analysis">
          <div className="bg-dark-900/50 rounded-lg border border-dark-700/50 p-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
              <div className="space-y-0">
                <InfoRow label="Sender Address" value={sender} />
                <InfoRow label="Display Name" value={displayName} />
                <InfoRow label="Sender Domain" value={senderDomain} />
              </div>
              <div className="space-y-0">
                <div className="flex items-center justify-between py-2 border-b border-dark-700/50 last:border-0">
                  <span className="text-xs text-dark-400">Spoofing Detected</span>
                  {spoofing === true || spoofing === 'detected' || spoofing === 'yes' ? (
                    <div className="flex items-center gap-1.5">
                      <FiAlertTriangle className="w-3.5 h-3.5 text-red-400" />
                      <span className="text-xs font-semibold text-red-400">YES</span>
                    </div>
                  ) : spoofing === false || spoofing === 'none' || spoofing === 'no' ? (
                    <div className="flex items-center gap-1.5">
                      <FiCheckCircle className="w-3.5 h-3.5 text-green-400" />
                      <span className="text-xs font-semibold text-green-400">NO</span>
                    </div>
                  ) : (
                    <span className="text-xs text-dark-400">—</span>
                  )}
                </div>
                <InfoRow
                  label="Return-Path"
                  value={typeof returnPath === 'string' ? returnPath : (returnPath && typeof returnPath === 'object' ? (returnPath.value || JSON.stringify(returnPath)) : '—')}
                />
                <InfoRow
                  label="Return-Path Mismatch"
                  value={
                    returnPath && typeof returnPath === 'object'
                      ? (returnPath.mismatch === true ? 'YES' : returnPath.mismatch === false ? 'NO' : (returnPath.mismatch || '—'))
                      : '—'
                  }
                />
              </div>
            </div>
          </div>
        </SectionCard>

        {/* Section 4: URL Analysis */}
        <SectionCard icon={FiLink} title={`URL Analysis (${urls.length} URL${urls.length !== 1 ? 's' : ''} found)`}>
          {urls.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-dark-700">
                    <th className="text-left text-dark-400 text-xs font-medium px-3 py-2.5 uppercase tracking-wider">URL</th>
                    <th className="text-left text-dark-400 text-xs font-medium px-3 py-2.5 uppercase tracking-wider">Domain</th>
                    <th className="text-center text-dark-400 text-xs font-medium px-3 py-2.5 uppercase tracking-wider">Risk</th>
                    <th className="text-center text-dark-400 text-xs font-medium px-3 py-2.5 uppercase tracking-wider">HTTPS</th>
                    <th className="text-center text-dark-400 text-xs font-medium px-3 py-2.5 uppercase tracking-wider">Suspicious</th>
                    <th className="text-center text-dark-400 text-xs font-medium px-3 py-2.5 uppercase tracking-wider">Phishing</th>
                    <th className="text-left text-dark-400 text-xs font-medium px-3 py-2.5 uppercase tracking-wider">Reasons</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-700/50">
                  {urls.map((url, idx) => {
                    const urlStr = typeof url === 'string' ? url : (url.url || url.href || url.link || '');
                    const urlDomain = typeof url === 'object' ? (url.domain || url.host || '') : '';
                    const urlRisk = typeof url === 'object' ? (url.risk_score ?? url.risk ?? 0) : 0;
                    const urlHttps = typeof url === 'object' ? (url.is_https ?? url.https ?? false) : false;
                    const urlSuspicious = typeof url === 'object' ? (url.is_suspicious ?? url.suspicious ?? false) : false;
                    const urlPhishing = typeof url === 'object' ? (url.is_phishing ?? url.phishing ?? false) : false;
                    const urlReasons = typeof url === 'object' ? (url.reasons ?? url.reason ?? []) : [];

                    return (
                      <tr key={idx} className={`hover:bg-dark-700/30 transition-colors ${getRiskRowColor(urlRisk)}`}>
                        <td className="px-3 py-2.5 max-w-[200px]">
                          <span className="text-dark-100 text-xs truncate block" title={urlStr}>
                            {urlStr || '—'}
                          </span>
                        </td>
                        <td className="px-3 py-2.5">
                          <span className="text-dark-300 text-xs">{urlDomain || '—'}</span>
                        </td>
                        <td className="px-3 py-2.5 text-center">
                          <RiskBadge score={urlRisk} />
                        </td>
                        <td className="px-3 py-2.5 text-center">
                          {urlHttps ? (
                            <FiLock className="w-3.5 h-3.5 text-green-400 mx-auto" />
                          ) : (
                            <FiAlertTriangle className="w-3.5 h-3.5 text-dark-500 mx-auto" />
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-center">
                          {urlSuspicious ? (
                            <span className="text-xs font-medium text-yellow-400">YES</span>
                          ) : (
                            <span className="text-xs text-dark-500">NO</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-center">
                          {urlPhishing ? (
                            <span className="text-xs font-medium text-red-400">YES</span>
                          ) : (
                            <span className="text-xs text-dark-500">NO</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5 max-w-[200px]">
                          <span className="text-dark-400 text-xs truncate block">
                            {Array.isArray(urlReasons)
                              ? urlReasons.join(', ')
                              : typeof urlReasons === 'string'
                              ? urlReasons
                              : '—'}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-8 text-center">
              <FiLink className="w-8 h-8 text-dark-600 mx-auto mb-2" />
              <p className="text-dark-400 text-sm">No URLs found in this email</p>
            </div>
          )}
        </SectionCard>

        {/* Section 5: Attachments */}
        <SectionCard icon={FiFile} title={`Attachments (${attachments.length})`}>
          {attachments.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {attachments.map((att, idx) => {
                const filename = att.filename ?? att.name ?? att.file_name ?? `Attachment ${idx + 1}`;
                const fileSize = att.size ?? att.file_size ?? att.filesize ?? 0;
                const attRisk = att.risk_score ?? att.risk ?? 0;
                const attClassification = att.classification ?? att.risk_level ?? att.type ?? 'unknown';
                const md5 = att.md5 ?? att.md5_hash ?? '';
                const sha1 = att.sha1 ?? att.sha1_hash ?? '';
                const sha256 = att.sha256 ?? att.sha256_hash ?? '';
                const attReasons = att.reasons ?? att.detection_reasons ?? att.indicators ?? [];
                const dangerousExt = att.dangerous_extension ?? att.dangerous_ext ?? false;
                const doubleExt = att.double_extension ?? att.double_ext ?? false;

                return (
                  <div
                    key={idx}
                    className="bg-dark-900/50 rounded-lg border border-dark-700/50 p-4 space-y-3"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <FiFile className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                        <span className="text-dark-100 text-sm font-medium truncate" title={filename}>
                          {filename}
                        </span>
                      </div>
                      <RiskBadge score={attRisk} />
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <ClassificationBadge classification={attClassification} />
                      {dangerousExt && (
                        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30 flex items-center gap-1">
                          <FiAlertTriangle className="w-3 h-3" />
                          Dangerous Extension
                        </span>
                      )}
                      {doubleExt && (
                        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-orange-500/15 text-orange-400 border border-orange-500/30 flex items-center gap-1">
                          <FiAlertTriangle className="w-3 h-3" />
                          Double Extension
                        </span>
                      )}
                    </div>

                    <div className="space-y-0">
                      <InfoRow label="Size" value={formatSize(fileSize)} />
                      <div className="flex items-center justify-between py-2 border-b border-dark-700/50">
                        <span className="text-xs text-dark-400">MD5</span>
                        <TruncateHash hash={md5} />
                      </div>
                      <div className="flex items-center justify-between py-2 border-b border-dark-700/50">
                        <span className="text-xs text-dark-400">SHA-1</span>
                        <TruncateHash hash={sha1} />
                      </div>
                      <div className="flex items-center justify-between py-2 border-b border-dark-700/50 last:border-0">
                        <span className="text-xs text-dark-400">SHA-256</span>
                        <TruncateHash hash={sha256} />
                      </div>
                    </div>

                    {Array.isArray(attReasons) && attReasons.length > 0 && (
                      <div>
                        <p className="text-xs text-dark-400 mb-1.5">Detection Reasons:</p>
                        <div className="flex flex-wrap gap-1.5">
                          {attReasons.map((r, ri) => (
                            <span
                              key={ri}
                              className="px-2 py-0.5 rounded text-xs bg-dark-700 text-dark-300 border border-dark-600"
                            >
                              {typeof r === 'string' ? r : (r.description || r.reason || JSON.stringify(r))}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="py-8 text-center">
              <FiFile className="w-8 h-8 text-dark-600 mx-auto mb-2" />
              <p className="text-dark-400 text-sm">No attachments found</p>
            </div>
          )}
        </SectionCard>

        {/* Section 6: Detection Reasons */}
        <SectionCard icon={FiAlertTriangle} title={`Detection Reasons (${reasons.length})`}>
          {reasons.length > 0 ? (
            <div className="space-y-2">
              {reasons.map((reason, idx) => {
                const category = reason.category ?? reason.type ?? reason.group ?? '';
                const description = reason.description ?? reason.message ?? reason.detail ?? (typeof reason === 'string' ? reason : '');
                const severity = reason.severity ?? reason.level ?? reason.risk ?? 'info';
                const points = reason.points ?? reason.score ?? reason.weight ?? null;

                return (
                  <div
                    key={idx}
                    className="bg-dark-900/50 rounded-lg border border-dark-700/50 p-3 flex items-start gap-3"
                  >
                    <div className="mt-0.5">
                      <SeverityIcon severity={severity} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        {category && (
                          <span className="text-xs text-cyan-400 font-medium">{category}</span>
                        )}
                        <SeverityBadge severity={severity} />
                        {points !== null && points !== undefined && (
                          <span className="text-xs text-dark-400">
                            +{points} pts
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-dark-300">{description || '—'}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="py-8 text-center">
              <FiCheckCircle className="w-8 h-8 text-dark-600 mx-auto mb-2" />
              <p className="text-dark-400 text-sm">No detection reasons recorded</p>
            </div>
          )}
        </SectionCard>

        {/* Section 7: Email Body Preview */}
        <SectionCard icon={FiEye} title="Email Body Preview" defaultOpen={false}>
          {body ? (
            <div className="bg-dark-900/50 rounded-lg border border-dark-700/50 p-4">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-dark-400">
                  {body.length > 2000 ? `Showing first 2,000 of ${body.length.toLocaleString()} characters` : `${body.length.toLocaleString()} characters`}
                </span>
                {body.length > 2000 && (
                  <button
                    onClick={() => setBodyExpanded(!bodyExpanded)}
                    className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1"
                  >
                    {bodyExpanded ? (
                      <>
                        <FiLock className="w-3 h-3" />
                        Collapse
                      </>
                    ) : (
                      <>
                        <FiEye className="w-3 h-3" />
                        Show All
                      </>
                    )}
                  </button>
                )}
              </div>
              <div className="bg-dark-900 rounded border border-dark-700/30 p-3 max-h-[400px] overflow-y-auto">
                <pre className="text-dark-300 text-xs whitespace-pre-wrap break-words font-mono leading-relaxed">
                  {bodyExpanded ? body : body.substring(0, 2000)}
                  {!bodyExpanded && body.length > 2000 && '...'}
                </pre>
              </div>
            </div>
          ) : (
            <div className="py-8 text-center">
              <FiMail className="w-8 h-8 text-dark-600 mx-auto mb-2" />
              <p className="text-dark-400 text-sm">No body content available</p>
            </div>
          )}
        </SectionCard>

        {/* Section 8: Actions */}
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-5">
          <div className="flex items-center gap-2.5 mb-4">
            <FiDownload className="w-4 h-4 text-cyan-400" />
            <h2 className="text-dark-100 font-semibold text-sm">Actions</h2>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleQuarantine}
              disabled={isQuarantineActionDisabled}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isQuarantineActionDisabled
                  ? 'bg-dark-700 text-dark-500 border border-dark-600 cursor-not-allowed'
                  : 'bg-red-500/15 text-red-400 border border-red-500/30 hover:bg-red-500/25'
              }`}
            >
              {actionLoading === 'quarantine' ? (
                <div className="w-4 h-4 border-2 border-red-400 border-t-transparent rounded-full animate-spin" />
              ) : (
                <FiLock className="w-4 h-4" />
              )}
              Quarantine Email
            </button>

            <button
              onClick={handleRelease}
              disabled={isReleaseActionDisabled}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isReleaseActionDisabled
                  ? 'bg-dark-700 text-dark-500 border border-dark-600 cursor-not-allowed'
                  : 'bg-green-500/15 text-green-400 border border-green-500/30 hover:bg-green-500/25'
              }`}
            >
              {actionLoading === 'release' ? (
                <div className="w-4 h-4 border-2 border-green-400 border-t-transparent rounded-full animate-spin" />
              ) : (
                <FiCheckCircle className="w-4 h-4" />
              )}
              Release Email
            </button>

            <button
              onClick={() => navigate(-1)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium bg-dark-700 text-dark-300 border border-dark-600 hover:bg-dark-600 hover:text-dark-100 transition-colors"
            >
              <FiArrowLeft className="w-4 h-4" />
              Back to List
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
