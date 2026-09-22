import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import {
  FiArrowLeft, FiFile, FiHash, FiShield, FiAlertTriangle,
  FiCheckCircle, FiCopy, FiCheck, FiDownload, FiLock,
  FiInfo, FiCode,
} from 'react-icons/fi';
import { scansAPI, quarantineAPI, reportsAPI } from '../services/api';

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      toast.success('Copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <button
      onClick={handleCopy}
      className="p-1.5 rounded-md text-dark-400 hover:text-cyan-400 hover:bg-dark-700/50 transition-colors"
      title="Copy to clipboard"
    >
      {copied ? <FiCheck className="w-3.5 h-3.5 text-green-400" /> : <FiCopy className="w-3.5 h-3.5" />}
    </button>
  );
}

function InfoRow({ label, value }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-dark-700/50 last:border-0">
      <span className="text-xs text-dark-400">{label}</span>
      <span className="text-sm text-dark-100 text-right max-w-[60%] truncate">{value || '—'}</span>
    </div>
  );
}

function parseList(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) return parsed;
    } catch {
      return [];
    }
  }
  return [];
}

function RiskGauge({ score }) {
  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const getColor = (s) => {
    if (s <= 30) return { stroke: '#22c55e', text: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/20', label: 'LOW RISK' };
    if (s <= 70) return { stroke: '#eab308', text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', label: 'SUSPICIOUS' };
    return { stroke: '#ef4444', text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', label: 'MALICIOUS' };
  };

  const colors = getColor(score);

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-40 h-40">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
          <circle cx="64" cy="64" r={radius} fill="none" stroke="#1e293b" strokeWidth="8" />
          <circle
            cx="64" cy="64" r={radius} fill="none"
            stroke={colors.stroke}
            strokeWidth="8" strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 1s ease-out' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-4xl font-bold ${colors.text}`}>{score}</span>
          <span className="text-xs text-dark-500 mt-0.5">/ 100</span>
        </div>
      </div>
      <span className={`text-sm font-semibold ${colors.text}`}>{colors.label}</span>
    </div>
  );
}

export default function ScanDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [quarantining, setQuarantining] = useState(false);
  const [downloadingPDF, setDownloadingPDF] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError('');
    scansAPI.get(id)
      .then((res) => {
        const scan = res.data;
        const file = scan.file || {};
        setData({
          ...scan,
          ...file,
          file_id: scan.file_id,
          filename: file.original_filename || scan.filename,
          detection_reasons: parseList(scan.detection_reasons),
          suspicious_strings: parseList(scan.suspicious_strings),
        });
      })
      .catch((err) => {
        if (err.response?.status === 404) {
          setError('Scan not found.');
        } else {
          setError('Failed to load scan details.');
        }
      })
      .finally(() => setLoading(false));
  }, [id]);

  const handleDownloadPDF = async () => {
    setDownloadingPDF(true);
    try {
      const res = await reportsAPI.getPDF(id);
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `report-${id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      toast.success('Report downloaded successfully');
    } catch (err) {
      toast.error('Failed to download report');
    } finally {
      setDownloadingPDF(false);
    }
  };

  const handleQuarantine = async () => {
    if (!window.confirm('Are you sure you want to quarantine this file?')) return;
    setQuarantining(true);
    try {
      await quarantineAPI.quarantine(data.file_id || id);
      toast.success('File quarantined successfully');
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to quarantine file');
    } finally {
      setQuarantining(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin h-10 w-10 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-dark-400">Loading scan details...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-3xl mx-auto text-center py-16">
        <div className="w-16 h-16 bg-red-500/10 border border-red-500/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
          <FiAlertTriangle className="w-8 h-8 text-red-400" />
        </div>
        <h2 className="text-lg font-medium text-dark-100 mb-2">{error}</h2>
        <div className="flex justify-center gap-3 mt-6">
          <button
            onClick={() => navigate(-1)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 text-dark-200 rounded-lg text-sm font-medium transition-colors"
          >
            <FiArrowLeft className="w-4 h-4" /> Go Back
          </button>
          <button
            onClick={() => navigate('/scanner')}
            className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors"
          >
            Scan a File
          </button>
        </div>
      </div>
    );
  }

  const score = data.risk_score || 0;
  const indicators = data.indicators || data.detection_reasons || [];
  const suspiciousStrings = data.suspicious_strings || data.suspicious_patterns || [];

  const getClassBadge = (cls) => {
    const map = {
      safe: 'bg-green-500/20 text-green-400 border border-green-500/30',
      suspicious: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
      malicious: 'bg-red-500/20 text-red-400 border border-red-500/30',
    };
    return map[cls?.toLowerCase()] || 'bg-dark-700 text-dark-300 border border-dark-600';
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <button
        onClick={() => navigate(-1)}
        className="inline-flex items-center gap-2 text-sm text-dark-400 hover:text-dark-100 transition-colors"
      >
        <FiArrowLeft className="w-4 h-4" /> Back to results
      </button>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row items-center gap-8">
          <RiskGauge score={score} />
          <div className="flex-1 text-center sm:text-left space-y-3">
            <div>
              <h1 className="text-2xl font-bold text-dark-100">Security Analysis</h1>
              <p className="text-dark-400 text-sm mt-1">{data.filename}</p>
            </div>
            <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2">
              <span className={`inline-block px-3 py-1 rounded-full text-xs font-semibold ${getClassBadge(data.classification)}`}>
                {(data.classification || 'unknown').charAt(0).toUpperCase() + (data.classification || 'unknown').slice(1)}
              </span>
              {data.file_type && (
                <span className="inline-block px-3 py-1 rounded-full text-xs font-medium bg-dark-700 text-dark-300 border border-dark-600">
                  {data.file_type}
                </span>
              )}
            </div>
            {score > 70 && (
              <div className="flex items-start gap-3 bg-red-500/10 border border-red-500/30 rounded-lg p-4 border-l-4 border-l-red-500 max-w-lg">
                <FiAlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-sm font-semibold text-red-400">Malicious Activity Detected</h4>
                  <p className="text-xs text-dark-400 leading-relaxed mt-0.5">
                    This file has a <strong className="text-red-400">HIGH</strong> risk score ({score}/100).
                    <strong className="text-red-400"> Do not open, execute, or share this file.</strong>
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-dark-700 flex items-center gap-2">
            <FiFile className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-dark-100">File Information</h3>
          </div>
          <div className="px-5 py-3">
            <InfoRow label="Filename" value={data.filename} />
            <InfoRow label="File Size" value={data.file_size ? `${(data.file_size / 1024).toFixed(1)} KB` : '—'} />
            <InfoRow label="File Type" value={data.file_type} />
            <InfoRow label="Extension" value={data.extension || 'None'} />
            <InfoRow label="MIME Type" value={data.mime_type} />
          </div>
        </div>

        <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-dark-700 flex items-center gap-2">
            <FiHash className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-dark-100">Hash Information</h3>
          </div>
          <div className="px-5 py-3 space-y-3">
            {[
              { label: 'MD5', value: data.md5 || data.hashes?.md5 },
              { label: 'SHA-1', value: data.sha1 || data.hashes?.sha1 },
              { label: 'SHA-256', value: data.sha256 || data.hashes?.sha256 },
            ].map((hash) => (
              <div key={hash.label}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-dark-400">{hash.label}</span>
                  {hash.value && <CopyButton text={hash.value} />}
                </div>
                <div className="bg-dark-950 rounded-lg px-3 py-2 border border-dark-700/50">
                  <p className="font-mono text-xs text-dark-200 break-all">{hash.value || '—'}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-dark-700 flex items-center gap-2">
          <FiInfo className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-dark-100">Analysis</h3>
        </div>
        <div className="px-5 py-4 space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-dark-400">Entropy</span>
              <span className="text-sm font-mono text-dark-200">{(data.entropy || 0).toFixed(4)}</span>
            </div>
            <div className="w-full h-3 bg-dark-950 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${Math.min((data.entropy || 0) / 8 * 100, 100)}%`,
                  background: data.entropy > 7 ? 'linear-gradient(90deg, #eab308, #ef4444)' :
                    data.entropy > 5 ? 'linear-gradient(90deg, #22c55e, #eab308)' :
                      'linear-gradient(90deg, #06b6d4, #22c55e)',
                }}
              />
            </div>
            <div className="flex justify-between mt-1">
              <span className="text-[10px] text-dark-500">Low (0)</span>
              <span className="text-[10px] text-dark-500">High (8)</span>
            </div>
          </div>
          <InfoRow label="File Signature" value={data.file_signature || data.magic_bytes || 'Unknown'} />
        </div>
      </div>

      {suspiciousStrings.length > 0 && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-dark-700 flex items-center gap-2">
            <FiCode className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-dark-100">Suspicious Strings</h3>
            <span className="ml-auto text-xs text-dark-400">{suspiciousStrings.length} found</span>
          </div>
          <div className="px-5 py-3">
            <div className="space-y-1.5">
              {suspiciousStrings.map((str, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-2 px-3 py-2 bg-dark-950 rounded-lg border border-dark-700/50"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 shrink-0" />
                  <code className="text-xs font-mono text-dark-300 break-all">
                    {typeof str === 'string' ? str : str.value || str.string}
                  </code>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {indicators.length > 0 && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-dark-700 flex items-center gap-2">
            <FiAlertTriangle className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-dark-100">Detection Reasons</h3>
          </div>
          <div className="px-5 py-3 space-y-2">
            {indicators.map((ind, idx) => (
              <div
                key={idx}
                className={`flex items-start gap-3 p-3 rounded-lg border ${
                  ind.severity === 'critical'
                    ? 'bg-red-500/5 border-red-500/10'
                    : 'bg-yellow-500/5 border-yellow-500/10'
                }`}
              >
                <FiAlertTriangle className={`w-4 h-4 mt-0.5 shrink-0 ${
                  ind.severity === 'critical' ? 'text-red-400' : 'text-yellow-400'
                }`} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-dark-100">
                      {ind.name || ind.reason || ind}
                    </span>
                    {ind.points && (
                      <span className={`text-xs font-mono font-bold ${
                        ind.severity === 'critical' ? 'text-red-400' : 'text-yellow-400'
                      }`}>+{ind.points}</span>
                    )}
                  </div>
                  {ind.description && (
                    <p className="text-xs text-dark-400 mt-0.5">{ind.description}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex justify-center gap-3 pb-8">
        <button
          onClick={handleDownloadPDF}
          disabled={downloadingPDF}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <FiDownload className="w-4 h-4" />
          {downloadingPDF ? 'Generating...' : 'Download PDF Report'}
        </button>
        <button
          onClick={handleQuarantine}
          disabled={quarantining}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <FiLock className="w-4 h-4" />
          {quarantining ? 'Quarantining...' : 'Quarantine File'}
        </button>
      </div>
    </div>
  );
}
