import { useState } from 'react';
import {
  FiHash, FiSearch, FiCopy, FiClock, FiTrash2
} from 'react-icons/fi';
import toast from 'react-hot-toast';
import { hashLookupAPI } from '../services/api';

const THREAT_LEVELS = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/20', border: 'border-red-500/30', label: 'CRITICAL' },
  high: { color: 'text-red-400', bg: 'bg-red-500/20', border: 'border-red-500/30', label: 'HIGH' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/20', border: 'border-yellow-500/30', label: 'MEDIUM' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/20', border: 'border-blue-500/30', label: 'LOW' },
  clean: { color: 'text-green-400', bg: 'bg-green-500/20', border: 'border-green-500/30', label: 'CLEAN' },
  unknown: { color: 'text-dark-400', bg: 'bg-dark-700', border: 'border-dark-600', label: 'UNKNOWN' },
  invalid: { color: 'text-orange-400', bg: 'bg-orange-500/20', border: 'border-orange-500/30', label: 'INVALID' },
};

const HASH_TYPE_LABELS = {
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  unknown: 'Unknown',
};

export default function HashLookupPage() {
  const [input, setInput] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [recentLookups, setRecentLookups] = useState([]);

  const handleLookup = async () => {
    const hashes = input.split('\n').map(h => h.trim()).filter(h => h.length > 0);
    if (hashes.length === 0) {
      toast.error('Please enter at least one hash');
      return;
    }

    setLoading(true);
    setResults(null);
    try {
      const res = await hashLookupAPI.lookup({ hashes });
      setResults(res.data);
      toast.success(`Looked up ${res.data.total} hash(es)`);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      toast.success('Copied to clipboard');
    });
  };

  const getThreatStyle = (level) => THREAT_LEVELS[level] || THREAT_LEVELS.unknown;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100">Hash Reputation Lookup</h1>
        <p className="text-dark-400 text-sm mt-1">Look up file hashes against local database and VirusTotal</p>
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-6">
        <h3 className="text-dark-200 font-semibold mb-4 flex items-center gap-2">
          <FiHash className="text-cyan-400" /> Enter File Hashes
        </h3>
        <p className="text-dark-400 text-sm mb-4">
          Enter one hash per line. Supports MD5, SHA-1, and SHA-256 formats.
        </p>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={"e.g.\na1b2c3d4e5f678901234567890123456\n5d41402abc4b2a76b9719d911017c592"}
          className="w-full h-40 bg-dark-950 border border-dark-600 text-dark-100 rounded-lg px-4 py-3 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent resize-none"
        />
        <div className="flex items-center justify-between mt-4">
          <span className="text-dark-500 text-sm">
            {input.split('\n').filter(h => h.trim()).length} hash(es) entered
          </span>
          <button
            onClick={handleLookup}
            disabled={loading || !input.trim()}
            className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-800 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            {loading ? (
              <>
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Looking up...
              </>
            ) : (
              <>
                <FiSearch className="w-4 h-4" /> Lookup Hashes
              </>
            )}
          </button>
        </div>
      </div>

      {results && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-dark-200 font-semibold">
              Results ({results.total} hash{results.total !== 1 ? 'es' : ''})
            </h3>
            <button
              onClick={() => setResults(null)}
              className="text-dark-400 hover:text-dark-200 text-sm flex items-center gap-1"
            >
              <FiTrash2 className="w-3 h-3" /> Clear
            </button>
          </div>

          {results.results.map((result, index) => {
            const threatStyle = getThreatStyle(result.threat_level);
            return (
              <div key={index} className="bg-dark-900 border border-dark-700 rounded-xl p-5">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3 min-w-0">
                    <FiHash className="text-dark-500 flex-shrink-0" />
                    <code className="text-dark-100 text-sm font-mono truncate">{result.hash}</code>
                    <button
                      onClick={() => copyToClipboard(result.hash)}
                      className="text-dark-500 hover:text-cyan-400 flex-shrink-0"
                      title="Copy"
                    >
                      <FiCopy size={14} />
                    </button>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${threatStyle.bg} ${threatStyle.color} ${threatStyle.border}`}>
                    {threatStyle.label}
                  </span>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm mb-4">
                  <div className="bg-dark-950 rounded-lg p-3 border border-dark-700">
                    <span className="text-dark-500 text-xs block">Hash Type</span>
                    <span className="text-dark-100">{HASH_TYPE_LABELS[result.hash_type]}</span>
                  </div>
                  <div className="bg-dark-950 rounded-lg p-3 border border-dark-700">
                    <span className="text-dark-500 text-xs block">Local Database</span>
                    <span className={result.found_locally ? 'text-yellow-400' : 'text-green-400'}>
                      {result.found_locally ? 'Found' : 'Not Found'}
                    </span>
                  </div>
                  {result.vt_result && (
                    <div className="bg-dark-950 rounded-lg p-3 border border-dark-700">
                      <span className="text-dark-500 text-xs block">VirusTotal</span>
                      <span className={result.vt_result.found ? 'text-dark-100' : 'text-dark-400'}>
                        {result.vt_result.found
                          ? `${result.vt_result.positives}/${result.vt_result.total} detections`
                          : 'Not found'}
                      </span>
                    </div>
                  )}
                </div>

                {result.local_scan && (
                  <div className="bg-dark-950 rounded-lg p-4 border border-dark-700 mb-3">
                    <h4 className="text-dark-300 text-sm font-medium mb-2">Local Scan Result</h4>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                      <div>
                        <span className="text-dark-500 text-xs block">File</span>
                        <span className="text-dark-100 truncate block">{result.local_scan.filename}</span>
                      </div>
                      <div>
                        <span className="text-dark-500 text-xs block">Risk Score</span>
                        <span className={`font-bold ${result.local_scan.risk_score <= 30 ? 'text-green-400' : result.local_scan.risk_score <= 70 ? 'text-yellow-400' : 'text-red-400'}`}>
                          {result.local_scan.risk_score}
                        </span>
                      </div>
                      <div>
                        <span className="text-dark-500 text-xs block">Classification</span>
                        <span className="text-dark-100 capitalize">{result.local_scan.classification}</span>
                      </div>
                      <div>
                        <span className="text-dark-500 text-xs block">Scan Date</span>
                        <span className="text-dark-100 text-xs">{result.local_scan.scan_date?.slice(0, 10)}</span>
                      </div>
                    </div>
                  </div>
                )}

                {result.vt_result && result.vt_result.found && (
                  <div className="bg-dark-950 rounded-lg p-4 border border-dark-700">
                    <h4 className="text-dark-300 text-sm font-medium mb-2">VirusTotal Details</h4>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                      <div>
                        <span className="text-dark-500 text-xs block">Malicious</span>
                        <span className="text-red-400 font-bold">{result.vt_result.malicious}</span>
                      </div>
                      <div>
                        <span className="text-dark-500 text-xs block">Suspicious</span>
                        <span className="text-yellow-400 font-bold">{result.vt_result.suspicious}</span>
                      </div>
                      <div>
                        <span className="text-dark-500 text-xs block">Undetected</span>
                        <span className="text-green-400">{result.vt_result.undetected}</span>
                      </div>
                      <div>
                        <span className="text-dark-500 text-xs block">Detection Rate</span>
                        <span className="text-dark-100">{result.vt_result.detection_rate}%</span>
                      </div>
                    </div>
                    {result.vt_result.tags && result.vt_result.tags.length > 0 && (
                      <div className="mt-3 flex flex-wrap gap-1">
                        {result.vt_result.tags.slice(0, 5).map((tag, i) => (
                          <span key={i} className="px-2 py-0.5 bg-dark-800 border border-dark-600 rounded text-xs text-dark-300">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {result.error && (
                  <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-red-400 text-sm">
                    {result.error}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {!results && !loading && (
        <div className="bg-dark-900 border border-dark-700 rounded-xl p-12 text-center">
          <FiHash className="mx-auto text-5xl text-dark-600 mb-4" />
          <p className="text-dark-400 text-lg">Enter hashes above to check their reputation</p>
          <p className="text-dark-500 text-sm mt-2">
            Results include local database matches and VirusTotal analysis
          </p>
        </div>
      )}
    </div>
  );
}
