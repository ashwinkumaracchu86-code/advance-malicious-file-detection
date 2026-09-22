import { useState } from 'react';
import toast from 'react-hot-toast';
import {
  FiDownload, FiFile, FiAlertTriangle, FiFileText
} from 'react-icons/fi';
import { featuresAPI } from '../services/api';

export default function ExportPage() {
  const [exporting, setExporting] = useState(null);

  const handleExport = async (type) => {
    setExporting(type);
    try {
      let res;
      let filename;

      if (type === 'scans-csv') {
        res = await featuresAPI.exportScansCSV();
        filename = 'scan_results.csv';
      } else if (type === 'scans-json') {
        res = await featuresAPI.exportScansJSON();
        filename = 'scan_results.json';
      } else if (type === 'threats-csv') {
        res = await featuresAPI.exportThreatsCSV();
        filename = 'threats.csv';
      }

      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      toast.success(`Exported ${filename}`);
    } catch (err) {
      toast.error('Export failed');
    } finally {
      setExporting(null);
    }
  };

  const exportOptions = [
    {
      id: 'scans-csv',
      title: 'All Scans (CSV)',
      description: 'Export all scan results as a CSV file for spreadsheet analysis',
      icon: FiFile,
      color: 'text-green-400',
      bgColor: 'bg-green-500/10',
    },
    {
      id: 'scans-json',
      title: 'All Scans (JSON)',
      description: 'Export all scan results as JSON for programmatic use',
      icon: FiFileText,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/10',
    },
    {
      id: 'threats-csv',
      title: 'Threats Only (CSV)',
      description: 'Export only malicious and suspicious files as CSV',
      icon: FiAlertTriangle,
      color: 'text-red-400',
      bgColor: 'bg-red-500/10',
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100 flex items-center gap-2">
          <FiDownload className="text-cyan-400" /> Export Reports
        </h1>
        <p className="text-dark-400 text-sm mt-1">Download scan results and threat reports</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {exportOptions.map((option) => (
          <div key={option.id} className="bg-dark-900 border border-dark-700 rounded-xl p-6 hover:border-cyan-500/30 transition-colors">
            <div className="flex items-center gap-3 mb-4">
              <div className={`p-3 rounded-xl ${option.bgColor}`}>
                <option.icon className={`w-6 h-6 ${option.color}`} />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-dark-100">{option.title}</h3>
              </div>
            </div>
            <p className="text-xs text-dark-400 mb-4">{option.description}</p>
            <button
              onClick={() => handleExport(option.id)}
              disabled={exporting === option.id}
              className="w-full px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {exporting === option.id ? (
                <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
              ) : (
                <FiDownload className="w-4 h-4" />
              )}
              {exporting === option.id ? 'Exporting...' : 'Download'}
            </button>
          </div>
        ))}
      </div>

      <div className="bg-dark-900 border border-dark-700 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-dark-100 mb-4">Export Information</h3>
        <div className="space-y-2 text-xs text-dark-400">
          <p><strong className="text-dark-200">CSV files</strong> can be opened in Microsoft Excel, Google Sheets, or any spreadsheet application.</p>
          <p><strong className="text-dark-200">JSON files</strong> are machine-readable and can be imported into other security tools or custom scripts.</p>
          <p><strong className="text-dark-200">Threats Only</strong> export includes only files classified as malicious or suspicious.</p>
        </div>
      </div>
    </div>
  );
}
