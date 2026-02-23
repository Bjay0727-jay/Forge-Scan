import { useState, useRef, useCallback, useEffect } from 'react';
import {
  Upload,
  FileJson,
  FileText,
  AlertCircle,
  CheckCircle,
  FileSpreadsheet,
  Server,
  Shield,
  Clock,
  RefreshCw,
  X,
  ChevronDown,
  ChevronUp,
  Loader2,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { importApi, ingestApi } from '@/lib/api';
import { formatRelativeTime } from '@/lib/utils';
import type { ImportFormat, ImportResult, IngestVendor, IngestDataType, IngestUploadResult, IngestJob } from '@/types';

type ImportType = 'findings' | 'assets';

const findingFormats: { value: ImportFormat; label: string; description: string }[] = [
  {
    value: 'sarif',
    label: 'SARIF',
    description: 'Static Analysis Results Interchange Format (SARIF 2.1.0)',
  },
  {
    value: 'cyclonedx',
    label: 'CycloneDX',
    description: 'CycloneDX Software Bill of Materials (JSON)',
  },
  {
    value: 'csv',
    label: 'CSV',
    description: 'Comma-Separated Values with header row',
  },
  {
    value: 'json',
    label: 'JSON',
    description: 'ForgeScan native JSON format',
  },
];

const assetFormats: { value: string; label: string; description: string }[] = [
  {
    value: 'csv',
    label: 'CSV',
    description: 'Comma-Separated Values with header row',
  },
  {
    value: 'xlsx',
    label: 'Excel (XLSX)',
    description: 'Microsoft Excel spreadsheet format',
  },
  {
    value: 'json',
    label: 'JSON',
    description: 'ForgeScan native JSON format',
  },
];

const vendors: { value: IngestVendor; label: string; description: string }[] = [
  {
    value: 'generic',
    label: 'Generic',
    description: 'Standard CSV column names (title, severity, description)',
  },
  {
    value: 'tenable',
    label: 'Tenable / Nessus',
    description: 'Exported Nessus scan results with Plugin ID, Risk, etc.',
  },
  {
    value: 'qualys',
    label: 'Qualys',
    description: 'Qualys vulnerability scan export (QID, Severity Level)',
  },
  {
    value: 'rapid7',
    label: 'Rapid7 / Nexpose',
    description: 'Rapid7 InsightVM / Nexpose export format',
  },
];

// ─── Sub-components ─────────────────────────────────────────────────────────

function ImportResultCard({ result }: { result: ImportResult }) {
  return (
    <Card className={result.success ? 'border-green-500/30' : 'border-red-500/30'}>
      <CardContent className="pt-6">
        <div className="flex items-start gap-4">
          {result.success ? (
            <CheckCircle className="h-8 w-8 text-green-400" />
          ) : (
            <AlertCircle className="h-8 w-8 text-red-400" />
          )}
          <div className="flex-1">
            <h3 className="text-lg font-semibold">
              {result.success ? 'Import Successful' : 'Import Completed with Errors'}
            </h3>
            <div className="mt-2 grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-muted-foreground">Imported:</span>
                <span className="ml-2 font-medium text-green-400">
                  {result.imported_count}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Failed:</span>
                <span className="ml-2 font-medium text-red-400">
                  {result.failed_count}
                </span>
              </div>
            </div>
            {result.errors.length > 0 && (
              <div className="mt-4">
                <h4 className="mb-2 text-sm font-medium text-red-400">Errors:</h4>
                <ul className="max-h-40 overflow-auto rounded-lg bg-muted p-3 text-xs">
                  {result.errors.map((error, i) => (
                    <li key={i} className="text-red-400">
                      {error}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function IngestResultCard({ result }: { result: IngestUploadResult }) {
  const isSuccess = result.records_skipped === 0 && result.errors.length === 0;
  return (
    <Card className={isSuccess ? 'border-green-500/30' : 'border-amber-500/30'}>
      <CardContent className="pt-6">
        <div className="flex items-start gap-4">
          {isSuccess ? (
            <CheckCircle className="h-8 w-8 text-green-400" />
          ) : (
            <AlertCircle className="h-8 w-8 text-amber-400" />
          )}
          <div className="flex-1">
            <h3 className="text-lg font-semibold">
              {isSuccess ? 'Import Successful' : 'Import Completed with Warnings'}
            </h3>
            <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
              <Badge variant="outline" className="text-xs">{result.type}</Badge>
              <span>Job ID: {result.job_id.slice(0, 8)}...</span>
            </div>
            <div className="mt-3 grid grid-cols-3 gap-4 text-sm">
              <div>
                <span className="text-muted-foreground">Processed:</span>
                <span className="ml-2 font-medium">{result.records_processed}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Imported:</span>
                <span className="ml-2 font-medium text-green-400">{result.records_imported}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Skipped:</span>
                <span className="ml-2 font-medium text-amber-400">{result.records_skipped}</span>
              </div>
            </div>
            {/* Progress bar */}
            <div className="mt-3">
              <div className="h-2 w-full rounded-full bg-muted">
                <div
                  className="h-2 rounded-full bg-green-500 transition-all duration-500"
                  style={{
                    width: result.records_processed > 0
                      ? `${(result.records_imported / result.records_processed) * 100}%`
                      : '0%',
                  }}
                />
              </div>
            </div>
            {result.errors.length > 0 && (
              <div className="mt-4">
                <h4 className="mb-2 text-sm font-medium text-amber-400">
                  Warnings ({result.errors.length}):
                </h4>
                <ul className="max-h-40 overflow-auto rounded-lg bg-muted p-3 text-xs space-y-1">
                  {result.errors.map((error, i) => (
                    <li key={i} className="text-amber-400">{error}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function JobStatusBadge({ status }: { status: string }) {
  switch (status) {
    case 'completed':
      return <Badge className="bg-green-500/15 text-green-400 border-green-500/30 text-xs">Completed</Badge>;
    case 'processing':
      return <Badge className="bg-blue-500/15 text-blue-400 border-blue-500/30 text-xs animate-pulse">Processing</Badge>;
    case 'failed':
      return <Badge className="bg-red-500/15 text-red-400 border-red-500/30 text-xs">Failed</Badge>;
    default:
      return <Badge variant="outline" className="text-xs">{status}</Badge>;
  }
}

function ImportHistory({ jobs, loading, onRefresh }: {
  jobs: IngestJob[];
  loading: boolean;
  onRefresh: () => void;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (loading && jobs.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
          <p className="mt-2 text-sm text-muted-foreground">Loading import history...</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-lg">Recent Imports</CardTitle>
            <CardDescription>Last 10 import jobs</CardDescription>
          </div>
          <Button variant="ghost" size="sm" onClick={onRefresh} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {jobs.length === 0 ? (
          <p className="text-center text-sm text-muted-foreground py-4">
            No import jobs yet. Upload a file to get started.
          </p>
        ) : (
          <div className="space-y-2">
            {jobs.map((job) => {
              const errors = job.errors ? JSON.parse(job.errors) as string[] : [];
              const isExpanded = expanded === job.id;
              return (
                <div
                  key={job.id}
                  className="rounded-lg border p-3 transition-colors hover:bg-muted/50"
                >
                  <div
                    className="flex items-center justify-between cursor-pointer"
                    onClick={() => setExpanded(isExpanded ? null : job.id)}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <JobStatusBadge status={job.status} />
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium capitalize">{job.vendor}</span>
                          <span className="text-xs text-muted-foreground">{job.source}</span>
                        </div>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5">
                          <Clock className="h-3 w-3" />
                          <span>{formatRelativeTime(job.completed_at || job.started_at || job.created_at)}</span>
                          {job.records_processed != null && (
                            <>
                              <span className="text-muted-foreground/50">|</span>
                              <span>{job.records_imported ?? 0} imported</span>
                              {(job.records_skipped ?? 0) > 0 && (
                                <span className="text-amber-400">{job.records_skipped} skipped</span>
                              )}
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {job.records_processed != null && job.records_processed > 0 && (
                        <div className="hidden sm:block w-24">
                          <div className="h-1.5 w-full rounded-full bg-muted">
                            <div
                              className="h-1.5 rounded-full bg-green-500"
                              style={{
                                width: `${((job.records_imported ?? 0) / job.records_processed) * 100}%`,
                              }}
                            />
                          </div>
                        </div>
                      )}
                      {isExpanded ? (
                        <ChevronUp className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      )}
                    </div>
                  </div>
                  {isExpanded && (
                    <div className="mt-3 pt-3 border-t space-y-2">
                      <div className="grid grid-cols-3 gap-2 text-xs">
                        <div>
                          <span className="text-muted-foreground">Processed:</span>
                          <span className="ml-1 font-medium">{job.records_processed ?? 0}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Imported:</span>
                          <span className="ml-1 font-medium text-green-400">{job.records_imported ?? 0}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Skipped:</span>
                          <span className="ml-1 font-medium text-amber-400">{job.records_skipped ?? 0}</span>
                        </div>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Job ID: <code className="bg-muted px-1 rounded">{job.id}</code>
                      </div>
                      {errors.length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-red-400 mb-1">Errors:</h4>
                          <ul className="max-h-32 overflow-auto rounded bg-muted p-2 text-xs space-y-0.5">
                            {errors.map((err, i) => (
                              <li key={i} className="text-red-400">{err}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Main component ─────────────────────────────────────────────────────────

export function Import() {
  const [importType, setImportType] = useState<ImportType>('findings');
  const [format, setFormat] = useState<string>('csv');
  const [vendor, setVendor] = useState<IngestVendor>('generic');
  const [data, setData] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [ingestResult, setIngestResult] = useState<IngestUploadResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Import history
  const [jobs, setJobs] = useState<IngestJob[]>([]);
  const [jobsLoading, setJobsLoading] = useState(false);

  const loadJobs = useCallback(async () => {
    setJobsLoading(true);
    try {
      const data = await ingestApi.getJobs({ limit: 10 });
      setJobs(data);
    } catch {
      // Silently fail — history is not critical
    } finally {
      setJobsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadJobs();
  }, [loadJobs]);

  const clearResults = () => {
    setResult(null);
    setIngestResult(null);
    setError(null);
    setSelectedFile(null);
  };

  const handleImportTypeChange = (type: ImportType) => {
    setImportType(type);
    setFormat(type === 'findings' ? 'csv' : 'csv');
    setData('');
    clearResults();
  };

  // Use ingest API for CSV uploads (supports vendor mappings)
  const isCSVFormat = format === 'csv';
  const useIngestApi = isCSVFormat;

  const processFileUpload = async (file: File) => {
    setLoading(true);
    clearResults();
    setSelectedFile(file);

    try {
      if (useIngestApi) {
        // Route CSV through the ingest API with vendor-specific parsing
        const dataType: IngestDataType = importType === 'assets' ? 'assets' : 'findings';
        const uploadResult = await ingestApi.uploadFile(file, vendor, dataType);
        setIngestResult(uploadResult);
        // Refresh job history
        loadJobs();
      } else {
        // Use legacy import API for SARIF, CycloneDX, JSON
        if (importType === 'assets') {
          const importResult = await importApi.uploadAssetFile(format, file);
          setResult(importResult);
        } else {
          const importResult = await importApi.uploadFile(format as ImportFormat, file);
          setResult(importResult);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'File upload failed');
    } finally {
      setLoading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    await processFileUpload(file);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files[0];
    if (!file) return;
    await processFileUpload(file);
  };

  const handleDataImport = async () => {
    if (!data.trim()) {
      setError('Please enter data to import');
      return;
    }

    setLoading(true);
    clearResults();

    try {
      if (useIngestApi && isCSVFormat) {
        // For pasted CSV data, create a File from the text and use ingest API
        const blob = new Blob([data], { type: 'text/csv' });
        const file = new File([blob], 'pasted-data.csv', { type: 'text/csv' });
        const dataType: IngestDataType = importType === 'assets' ? 'assets' : 'findings';
        const uploadResult = await ingestApi.uploadFile(file, vendor, dataType);
        setIngestResult(uploadResult);
        loadJobs();
      } else {
        let parsedData: string | object = data;
        if (format !== 'csv') {
          try {
            parsedData = JSON.parse(data);
          } catch {
            setError('Invalid JSON format');
            setLoading(false);
            return;
          }
        }

        if (importType === 'assets') {
          const importResult = await importApi.importAssets(format, parsedData);
          setResult(importResult);
        } else {
          const importResult = await importApi.importData(format as ImportFormat, parsedData);
          setResult(importResult);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setLoading(false);
    }
  };

  const formats = importType === 'findings' ? findingFormats : assetFormats;
  const selectedFormat = formats.find((f) => f.value === format);
  const fileAccept = importType === 'assets'
    ? '.json,.csv,.xlsx,.xls'
    : '.json,.sarif,.xml,.csv';

  const getPlaceholder = () => {
    if (importType === 'assets') {
      if (format === 'csv') {
        return 'hostname,ip_address,os,asset_type,network_zone,tags\n"web-server-01","192.168.1.10","Ubuntu 22.04","host","production","web,linux"\n"db-server-01","192.168.1.20","Windows Server 2022","host","production","database,windows"';
      }
      return '[\n  {\n    "hostname": "web-server-01",\n    "ip_addresses": ["192.168.1.10"],\n    "os": "Ubuntu 22.04",\n    "asset_type": "host"\n  }\n]';
    }
    if (format === 'csv') {
      if (vendor === 'tenable') {
        return '"Plugin ID","Risk","Host","Name","Synopsis","Description","Solution","CVSS v3.0 Base Score"\n"12345","Critical","192.168.1.1","SSL Certificate Expired","The SSL certificate has expired.","The remote server SSL certificate has expired.","Renew the certificate.","9.8"';
      }
      if (vendor === 'qualys') {
        return '"QID","Severity Level","IP","Title","Threat","Impact","Solution","CVSS Base"\n"38173","5","192.168.1.1","SSL Certificate - Expired","Expired SSL cert detected","Sensitive data may be exposed","Renew the certificate","9.8"';
      }
      if (vendor === 'rapid7') {
        return '"Vulnerability ID","Severity","IP Address","Title","Description","Proof","Solution","CVSS Score"\n"ssl-expired-cert","Critical","192.168.1.1","Expired SSL Certificate","SSL certificate has expired","Certificate valid until 2023-01-01","Renew certificate","9.8"';
      }
      return 'title,severity,cve_id,description,affected_component\n"SQL Injection",critical,CVE-2024-1234,"SQL injection vulnerability","login form"';
    }
    return '{\n  "version": "2.1.0",\n  "runs": [...]\n}';
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Import Data</h1>
        <p className="text-muted-foreground">
          Import assets and security findings from scanner exports and various formats
        </p>
      </div>

      {/* Import Type Selection */}
      <div className="mb-6 flex gap-4">
        <Button
          variant={importType === 'findings' ? 'default' : 'outline'}
          onClick={() => handleImportTypeChange('findings')}
          className="flex items-center gap-2"
        >
          <Shield className="h-4 w-4" />
          Import Findings
        </Button>
        <Button
          variant={importType === 'assets' ? 'default' : 'outline'}
          onClick={() => handleImportTypeChange('assets')}
          className="flex items-center gap-2"
        >
          <Server className="h-4 w-4" />
          Import Assets
        </Button>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>
                {importType === 'findings' ? 'Import Security Findings' : 'Import Assets'}
              </CardTitle>
              <CardDescription>
                {importType === 'findings'
                  ? 'Upload scanner exports or paste data to import findings'
                  : 'Upload or paste asset inventory data to import assets'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {/* Format + Vendor Selection Row */}
              <div className="mb-6 grid gap-4 sm:grid-cols-2">
                <div>
                  <Label htmlFor="format">Import Format</Label>
                  <Select
                    value={format}
                    onValueChange={(value) => {
                      setFormat(value);
                      clearResults();
                    }}
                  >
                    <SelectTrigger className="mt-2">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {formats.map((f) => (
                        <SelectItem key={f.value} value={f.value}>
                          {f.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {selectedFormat && (
                    <p className="mt-2 text-xs text-muted-foreground">
                      {selectedFormat.description}
                    </p>
                  )}
                </div>

                {/* Vendor selector — shown only for CSV format */}
                {isCSVFormat && importType === 'findings' && (
                  <div>
                    <Label htmlFor="vendor">Scanner Vendor</Label>
                    <Select
                      value={vendor}
                      onValueChange={(value) => {
                        setVendor(value as IngestVendor);
                        clearResults();
                      }}
                    >
                      <SelectTrigger className="mt-2">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {vendors.map((v) => (
                          <SelectItem key={v.value} value={v.value}>
                            {v.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className="mt-2 text-xs text-muted-foreground">
                      {vendors.find((v) => v.value === vendor)?.description}
                    </p>
                  </div>
                )}
              </div>

              <Tabs defaultValue="upload">
                <TabsList className="mb-4">
                  <TabsTrigger value="upload">
                    <Upload className="mr-2 h-4 w-4" />
                    Upload File
                  </TabsTrigger>
                  <TabsTrigger value="paste">
                    <FileText className="mr-2 h-4 w-4" />
                    Paste Data
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="upload">
                  <div
                    className={`flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-10 transition-colors ${
                      isDragOver
                        ? 'border-primary bg-primary/5'
                        : 'hover:border-primary'
                    } ${loading ? 'opacity-60 pointer-events-none' : ''}`}
                    onDragOver={(e) => {
                      e.preventDefault();
                      setIsDragOver(true);
                    }}
                    onDragLeave={() => setIsDragOver(false)}
                    onDrop={handleDrop}
                  >
                    {loading ? (
                      <>
                        <Loader2 className="mb-4 h-12 w-12 animate-spin text-primary" />
                        <p className="mb-2 text-lg font-medium">Processing...</p>
                        <p className="text-sm text-muted-foreground">
                          Parsing and importing your data
                        </p>
                      </>
                    ) : selectedFile && !error ? (
                      <>
                        <CheckCircle className="mb-4 h-12 w-12 text-green-400" />
                        <p className="mb-1 text-lg font-medium">{selectedFile.name}</p>
                        <p className="mb-4 text-sm text-muted-foreground">
                          {formatFileSize(selectedFile.size)}
                        </p>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setSelectedFile(null);
                            clearResults();
                          }}
                        >
                          <X className="mr-2 h-3 w-3" />
                          Clear &amp; Upload Another
                        </Button>
                      </>
                    ) : (
                      <>
                        {format === 'xlsx' ? (
                          <FileSpreadsheet className="mb-4 h-12 w-12 text-muted-foreground" />
                        ) : (
                          <Upload className="mb-4 h-12 w-12 text-muted-foreground" />
                        )}
                        <p className="mb-2 text-lg font-medium">
                          {isDragOver ? 'Drop your file here' : 'Drag and drop a file here'}
                        </p>
                        <p className="mb-4 text-sm text-muted-foreground">
                          or click to browse
                        </p>
                        <input
                          ref={fileInputRef}
                          type="file"
                          accept={fileAccept}
                          onChange={handleFileUpload}
                          className="hidden"
                          id="file-upload"
                        />
                        <Button
                          variant="outline"
                          onClick={() => fileInputRef.current?.click()}
                          disabled={loading}
                        >
                          Select File
                        </Button>
                      </>
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="paste">
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="data">Data</Label>
                      <Textarea
                        id="data"
                        value={data}
                        onChange={(e) => setData(e.target.value)}
                        placeholder={getPlaceholder()}
                        rows={12}
                        className="mt-2 font-mono text-sm"
                      />
                    </div>
                    <Button onClick={handleDataImport} disabled={loading || !data.trim()}>
                      {loading ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Importing...
                        </>
                      ) : (
                        'Import Data'
                      )}
                    </Button>
                  </div>
                </TabsContent>
              </Tabs>

              {error && (
                <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400 flex items-start gap-3">
                  <AlertCircle className="h-5 w-5 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-medium">Import Failed</p>
                    <p className="mt-1">{error}</p>
                  </div>
                </div>
              )}

              {ingestResult && (
                <div className="mt-4">
                  <IngestResultCard result={ingestResult} />
                </div>
              )}

              {result && (
                <div className="mt-4">
                  <ImportResultCard result={result} />
                </div>
              )}
            </CardContent>
          </Card>

          {/* Import History */}
          <ImportHistory jobs={jobs} loading={jobsLoading} onRefresh={loadJobs} />
        </div>

        {/* Sidebar documentation */}
        <div className="space-y-6">
          {importType === 'assets' ? (
            <>
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Asset CSV Format</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="mb-2 text-sm text-muted-foreground">
                    Required columns:
                  </p>
                  <ul className="list-inside list-disc text-sm text-muted-foreground">
                    <li><code className="bg-muted px-1 rounded">hostname</code> - Server name</li>
                    <li><code className="bg-muted px-1 rounded">ip_address</code> - IP address</li>
                  </ul>
                  <p className="mt-3 text-sm text-muted-foreground">
                    Optional columns:
                  </p>
                  <ul className="list-inside list-disc text-sm text-muted-foreground">
                    <li><code className="bg-muted px-1 rounded">fqdn</code> - Fully qualified domain name</li>
                    <li><code className="bg-muted px-1 rounded">os</code> - Operating system</li>
                    <li><code className="bg-muted px-1 rounded">os_version</code> - OS version</li>
                    <li><code className="bg-muted px-1 rounded">asset_type</code> - host, container, cloud_resource</li>
                    <li><code className="bg-muted px-1 rounded">network_zone</code> - production, staging, dev</li>
                    <li><code className="bg-muted px-1 rounded">tags</code> - Comma-separated tags</li>
                    <li><code className="bg-muted px-1 rounded">owner</code> - Asset owner</li>
                    <li><code className="bg-muted px-1 rounded">department</code> - Department</li>
                  </ul>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Example CSV</CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="text-xs bg-muted p-3 rounded-lg overflow-x-auto">
{`hostname,ip_address,os,asset_type,tags
web-srv-01,192.168.1.10,Ubuntu 22.04,host,web
db-srv-01,192.168.1.20,PostgreSQL,host,database
app-srv-01,192.168.1.30,Windows 2022,host,app`}
                  </pre>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Download Template</CardTitle>
                </CardHeader>
                <CardContent>
                  <Button
                    variant="outline"
                    className="w-full"
                    onClick={() => {
                      const csv = 'hostname,ip_address,fqdn,os,os_version,asset_type,network_zone,tags,owner,department\nweb-server-01,192.168.1.10,web-server-01.example.com,Ubuntu,22.04,host,production,"web,linux",John Doe,IT\n';
                      const blob = new Blob([csv], { type: 'text/csv' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = 'assets_template.csv';
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                  >
                    <FileSpreadsheet className="mr-2 h-4 w-4" />
                    Download CSV Template
                  </Button>
                </CardContent>
              </Card>
            </>
          ) : (
            <>
              {/* Vendor-specific help — shown for CSV */}
              {isCSVFormat && (
                <Card className="border-primary/20">
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <FileSpreadsheet className="h-5 w-5 text-primary" />
                      {vendor === 'generic' ? 'CSV' : vendors.find((v) => v.value === vendor)?.label} Column Mapping
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {vendor === 'tenable' && (
                      <div className="space-y-2 text-sm text-muted-foreground">
                        <p>Supported Nessus export columns:</p>
                        <ul className="list-inside list-disc space-y-0.5 text-xs">
                          <li><code className="bg-muted px-1 rounded">Plugin ID</code> / <code className="bg-muted px-1 rounded">plugin_id</code></li>
                          <li><code className="bg-muted px-1 rounded">Risk</code> / <code className="bg-muted px-1 rounded">Severity</code></li>
                          <li><code className="bg-muted px-1 rounded">Host</code> / <code className="bg-muted px-1 rounded">IP Address</code></li>
                          <li><code className="bg-muted px-1 rounded">Name</code> / <code className="bg-muted px-1 rounded">Plugin Name</code></li>
                          <li><code className="bg-muted px-1 rounded">Synopsis</code> / <code className="bg-muted px-1 rounded">Description</code></li>
                          <li><code className="bg-muted px-1 rounded">Solution</code></li>
                          <li><code className="bg-muted px-1 rounded">CVSS v3.0 Base Score</code></li>
                          <li><code className="bg-muted px-1 rounded">Plugin Output</code> / <code className="bg-muted px-1 rounded">Plugin Text</code></li>
                        </ul>
                      </div>
                    )}
                    {vendor === 'qualys' && (
                      <div className="space-y-2 text-sm text-muted-foreground">
                        <p>Supported Qualys export columns:</p>
                        <ul className="list-inside list-disc space-y-0.5 text-xs">
                          <li><code className="bg-muted px-1 rounded">QID</code></li>
                          <li><code className="bg-muted px-1 rounded">Severity Level</code> / <code className="bg-muted px-1 rounded">Severity</code></li>
                          <li><code className="bg-muted px-1 rounded">IP</code> / <code className="bg-muted px-1 rounded">IP Address</code></li>
                          <li><code className="bg-muted px-1 rounded">Title</code> / <code className="bg-muted px-1 rounded">Vulnerability</code></li>
                          <li><code className="bg-muted px-1 rounded">Threat</code> / <code className="bg-muted px-1 rounded">Impact</code></li>
                          <li><code className="bg-muted px-1 rounded">Solution</code></li>
                          <li><code className="bg-muted px-1 rounded">CVSS Base</code></li>
                          <li><code className="bg-muted px-1 rounded">Results</code> / <code className="bg-muted px-1 rounded">Output</code></li>
                        </ul>
                      </div>
                    )}
                    {vendor === 'rapid7' && (
                      <div className="space-y-2 text-sm text-muted-foreground">
                        <p>Supported Rapid7/Nexpose columns:</p>
                        <ul className="list-inside list-disc space-y-0.5 text-xs">
                          <li><code className="bg-muted px-1 rounded">Vulnerability ID</code></li>
                          <li><code className="bg-muted px-1 rounded">Severity</code> / <code className="bg-muted px-1 rounded">Risk Score</code></li>
                          <li><code className="bg-muted px-1 rounded">IP Address</code> / <code className="bg-muted px-1 rounded">Asset IP</code></li>
                          <li><code className="bg-muted px-1 rounded">Title</code> / <code className="bg-muted px-1 rounded">Vulnerability Title</code></li>
                          <li><code className="bg-muted px-1 rounded">Description</code></li>
                          <li><code className="bg-muted px-1 rounded">Solution</code> / <code className="bg-muted px-1 rounded">Remediation</code></li>
                          <li><code className="bg-muted px-1 rounded">CVSS Score</code></li>
                          <li><code className="bg-muted px-1 rounded">Proof</code></li>
                        </ul>
                      </div>
                    )}
                    {vendor === 'generic' && (
                      <div className="space-y-2 text-sm text-muted-foreground">
                        <p>Standard column names:</p>
                        <ul className="list-inside list-disc space-y-0.5 text-xs">
                          <li><code className="bg-muted px-1 rounded">title</code> / <code className="bg-muted px-1 rounded">name</code></li>
                          <li><code className="bg-muted px-1 rounded">severity</code> (critical, high, medium, low, info)</li>
                          <li><code className="bg-muted px-1 rounded">description</code></li>
                          <li><code className="bg-muted px-1 rounded">cve_id</code> / <code className="bg-muted px-1 rounded">cve</code></li>
                          <li><code className="bg-muted px-1 rounded">cvss_score</code> / <code className="bg-muted px-1 rounded">cvss</code></li>
                          <li><code className="bg-muted px-1 rounded">affected_component</code></li>
                          <li><code className="bg-muted px-1 rounded">remediation</code> / <code className="bg-muted px-1 rounded">solution</code></li>
                          <li><code className="bg-muted px-1 rounded">ip</code> / <code className="bg-muted px-1 rounded">hostname</code></li>
                        </ul>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Supported Formats</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {findingFormats.map((f) => (
                    <div key={f.value} className="flex items-start gap-3">
                      <FileJson className="mt-0.5 h-5 w-5 text-primary" />
                      <div>
                        <h4 className="font-medium">{f.label}</h4>
                        <p className="text-sm text-muted-foreground">
                          {f.description}
                        </p>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </>
          )}

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Tips</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              <ul className="list-inside list-disc space-y-2">
                <li>Select the correct vendor preset to auto-map columns</li>
                <li>CSV files are parsed with RFC 4180 compliance (quoted fields, escaped quotes)</li>
                <li>Severity values are automatically normalized (CVSS scores, text labels)</li>
                <li>Assets are auto-created from hostname/IP when importing findings</li>
                <li>Check the import history below for past job results</li>
                {importType === 'assets' && (
                  <li>Excel files (.xlsx) will use the first sheet</li>
                )}
              </ul>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
