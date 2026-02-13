import { useState, useRef } from 'react';
import { Upload, FileJson, FileText, AlertCircle, CheckCircle, FileSpreadsheet, Server, Shield } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { importApi } from '@/lib/api';
import type { ImportFormat, ImportResult } from '@/types';

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

function ImportResultCard({ result }: { result: ImportResult }) {
  return (
    <Card className={result.success ? 'border-green-200' : 'border-red-200'}>
      <CardContent className="pt-6">
        <div className="flex items-start gap-4">
          {result.success ? (
            <CheckCircle className="h-8 w-8 text-green-600" />
          ) : (
            <AlertCircle className="h-8 w-8 text-red-600" />
          )}
          <div className="flex-1">
            <h3 className="text-lg font-semibold">
              {result.success ? 'Import Successful' : 'Import Completed with Errors'}
            </h3>
            <div className="mt-2 grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-muted-foreground">Imported:</span>
                <span className="ml-2 font-medium text-green-600">
                  {result.imported_count}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Failed:</span>
                <span className="ml-2 font-medium text-red-600">
                  {result.failed_count}
                </span>
              </div>
            </div>
            {result.errors.length > 0 && (
              <div className="mt-4">
                <h4 className="mb-2 text-sm font-medium text-red-600">Errors:</h4>
                <ul className="max-h-40 overflow-auto rounded-lg bg-muted p-3 text-xs">
                  {result.errors.map((error, i) => (
                    <li key={i} className="text-red-600">
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

export function Import() {
  const [importType, setImportType] = useState<ImportType>('findings');
  const [format, setFormat] = useState<string>('sarif');
  const [data, setData] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleImportTypeChange = (type: ImportType) => {
    setImportType(type);
    setFormat(type === 'findings' ? 'sarif' : 'csv');
    setData('');
    setResult(null);
    setError(null);
  };

  const handleDataImport = async () => {
    if (!data.trim()) {
      setError('Please enter data to import');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
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
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      if (importType === 'assets') {
        const importResult = await importApi.uploadAssetFile(format, file);
        setResult(importResult);
      } else {
        const importResult = await importApi.uploadFile(format as ImportFormat, file);
        setResult(importResult);
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

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      if (importType === 'assets') {
        const importResult = await importApi.uploadAssetFile(format, file);
        setResult(importResult);
      } else {
        const importResult = await importApi.uploadFile(format as ImportFormat, file);
        setResult(importResult);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'File upload failed');
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
      return 'title,severity,cve_id,description\n"SQL Injection",critical,CVE-2024-1234,"SQL injection vulnerability"';
    }
    return '{\n  "version": "2.1.0",\n  "runs": [...]\n}';
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-3xl font-bold">Import Data</h1>
        <p className="text-muted-foreground">
          Import assets and security findings from various formats
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
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>
                {importType === 'findings' ? 'Import Security Findings' : 'Import Assets'}
              </CardTitle>
              <CardDescription>
                {importType === 'findings'
                  ? 'Upload or paste security scan results to import findings'
                  : 'Upload or paste asset inventory data to import assets'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="mb-6">
                <Label htmlFor="format">Import Format</Label>
                <Select
                  value={format}
                  onValueChange={(value) => setFormat(value)}
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
                  <p className="mt-2 text-sm text-muted-foreground">
                    {selectedFormat.description}
                  </p>
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
                    className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-10 transition-colors hover:border-primary"
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={handleDrop}
                  >
                    {format === 'xlsx' ? (
                      <FileSpreadsheet className="mb-4 h-12 w-12 text-muted-foreground" />
                    ) : (
                      <Upload className="mb-4 h-12 w-12 text-muted-foreground" />
                    )}
                    <p className="mb-2 text-lg font-medium">
                      Drag and drop a file here
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
                      {loading ? 'Uploading...' : 'Select File'}
                    </Button>
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
                    <Button onClick={handleDataImport} disabled={loading}>
                      {loading ? 'Importing...' : 'Import Data'}
                    </Button>
                  </div>
                </TabsContent>
              </Tabs>

              {error && (
                <div className="mt-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-600">
                  {error}
                </div>
              )}

              {result && (
                <div className="mt-4">
                  <ImportResultCard result={result} />
                </div>
              )}
            </CardContent>
          </Card>
        </div>

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

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Findings CSV Format</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="mb-2 text-sm text-muted-foreground">
                    Required columns:
                  </p>
                  <ul className="list-inside list-disc text-sm text-muted-foreground">
                    <li>title</li>
                    <li>severity (critical, high, medium, low, info)</li>
                    <li>description</li>
                    <li>affected_component</li>
                  </ul>
                  <p className="mt-2 text-sm text-muted-foreground">
                    Optional columns:
                  </p>
                  <ul className="list-inside list-disc text-sm text-muted-foreground">
                    <li>cve_id</li>
                    <li>cvss_score</li>
                    <li>remediation</li>
                    <li>asset_id</li>
                  </ul>
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
                <li>Ensure your data is properly formatted before importing</li>
                <li>Large imports may take several minutes</li>
                <li>Duplicate entries will be updated, not created</li>
                <li>Check the import results for any errors</li>
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
