/**
 * ForgeScan Load Test Script
 *
 * Tests FC360 (compliance) and Reporter modules under heavy load.
 * No external dependencies — uses native fetch().
 *
 * Usage:
 *   npx tsx tests/load-test.ts
 *
 * Environment variables:
 *   LOAD_TEST_URL    — Base URL (default: http://localhost:8787)
 *   LOAD_TEST_TOKEN  — Bearer token for API auth
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL = process.env.LOAD_TEST_URL || 'http://localhost:8787';
const AUTH_TOKEN = process.env.LOAD_TEST_TOKEN || '';

const CONTROLS_COUNT = 10_000;
const POAM_COUNT = 500;
const CONCURRENT_USERS = 100;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface TimedResponse {
  status: number;
  ok: boolean;
  durationMs: number;
  body: unknown;
  error?: string;
}

function headers(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (AUTH_TOKEN) {
    h['Authorization'] = `Bearer ${AUTH_TOKEN}`;
  }
  return h;
}

async function timedFetch(
  url: string,
  options: RequestInit = {}
): Promise<TimedResponse> {
  const start = performance.now();
  try {
    const res = await fetch(url, {
      ...options,
      headers: { ...headers(), ...(options.headers as Record<string, string> || {}) },
    });
    const durationMs = performance.now() - start;
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      // non-JSON response is fine
    }
    return { status: res.status, ok: res.ok, durationMs, body };
  } catch (err: any) {
    const durationMs = performance.now() - start;
    return { status: 0, ok: false, durationMs, body: null, error: err.message };
  }
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

function formatMs(ms: number): string {
  return ms < 1000 ? `${ms.toFixed(1)}ms` : `${(ms / 1000).toFixed(2)}s`;
}

function printStats(label: string, durations: number[], errors: number) {
  const sorted = [...durations].sort((a, b) => a - b);
  const total = durations.length;
  const totalTime = durations.reduce((s, d) => s + d, 0);
  const throughput = total > 0 ? (total / (totalTime / 1000)).toFixed(2) : '0';
  const errorRate = total > 0 ? ((errors / total) * 100).toFixed(1) : '0';

  console.log(`\n  --- ${label} ---`);
  console.log(`  Requests:    ${total}`);
  console.log(`  Errors:      ${errors} (${errorRate}%)`);
  console.log(`  p50:         ${formatMs(percentile(sorted, 50))}`);
  console.log(`  p95:         ${formatMs(percentile(sorted, 95))}`);
  console.log(`  p99:         ${formatMs(percentile(sorted, 99))}`);
  console.log(`  Min:         ${formatMs(sorted[0] || 0)}`);
  console.log(`  Max:         ${formatMs(sorted[sorted.length - 1] || 0)}`);
  console.log(`  Throughput:  ${throughput} req/s`);
}

function estimateMemoryUsage(itemCount: number, avgItemBytes: number): string {
  const totalBytes = itemCount * avgItemBytes;
  if (totalBytes < 1024 * 1024) {
    return `${(totalBytes / 1024).toFixed(1)} KB`;
  }
  return `${(totalBytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function concurrentUsers<T>(
  count: number,
  fn: (userId: number) => Promise<T>
): Promise<T[]> {
  const promises: Promise<T>[] = [];
  for (let i = 0; i < count; i++) {
    promises.push(fn(i));
  }
  return Promise.all(promises);
}

function generateControlPayload(index: number, frameworkId: string) {
  return {
    control_id: `CTL-${String(index).padStart(5, '0')}`,
    name: `Control ${index}`,
    description: `Automated load test control #${index}. This control verifies security requirement ${index} as part of framework compliance.`,
    family: `Family-${Math.floor(index / 50)}`,
    compliance_status: ['compliant', 'non_compliant', 'partially_compliant', 'not_assessed'][index % 4],
    evidence: index % 3 === 0 ? `Evidence artifact for control ${index}` : null,
  };
}

function generatePOAMPayload(index: number) {
  return {
    title: `POA&M Item ${index}`,
    description: `Plan of action for remediation of finding #${index}. Requires patch deployment and validation.`,
    weakness: `CWE-${100 + (index % 500)}`,
    severity: ['critical', 'high', 'medium', 'low'][index % 4],
    status: ['open', 'in_progress', 'completed', 'cancelled'][index % 4],
    milestone: `Milestone ${Math.floor(index / 10)}`,
    due_date: new Date(Date.now() + index * 86400000).toISOString(),
    assigned_to: `user${index % 20}@forgescan.io`,
  };
}

// ---------------------------------------------------------------------------
// Seed Functions
// ---------------------------------------------------------------------------

async function seedFramework(): Promise<string> {
  console.log('  Seeding test framework...');
  const res = await timedFetch(`${BASE_URL}/api/v1/compliance/frameworks`, {
    method: 'POST',
    body: JSON.stringify({
      name: `Load Test Framework ${Date.now()}`,
      version: '1.0',
      description: 'Framework created for load testing FC360',
    }),
  });
  if (!res.ok) {
    console.error('  Failed to create framework:', res.body);
    throw new Error(`Failed to seed framework: ${res.status}`);
  }
  const frameworkId = (res.body as any)?.id || (res.body as any)?.data?.id || 'unknown';
  console.log(`  Framework created: ${frameworkId}`);
  return frameworkId;
}

async function seedControls(count: number, frameworkId: string): Promise<{ durations: number[]; errors: number }> {
  console.log(`  Seeding ${count.toLocaleString()} controls...`);
  const durations: number[] = [];
  let errors = 0;
  const batchSize = 50;

  for (let batch = 0; batch < count; batch += batchSize) {
    const batchEnd = Math.min(batch + batchSize, count);
    const promises: Promise<TimedResponse>[] = [];

    for (let i = batch; i < batchEnd; i++) {
      promises.push(
        timedFetch(`${BASE_URL}/api/v1/compliance/frameworks/${frameworkId}/controls`, {
          method: 'POST',
          body: JSON.stringify(generateControlPayload(i, frameworkId)),
        })
      );
    }

    const results = await Promise.all(promises);
    for (const r of results) {
      durations.push(r.durationMs);
      if (!r.ok) errors++;
    }

    if ((batch + batchSize) % 1000 === 0 || batchEnd === count) {
      console.log(`    ${batchEnd.toLocaleString()} / ${count.toLocaleString()} controls seeded`);
    }
  }

  return { durations, errors };
}

async function seedPOAMs(count: number): Promise<{ durations: number[]; errors: number }> {
  console.log(`  Seeding ${count.toLocaleString()} POA&M items...`);
  const durations: number[] = [];
  let errors = 0;
  const batchSize = 25;

  for (let batch = 0; batch < count; batch += batchSize) {
    const batchEnd = Math.min(batch + batchSize, count);
    const promises: Promise<TimedResponse>[] = [];

    for (let i = batch; i < batchEnd; i++) {
      promises.push(
        timedFetch(`${BASE_URL}/api/v1/compliance/poam`, {
          method: 'POST',
          body: JSON.stringify(generatePOAMPayload(i)),
        })
      );
    }

    const results = await Promise.all(promises);
    for (const r of results) {
      durations.push(r.durationMs);
      if (!r.ok) errors++;
    }

    if ((batch + batchSize) % 100 === 0 || batchEnd === count) {
      console.log(`    ${batchEnd.toLocaleString()} / ${count.toLocaleString()} POA&Ms seeded`);
    }
  }

  return { durations, errors };
}

// ---------------------------------------------------------------------------
// Test Scenarios
// ---------------------------------------------------------------------------

async function testFC360HighVolume(): Promise<void> {
  console.log('\n======================================================');
  console.log('  SCENARIO: FC360 High Volume');
  console.log(`  Controls: ${CONTROLS_COUNT.toLocaleString()}`);
  console.log(`  POA&Ms:   ${POAM_COUNT.toLocaleString()}`);
  console.log(`  Users:    ${CONCURRENT_USERS}`);
  console.log('======================================================');

  // Step 1: Seed framework and controls
  const frameworkId = await seedFramework();
  const controlResult = await seedControls(CONTROLS_COUNT, frameworkId);
  printStats('Control Seeding', controlResult.durations, controlResult.errors);
  console.log(`  Memory estimate (controls): ${estimateMemoryUsage(CONTROLS_COUNT, 512)}`);

  // Step 2: Seed POA&Ms
  const poamResult = await seedPOAMs(POAM_COUNT);
  printStats('POA&M Seeding', poamResult.durations, poamResult.errors);
  console.log(`  Memory estimate (POA&Ms): ${estimateMemoryUsage(POAM_COUNT, 1024)}`);

  // Step 3: Concurrent reads — listing controls with pagination
  console.log(`\n  Running concurrent reads (${CONCURRENT_USERS} users)...`);
  const readDurations: number[] = [];
  let readErrors = 0;

  const readResults = await concurrentUsers(CONCURRENT_USERS, async (userId) => {
    const page = (userId % 10) + 1;
    const res = await timedFetch(
      `${BASE_URL}/api/v1/compliance/frameworks/${frameworkId}/controls?page=${page}&limit=100`
    );
    return res;
  });

  for (const r of readResults) {
    readDurations.push(r.durationMs);
    if (!r.ok) readErrors++;
  }
  printStats('Concurrent Control Reads', readDurations, readErrors);

  // Step 4: Concurrent reads — listing POA&Ms
  const poamReadDurations: number[] = [];
  let poamReadErrors = 0;

  const poamReadResults = await concurrentUsers(CONCURRENT_USERS, async (userId) => {
    const page = (userId % 5) + 1;
    return timedFetch(`${BASE_URL}/api/v1/compliance/poam?page=${page}&limit=50`);
  });

  for (const r of poamReadResults) {
    poamReadDurations.push(r.durationMs);
    if (!r.ok) poamReadErrors++;
  }
  printStats('Concurrent POA&M Reads', poamReadDurations, poamReadErrors);

  // Step 5: Concurrent compliance status updates
  console.log(`\n  Running concurrent status updates (${CONCURRENT_USERS} users)...`);
  const updateDurations: number[] = [];
  let updateErrors = 0;

  const updateResults = await concurrentUsers(CONCURRENT_USERS, async (userId) => {
    const controlIndex = userId % CONTROLS_COUNT;
    return timedFetch(
      `${BASE_URL}/api/v1/compliance/frameworks/${frameworkId}/controls/CTL-${String(controlIndex).padStart(5, '0')}`,
      {
        method: 'PUT',
        body: JSON.stringify({
          compliance_status: ['compliant', 'non_compliant', 'partially_compliant'][userId % 3],
          evidence: `Updated evidence by user ${userId}`,
        }),
      }
    );
  });

  for (const r of updateResults) {
    updateDurations.push(r.durationMs);
    if (!r.ok) updateErrors++;
  }
  printStats('Concurrent Status Updates', updateDurations, updateErrors);
}

async function testReporterMaxSSP(): Promise<void> {
  console.log('\n======================================================');
  console.log('  SCENARIO: Reporter — Max-size SSP Generation');
  console.log('  Includes: all findings + all controls + all evidence');
  console.log('======================================================');

  // Generate a full SSP report (System Security Plan)
  console.log('  Requesting full SSP report generation...');
  const startTime = performance.now();
  const res = await timedFetch(`${BASE_URL}/api/v1/reports/generate`, {
    method: 'POST',
    body: JSON.stringify({
      type: 'ssp',
      format: 'pdf',
      include_findings: true,
      include_controls: true,
      include_evidence: true,
      include_poam: true,
      include_risk_assessment: true,
    }),
  });

  if (res.ok) {
    const reportId = (res.body as any)?.id || (res.body as any)?.data?.id;
    console.log(`  Report generation initiated: ${reportId}`);
    console.log(`  Initial response: ${formatMs(res.durationMs)}`);

    // Poll for report completion
    let completed = false;
    let pollCount = 0;
    const maxPolls = 60;
    const pollDurations: number[] = [];

    while (!completed && pollCount < maxPolls) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      const pollRes = await timedFetch(`${BASE_URL}/api/v1/reports/${reportId}`);
      pollDurations.push(pollRes.durationMs);
      pollCount++;

      const status = (pollRes.body as any)?.status || (pollRes.body as any)?.data?.status;
      if (status === 'completed' || status === 'ready') {
        completed = true;
        const totalTime = performance.now() - startTime;
        console.log(`  Report completed after ${pollCount} polls`);
        console.log(`  Total generation time: ${formatMs(totalTime)}`);
        printStats('Report Status Polling', pollDurations, 0);
      } else if (status === 'failed' || status === 'error') {
        console.error(`  Report generation failed: ${JSON.stringify(pollRes.body)}`);
        break;
      } else {
        if (pollCount % 5 === 0) {
          console.log(`    Polling... (${pollCount}/${maxPolls}) status=${status}`);
        }
      }
    }

    if (!completed) {
      console.warn(`  Report did not complete within ${maxPolls} polls`);
    }

    // Download the completed report to measure transfer size
    if (completed && reportId) {
      console.log('  Downloading completed report...');
      const downloadRes = await timedFetch(`${BASE_URL}/api/v1/reports/${reportId}/download`);
      console.log(`  Download response: ${formatMs(downloadRes.durationMs)} (status: ${downloadRes.status})`);
    }
  } else {
    console.error(`  Failed to initiate report: ${res.status}`, res.body);
  }

  // Estimate memory for max SSP
  const estimatedFindings = 5000;
  const estimatedControls = CONTROLS_COUNT;
  const estimatedEvidence = 2000;
  console.log(`\n  Memory estimates for max SSP:`);
  console.log(`    Findings payload:  ${estimateMemoryUsage(estimatedFindings, 2048)}`);
  console.log(`    Controls payload:  ${estimateMemoryUsage(estimatedControls, 512)}`);
  console.log(`    Evidence payload:  ${estimateMemoryUsage(estimatedEvidence, 4096)}`);
  console.log(`    Total estimated:   ${estimateMemoryUsage(
    estimatedFindings * 2048 + estimatedControls * 512 + estimatedEvidence * 4096, 1
  )}`);
}

async function testConcurrentReportGeneration(): Promise<void> {
  console.log('\n======================================================');
  console.log('  SCENARIO: Concurrent Report Generation');
  console.log(`  Concurrent report requests: ${CONCURRENT_USERS}`);
  console.log('======================================================');

  const reportTypes = ['ssp', 'poam', 'risk_assessment', 'findings_summary', 'executive_summary'];

  console.log('  Submitting concurrent report generation requests...');
  const genDurations: number[] = [];
  let genErrors = 0;

  const results = await concurrentUsers(CONCURRENT_USERS, async (userId) => {
    const reportType = reportTypes[userId % reportTypes.length];
    return timedFetch(`${BASE_URL}/api/v1/reports/generate`, {
      method: 'POST',
      body: JSON.stringify({
        type: reportType,
        format: userId % 2 === 0 ? 'pdf' : 'json',
        include_findings: true,
        include_controls: userId % 3 !== 0,
        include_evidence: userId % 5 === 0,
      }),
    });
  });

  for (const r of results) {
    genDurations.push(r.durationMs);
    if (!r.ok) genErrors++;
  }
  printStats('Concurrent Report Submissions', genDurations, genErrors);

  // Concurrent report listing (simulates users checking report status)
  console.log(`\n  Simulating ${CONCURRENT_USERS} users listing reports...`);
  const listDurations: number[] = [];
  let listErrors = 0;

  const listResults = await concurrentUsers(CONCURRENT_USERS, async (userId) => {
    const page = (userId % 5) + 1;
    return timedFetch(`${BASE_URL}/api/v1/reports?page=${page}&limit=20`);
  });

  for (const r of listResults) {
    listDurations.push(r.durationMs);
    if (!r.ok) listErrors++;
  }
  printStats('Concurrent Report Listings', listDurations, listErrors);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('======================================================');
  console.log('  ForgeScan Load Test');
  console.log(`  Target: ${BASE_URL}`);
  console.log(`  Auth:   ${AUTH_TOKEN ? 'Bearer token provided' : 'No token (unauthenticated)'}`);
  console.log(`  Time:   ${new Date().toISOString()}`);
  console.log('======================================================');

  // Verify connectivity
  console.log('\n  Verifying connectivity...');
  const healthCheck = await timedFetch(`${BASE_URL}/api/v1/health`);
  if (!healthCheck.ok && healthCheck.status !== 404) {
    console.error(`  Cannot reach ${BASE_URL}: status=${healthCheck.status} error=${healthCheck.error}`);
    console.error('  Aborting load test.');
    process.exit(1);
  }
  console.log(`  Health check: ${healthCheck.status} (${formatMs(healthCheck.durationMs)})`);

  const overallStart = performance.now();

  try {
    await testFC360HighVolume();
  } catch (err: any) {
    console.error(`\n  FC360 scenario failed: ${err.message}`);
  }

  try {
    await testReporterMaxSSP();
  } catch (err: any) {
    console.error(`\n  Reporter Max SSP scenario failed: ${err.message}`);
  }

  try {
    await testConcurrentReportGeneration();
  } catch (err: any) {
    console.error(`\n  Concurrent Report scenario failed: ${err.message}`);
  }

  const overallDuration = performance.now() - overallStart;
  console.log('\n======================================================');
  console.log('  LOAD TEST COMPLETE');
  console.log(`  Total duration: ${formatMs(overallDuration)}`);
  console.log('======================================================');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
