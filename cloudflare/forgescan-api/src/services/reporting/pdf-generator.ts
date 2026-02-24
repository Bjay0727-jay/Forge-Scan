// PDF Report Generator using pdf-lib
// Generates executive summary, findings, compliance, and asset reports as PDF

import { PDFDocument, StandardFonts, rgb, PDFPage, PDFFont } from 'pdf-lib';

// Color constants
const COLORS = {
  primary: rgb(0.09, 0.09, 0.44),      // Dark blue header
  secondary: rgb(0.4, 0.4, 0.4),        // Gray text
  critical: rgb(0.75, 0.05, 0.05),      // Red
  high: rgb(0.9, 0.4, 0.0),             // Orange
  medium: rgb(0.85, 0.65, 0.0),         // Yellow-orange
  low: rgb(0.0, 0.5, 0.25),             // Green
  info: rgb(0.3, 0.3, 0.8),             // Blue
  white: rgb(1, 1, 1),
  lightGray: rgb(0.95, 0.95, 0.95),
  black: rgb(0, 0, 0),
  headerBg: rgb(0.12, 0.12, 0.48),
  tableBorder: rgb(0.8, 0.8, 0.8),
};

function severityColor(severity: string) {
  switch (severity?.toLowerCase()) {
    case 'critical': return COLORS.critical;
    case 'high': return COLORS.high;
    case 'medium': return COLORS.medium;
    case 'low': return COLORS.low;
    default: return COLORS.info;
  }
}

interface PageContext {
  doc: PDFDocument;
  page: PDFPage;
  font: PDFFont;
  boldFont: PDFFont;
  y: number;
  pageNum: number;
  margin: number;
  width: number;
  height: number;
}

function newPage(ctx: PageContext): PageContext {
  const page = ctx.doc.addPage([612, 792]); // Letter size
  ctx.pageNum++;
  // Footer
  page.drawText(`ForgeScan Report | Page ${ctx.pageNum}`, {
    x: ctx.margin,
    y: 20,
    size: 8,
    font: ctx.font,
    color: COLORS.secondary,
  });
  page.drawText(new Date().toISOString().split('T')[0], {
    x: 612 - ctx.margin - 60,
    y: 20,
    size: 8,
    font: ctx.font,
    color: COLORS.secondary,
  });
  return { ...ctx, page, y: 792 - ctx.margin };
}

function ensureSpace(ctx: PageContext, needed: number): PageContext {
  if (ctx.y - needed < 50) {
    return newPage(ctx);
  }
  return ctx;
}

function drawTitle(ctx: PageContext, title: string): PageContext {
  ctx = ensureSpace(ctx, 40);
  // Blue header bar
  ctx.page.drawRectangle({
    x: 0,
    y: ctx.y - 5,
    width: 612,
    height: 35,
    color: COLORS.headerBg,
  });
  ctx.page.drawText(title, {
    x: ctx.margin,
    y: ctx.y + 5,
    size: 16,
    font: ctx.boldFont,
    color: COLORS.white,
  });
  ctx.y -= 50;
  return ctx;
}

function drawSectionHeader(ctx: PageContext, text: string): PageContext {
  ctx = ensureSpace(ctx, 30);
  ctx.page.drawLine({
    start: { x: ctx.margin, y: ctx.y + 5 },
    end: { x: 612 - ctx.margin, y: ctx.y + 5 },
    thickness: 1,
    color: COLORS.primary,
  });
  ctx.page.drawText(text, {
    x: ctx.margin,
    y: ctx.y - 12,
    size: 12,
    font: ctx.boldFont,
    color: COLORS.primary,
  });
  ctx.y -= 28;
  return ctx;
}

function drawKeyValue(ctx: PageContext, key: string, value: string, indent = 0): PageContext {
  ctx = ensureSpace(ctx, 16);
  ctx.page.drawText(`${key}:`, {
    x: ctx.margin + indent,
    y: ctx.y,
    size: 10,
    font: ctx.boldFont,
    color: COLORS.black,
  });
  ctx.page.drawText(value, {
    x: ctx.margin + indent + ctx.boldFont.widthOfTextAtSize(`${key}: `, 10),
    y: ctx.y,
    size: 10,
    font: ctx.font,
    color: COLORS.secondary,
  });
  ctx.y -= 16;
  return ctx;
}

function drawText(ctx: PageContext, text: string, size = 10, color = COLORS.black): PageContext {
  ctx = ensureSpace(ctx, size + 4);
  // Wrap long text
  const maxWidth = 612 - 2 * ctx.margin;
  const words = text.split(' ');
  let line = '';
  for (const word of words) {
    const testLine = line ? `${line} ${word}` : word;
    if (ctx.font.widthOfTextAtSize(testLine, size) > maxWidth) {
      ctx.page.drawText(line, { x: ctx.margin, y: ctx.y, size, font: ctx.font, color });
      ctx.y -= size + 4;
      ctx = ensureSpace(ctx, size + 4);
      line = word;
    } else {
      line = testLine;
    }
  }
  if (line) {
    ctx.page.drawText(line, { x: ctx.margin, y: ctx.y, size, font: ctx.font, color });
    ctx.y -= size + 4;
  }
  return ctx;
}

// ---- Cover Page ----
function drawCoverPage(ctx: PageContext, reportTitle: string, reportType: string): PageContext {
  // Full-page blue header block
  ctx.page.drawRectangle({
    x: 0, y: 792 - 280, width: 612, height: 280, color: COLORS.headerBg,
  });

  // Logo text
  ctx.page.drawText('FORGESCAN', {
    x: ctx.margin, y: 792 - 80, size: 32, font: ctx.boldFont, color: COLORS.white,
  });
  ctx.page.drawText('Vulnerability Management Platform', {
    x: ctx.margin, y: 792 - 110, size: 14, font: ctx.font, color: rgb(0.7, 0.7, 1),
  });

  // Report title
  ctx.page.drawText(reportTitle, {
    x: ctx.margin, y: 792 - 180, size: 24, font: ctx.boldFont, color: COLORS.white,
  });
  ctx.page.drawText(`${reportType} Report`, {
    x: ctx.margin, y: 792 - 210, size: 14, font: ctx.font, color: rgb(0.8, 0.8, 1),
  });

  // Date
  const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  ctx.page.drawText(`Generated: ${dateStr}`, {
    x: ctx.margin, y: 792 - 250, size: 11, font: ctx.font, color: rgb(0.7, 0.7, 1),
  });

  // Confidentiality notice
  ctx.page.drawText('CONFIDENTIAL', {
    x: ctx.margin, y: 200, size: 12, font: ctx.boldFont, color: COLORS.critical,
  });
  ctx.page.drawText('This document contains sensitive security information. Distribution is restricted to authorized personnel only.', {
    x: ctx.margin, y: 180, size: 9, font: ctx.font, color: COLORS.secondary,
  });

  ctx.y = 160;
  return ctx;
}

// ---- Table drawing ----
function drawTableRow(
  ctx: PageContext,
  cols: { text: string; width: number; color?: typeof COLORS.black; bold?: boolean }[],
  isHeader = false,
  bgColor?: typeof COLORS.lightGray
): PageContext {
  ctx = ensureSpace(ctx, 18);

  const rowHeight = 18;
  if (bgColor || isHeader) {
    ctx.page.drawRectangle({
      x: ctx.margin - 2,
      y: ctx.y - 4,
      width: 612 - 2 * ctx.margin + 4,
      height: rowHeight,
      color: isHeader ? COLORS.headerBg : bgColor!,
    });
  }

  let x = ctx.margin;
  for (const col of cols) {
    const truncatedText = truncate(col.text, col.width, ctx.font, 9);
    ctx.page.drawText(truncatedText, {
      x,
      y: ctx.y,
      size: 9,
      font: (col.bold || isHeader) ? ctx.boldFont : ctx.font,
      color: isHeader ? COLORS.white : (col.color || COLORS.black),
    });
    x += col.width;
  }

  ctx.y -= rowHeight;
  return ctx;
}

function truncate(text: string, maxWidth: number, font: PDFFont, size: number): string {
  if (!text) return '';
  if (font.widthOfTextAtSize(text, size) <= maxWidth - 4) return text;
  let t = text;
  while (t.length > 0 && font.widthOfTextAtSize(t + '...', size) > maxWidth - 4) {
    t = t.slice(0, -1);
  }
  return t + '...';
}

// ---- Public generators ----

export async function generateExecutivePDF(data: {
  totals: { assets: number; open_findings: number; fixed_findings: number; new_findings_period: number; remediation_rate: number };
  risk_score: { current: number; grade: string };
  severity_breakdown: { severity: string; count: number }[];
  top_risks: { title: string; severity: string; affected_assets: number; frs_score: number | null }[];
  recommendations: string[];
  period: { start: string; end: string };
}): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const boldFont = await doc.embedFont(StandardFonts.HelveticaBold);

  let ctx: PageContext = {
    doc, page: doc.addPage([612, 792]), font, boldFont,
    y: 792 - 40, pageNum: 1, margin: 50, width: 612, height: 792,
  };

  // Cover
  ctx = drawCoverPage(ctx, 'Executive Summary', 'Security Posture');

  // New page for content
  ctx = newPage(ctx);

  // Risk Overview
  ctx = drawSectionHeader(ctx, 'Risk Overview');
  ctx = drawKeyValue(ctx, 'Risk Score', `${data.risk_score.current}/100 (Grade: ${data.risk_score.grade})`);
  ctx = drawKeyValue(ctx, 'Reporting Period', `${data.period.start} to ${data.period.end}`);
  ctx = drawKeyValue(ctx, 'Total Assets', String(data.totals.assets));
  ctx = drawKeyValue(ctx, 'Open Findings', String(data.totals.open_findings));
  ctx = drawKeyValue(ctx, 'Fixed Findings', String(data.totals.fixed_findings));
  ctx = drawKeyValue(ctx, 'New Findings (Period)', String(data.totals.new_findings_period));
  ctx = drawKeyValue(ctx, 'Remediation Rate', `${data.totals.remediation_rate}%`);
  ctx.y -= 10;

  // Severity Breakdown
  ctx = drawSectionHeader(ctx, 'Severity Breakdown');
  ctx = drawTableRow(ctx, [
    { text: 'Severity', width: 150 },
    { text: 'Count', width: 100 },
    { text: 'Percentage', width: 150 },
  ], true);

  const totalFindings = data.severity_breakdown.reduce((s, r) => s + r.count, 0);
  for (let i = 0; i < data.severity_breakdown.length; i++) {
    const row = data.severity_breakdown[i];
    const pct = totalFindings > 0 ? Math.round((row.count / totalFindings) * 100) : 0;
    ctx = drawTableRow(ctx, [
      { text: row.severity.toUpperCase(), width: 150, color: severityColor(row.severity), bold: true },
      { text: String(row.count), width: 100 },
      { text: `${pct}%`, width: 150 },
    ], false, i % 2 === 0 ? COLORS.lightGray : undefined);
  }
  ctx.y -= 10;

  // Top Risks
  if (data.top_risks.length > 0) {
    ctx = drawSectionHeader(ctx, 'Top Risks');
    ctx = drawTableRow(ctx, [
      { text: 'Finding', width: 230 },
      { text: 'Severity', width: 80 },
      { text: 'Affected Assets', width: 100 },
      { text: 'FRS Score', width: 80 },
    ], true);

    for (let i = 0; i < Math.min(data.top_risks.length, 15); i++) {
      const risk = data.top_risks[i];
      ctx = drawTableRow(ctx, [
        { text: risk.title || 'Unknown', width: 230 },
        { text: risk.severity.toUpperCase(), width: 80, color: severityColor(risk.severity), bold: true },
        { text: String(risk.affected_assets), width: 100 },
        { text: risk.frs_score != null ? String(risk.frs_score.toFixed(1)) : 'N/A', width: 80 },
      ], false, i % 2 === 0 ? COLORS.lightGray : undefined);
    }
    ctx.y -= 10;
  }

  // Recommendations
  if (data.recommendations.length > 0) {
    ctx = drawSectionHeader(ctx, 'Recommendations');
    for (const rec of data.recommendations) {
      ctx = drawText(ctx, `• ${rec}`, 10, COLORS.black);
    }
  }

  return doc.save();
}

export async function generateFindingsPDF(data: {
  summary: { total: number; critical: number; high: number; medium: number; low: number; info: number; affected_assets: number };
  findings: { title: string; severity: string; state: string; hostname: string; vendor: string; cve_id: string | null; cvss_score: number | null; first_seen: string }[];
  filters: Record<string, string | undefined>;
}): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const boldFont = await doc.embedFont(StandardFonts.HelveticaBold);

  let ctx: PageContext = {
    doc, page: doc.addPage([612, 792]), font, boldFont,
    y: 792 - 40, pageNum: 1, margin: 50, width: 612, height: 792,
  };

  ctx = drawCoverPage(ctx, 'Findings Report', 'Vulnerability Details');
  ctx = newPage(ctx);

  // Summary
  ctx = drawSectionHeader(ctx, 'Summary');
  ctx = drawKeyValue(ctx, 'Total Findings', String(data.summary.total));
  ctx = drawKeyValue(ctx, 'Critical', String(data.summary.critical));
  ctx = drawKeyValue(ctx, 'High', String(data.summary.high));
  ctx = drawKeyValue(ctx, 'Medium', String(data.summary.medium));
  ctx = drawKeyValue(ctx, 'Low', String(data.summary.low));
  ctx = drawKeyValue(ctx, 'Informational', String(data.summary.info));
  ctx = drawKeyValue(ctx, 'Affected Assets', String(data.summary.affected_assets));
  ctx.y -= 10;

  // Findings table
  ctx = drawSectionHeader(ctx, 'Findings Detail');
  ctx = drawTableRow(ctx, [
    { text: 'Title', width: 180 },
    { text: 'Severity', width: 65 },
    { text: 'Host', width: 100 },
    { text: 'CVE', width: 90 },
    { text: 'CVSS', width: 50 },
  ], true);

  for (let i = 0; i < data.findings.length; i++) {
    const f = data.findings[i];
    ctx = drawTableRow(ctx, [
      { text: f.title || 'Unknown', width: 180 },
      { text: (f.severity || 'info').toUpperCase(), width: 65, color: severityColor(f.severity), bold: true },
      { text: f.hostname || '-', width: 100 },
      { text: f.cve_id || '-', width: 90 },
      { text: f.cvss_score != null ? String(f.cvss_score) : '-', width: 50 },
    ], false, i % 2 === 0 ? COLORS.lightGray : undefined);
  }

  return doc.save();
}

export async function generateCompliancePDF(data: {
  frameworks: { name: string; version: string; compliance_percentage: number; total_controls: number; compliant: number; non_compliant: number; partial: number; not_assessed: number }[];
  gaps: { framework_name: string; control_id: string; control_name: string; status: string; family: string }[];
}): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const boldFont = await doc.embedFont(StandardFonts.HelveticaBold);

  let ctx: PageContext = {
    doc, page: doc.addPage([612, 792]), font, boldFont,
    y: 792 - 40, pageNum: 1, margin: 50, width: 612, height: 792,
  };

  ctx = drawCoverPage(ctx, 'Compliance Report', 'Framework Assessment');
  ctx = newPage(ctx);

  // Framework Overview
  ctx = drawSectionHeader(ctx, 'Framework Overview');
  ctx = drawTableRow(ctx, [
    { text: 'Framework', width: 160 },
    { text: 'Version', width: 60 },
    { text: 'Compliance', width: 80 },
    { text: 'Compliant', width: 70 },
    { text: 'Non-Comp', width: 65 },
    { text: 'Partial', width: 55 },
  ], true);

  for (let i = 0; i < data.frameworks.length; i++) {
    const fw = data.frameworks[i];
    const compColor = fw.compliance_percentage >= 80 ? COLORS.low : fw.compliance_percentage >= 50 ? COLORS.medium : COLORS.critical;
    ctx = drawTableRow(ctx, [
      { text: fw.name, width: 160, bold: true },
      { text: fw.version || '-', width: 60 },
      { text: `${fw.compliance_percentage}%`, width: 80, color: compColor, bold: true },
      { text: String(fw.compliant), width: 70 },
      { text: String(fw.non_compliant), width: 65, color: fw.non_compliant > 0 ? COLORS.critical : COLORS.black },
      { text: String(fw.partial), width: 55 },
    ], false, i % 2 === 0 ? COLORS.lightGray : undefined);
  }
  ctx.y -= 10;

  // Gap Analysis
  if (data.gaps.length > 0) {
    ctx = drawSectionHeader(ctx, 'Gap Analysis - Non-Compliant Controls');
    ctx = drawTableRow(ctx, [
      { text: 'Control ID', width: 100 },
      { text: 'Name', width: 200 },
      { text: 'Family', width: 120 },
      { text: 'Status', width: 80 },
    ], true);

    for (let i = 0; i < data.gaps.length; i++) {
      const gap = data.gaps[i];
      ctx = drawTableRow(ctx, [
        { text: gap.control_id, width: 100, bold: true },
        { text: gap.control_name || '-', width: 200 },
        { text: gap.family || '-', width: 120 },
        { text: gap.status, width: 80, color: gap.status === 'non_compliant' ? COLORS.critical : COLORS.medium },
      ], false, i % 2 === 0 ? COLORS.lightGray : undefined);
    }
  }

  return doc.save();
}

export async function generateAssetsPDF(data: {
  summary: { total_assets: number; asset_types: number; network_zones: number };
  breakdown_by_type: { asset_type: string; count: number }[];
  assets: { hostname: string; ip_addresses: string; os: string; asset_type: string; open_findings: number; critical_findings: number; high_findings: number }[];
}): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const boldFont = await doc.embedFont(StandardFonts.HelveticaBold);

  let ctx: PageContext = {
    doc, page: doc.addPage([612, 792]), font, boldFont,
    y: 792 - 40, pageNum: 1, margin: 50, width: 612, height: 792,
  };

  ctx = drawCoverPage(ctx, 'Asset Inventory', 'Infrastructure Overview');
  ctx = newPage(ctx);

  // Summary
  ctx = drawSectionHeader(ctx, 'Summary');
  ctx = drawKeyValue(ctx, 'Total Assets', String(data.summary.total_assets));
  ctx = drawKeyValue(ctx, 'Asset Types', String(data.summary.asset_types));
  ctx = drawKeyValue(ctx, 'Network Zones', String(data.summary.network_zones));
  ctx.y -= 10;

  // Breakdown by type
  if (data.breakdown_by_type.length > 0) {
    ctx = drawSectionHeader(ctx, 'Breakdown by Type');
    ctx = drawTableRow(ctx, [
      { text: 'Asset Type', width: 200 },
      { text: 'Count', width: 100 },
    ], true);
    for (let i = 0; i < data.breakdown_by_type.length; i++) {
      const bt = data.breakdown_by_type[i];
      ctx = drawTableRow(ctx, [
        { text: bt.asset_type || 'Unknown', width: 200 },
        { text: String(bt.count), width: 100 },
      ], false, i % 2 === 0 ? COLORS.lightGray : undefined);
    }
    ctx.y -= 10;
  }

  // Asset details
  ctx = drawSectionHeader(ctx, 'Asset Details');
  ctx = drawTableRow(ctx, [
    { text: 'Hostname', width: 130 },
    { text: 'IP', width: 100 },
    { text: 'OS', width: 100 },
    { text: 'Type', width: 70 },
    { text: 'Findings', width: 60 },
    { text: 'Crit/High', width: 60 },
  ], true);

  for (let i = 0; i < data.assets.length; i++) {
    const a = data.assets[i];
    ctx = drawTableRow(ctx, [
      { text: a.hostname || '-', width: 130 },
      { text: a.ip_addresses || '-', width: 100 },
      { text: a.os || '-', width: 100 },
      { text: a.asset_type || '-', width: 70 },
      { text: String(a.open_findings || 0), width: 60 },
      { text: `${a.critical_findings || 0}/${a.high_findings || 0}`, width: 60, color: (a.critical_findings || 0) > 0 ? COLORS.critical : COLORS.black },
    ], false, i % 2 === 0 ? COLORS.lightGray : undefined);
  }

  return doc.save();
}
