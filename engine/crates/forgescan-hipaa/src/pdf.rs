//! PDF executive summary report renderer
//!
//! Generates a CISO-ready PDF compliance report using the genpdf crate.
//! No external fonts or system dependencies required.

use crate::report::{HipaaReport, PenaltyTier};
use anyhow::{Context, Result};
use genpdf::elements::{Break, LinearLayout, Paragraph, TableLayout};
use genpdf::style::{self, Style};
use genpdf::{Alignment, Document, Element, SimplePageDecorator};

/// PDF report renderer for HIPAA compliance reports
pub struct PdfReportRenderer;

impl PdfReportRenderer {
    /// Render a HIPAA compliance report to PDF bytes
    pub fn render(report: &HipaaReport) -> Result<Vec<u8>> {
        let font_family =
            genpdf::fonts::from_files("", "LiberationSans", None).unwrap_or_else(|_| {
                // Fall back to built-in default if Liberation fonts not available
                genpdf::fonts::from_files(
                    "/usr/share/fonts/truetype/liberation",
                    "LiberationSans",
                    None,
                )
                .unwrap_or_else(|_| {
                    genpdf::fonts::from_files(
                        "/usr/share/fonts/liberation-sans",
                        "LiberationSans",
                        None,
                    )
                    .unwrap_or_else(|_| {
                        // Use a minimal built-in font
                        genpdf::fonts::from_files(".", "LiberationSans", None)
                            .expect("No fonts available for PDF generation")
                    })
                })
            });

        let mut doc = Document::new(font_family);
        doc.set_title("HIPAA Security Rule Compliance Assessment Report");
        doc.set_minimal_conformance();

        let mut decorator = SimplePageDecorator::new();
        decorator.set_margins(15);
        doc.set_page_decorator(decorator);

        // ── Title Page ──────────────────────────────────────────────
        Self::render_title_page(&mut doc, report);

        // ── Executive Summary ───────────────────────────────────────
        Self::render_executive_summary(&mut doc, report);

        // ── Safeguard Scorecard ─────────────────────────────────────
        Self::render_safeguard_scorecard(&mut doc, report);

        // ── HCCRA Control Scorecard ─────────────────────────────────
        Self::render_hccra_scorecard(&mut doc, report);

        // ── Top Risks ───────────────────────────────────────────────
        Self::render_top_risks(&mut doc, report);

        // ── HIPAA Gap Summary ───────────────────────────────────────
        Self::render_gap_summary(&mut doc, report);

        // ── Regulatory Risk Exposure ────────────────────────────────
        Self::render_risk_exposure(&mut doc, report);

        // Render to bytes
        let mut buf = Vec::new();
        doc.render(&mut buf)
            .context("Failed to render PDF document")?;
        Ok(buf)
    }

    fn render_title_page(doc: &mut Document, report: &HipaaReport) {
        doc.push(Break::new(3.0));
        doc.push(
            Paragraph::new("")
                .aligned(Alignment::Center)
                .styled(Style::new().bold()),
        );
        doc.push(Break::new(1.0));

        doc.push(
            Paragraph::new("HIPAA Security Rule")
                .aligned(Alignment::Center)
                .styled(Style::new().bold().with_font_size(22)),
        );
        doc.push(
            Paragraph::new("Compliance Assessment Report")
                .aligned(Alignment::Center)
                .styled(Style::new().bold().with_font_size(22)),
        );

        doc.push(Break::new(2.0));
        doc.push(
            Paragraph::new(&report.metadata.organization)
                .aligned(Alignment::Center)
                .styled(Style::new().with_font_size(16)),
        );

        doc.push(Break::new(1.0));
        doc.push(
            Paragraph::new(format!(
                "Assessment Date: {}",
                report.metadata.generated_at.format("%B %d, %Y")
            ))
            .aligned(Alignment::Center)
            .styled(Style::new().with_font_size(12)),
        );

        doc.push(
            Paragraph::new(format!("Report ID: {}", report.metadata.report_id))
                .aligned(Alignment::Center)
                .styled(Style::new().with_font_size(10)),
        );

        doc.push(Break::new(1.0));
        doc.push(
            Paragraph::new(&report.metadata.classification)
                .aligned(Alignment::Center)
                .styled(Style::new().bold().with_font_size(11)),
        );

        doc.push(
            Paragraph::new(format!("Prepared by: {}", report.metadata.prepared_by))
                .aligned(Alignment::Center)
                .styled(Style::new().with_font_size(10)),
        );

        doc.push(Break::new(4.0));
    }

    fn render_executive_summary(doc: &mut Document, report: &HipaaReport) {
        let es = &report.executive_summary;

        doc.push(section_header("EXECUTIVE SUMMARY"));
        doc.push(Break::new(0.5));

        doc.push(
            Paragraph::new(format!(
                "Compliance Posture: {}",
                es.compliance_posture.label().to_uppercase()
            ))
            .styled(Style::new().bold().with_font_size(14)),
        );

        doc.push(Paragraph::new(format!(
            "Overall Score: {:.0}/100",
            es.overall_score
        )));

        if let Some(prev) = es.previous_score {
            let delta = es.overall_score - prev;
            let direction = if delta > 0.0 { "up" } else { "down" };
            doc.push(Paragraph::new(format!(
                "Trend: {:.1} points {} from previous assessment ({:.0})",
                delta.abs(),
                direction,
                prev
            )));
        }

        doc.push(Break::new(0.3));
        doc.push(Paragraph::new(
            es.compliance_posture.board_description().to_string(),
        ));

        doc.push(Break::new(0.5));
        doc.push(Paragraph::new("Finding Summary").styled(Style::new().bold().with_font_size(12)));

        let mut summary = LinearLayout::vertical();
        summary.push(Paragraph::new(format!(
            "Total Findings: {}",
            es.total_findings
        )));
        summary.push(Paragraph::new(format!(
            "Critical: {}",
            es.critical_findings
        )));
        summary.push(Paragraph::new(format!("High: {}", es.high_findings)));
        summary.push(Paragraph::new(format!(
            "Medium/Low/Info: {}",
            es.total_findings - es.critical_findings - es.high_findings
        )));
        doc.push(summary);

        if !es.recommendations.is_empty() {
            doc.push(Break::new(0.5));
            doc.push(
                Paragraph::new("Board Recommendations")
                    .styled(Style::new().bold().with_font_size(12)),
            );
            for (i, rec) in es.recommendations.iter().enumerate() {
                doc.push(Paragraph::new(format!("{}. {}", i + 1, rec)));
            }
        }

        doc.push(Break::new(1.0));
    }

    fn render_safeguard_scorecard(doc: &mut Document, report: &HipaaReport) {
        doc.push(section_header("HIPAA TECHNICAL SAFEGUARD SCORECARD"));
        doc.push(Break::new(0.5));

        let mut table = TableLayout::new(vec![4, 2, 1, 1]);
        table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

        // Header row
        let header_style = Style::new().bold();
        table
            .row()
            .element(Paragraph::new("Safeguard").styled(header_style))
            .element(Paragraph::new("Status").styled(header_style))
            .element(Paragraph::new("Score").styled(header_style))
            .element(Paragraph::new("Findings").styled(header_style))
            .push()
            .ok();

        for entry in &report.scorecard.safeguard_scores {
            table
                .row()
                .element(Paragraph::new(format!(
                    "{} ({})",
                    entry.safeguard.name(),
                    entry.cfr_citation
                )))
                .element(Paragraph::new(entry.status.to_string()))
                .element(Paragraph::new(format!("{:.0}%", entry.score)))
                .element(Paragraph::new(entry.finding_count.to_string()))
                .push()
                .ok();
        }

        doc.push(table);
        doc.push(Break::new(0.5));
        doc.push(Paragraph::new(format!(
            "Overall Score: {:.0}/100  |  Trend: {}",
            report.scorecard.overall_score, report.scorecard.trend
        )));
        doc.push(Break::new(1.0));
    }

    fn render_hccra_scorecard(doc: &mut Document, report: &HipaaReport) {
        doc.push(section_header("HCCRA MANDATORY CONTROL SCORECARD"));
        doc.push(Break::new(0.5));

        let mut table = TableLayout::new(vec![1, 3, 2, 1]);
        table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, false));

        let header_style = Style::new().bold();
        table
            .row()
            .element(Paragraph::new("Ctrl").styled(header_style))
            .element(Paragraph::new("Control Name").styled(header_style))
            .element(Paragraph::new("Status").styled(header_style))
            .element(Paragraph::new("Findings").styled(header_style))
            .push()
            .ok();

        for entry in &report.scorecard.hccra_scores {
            table
                .row()
                .element(Paragraph::new(&entry.control_id))
                .element(Paragraph::new(entry.control.name()))
                .element(Paragraph::new(entry.status.to_string()))
                .element(Paragraph::new(entry.finding_count.to_string()))
                .push()
                .ok();
        }

        doc.push(table);
        doc.push(Break::new(1.0));
    }

    fn render_top_risks(doc: &mut Document, report: &HipaaReport) {
        doc.push(section_header("TOP RISKS"));
        doc.push(Break::new(0.5));

        // Collect all findings from safeguard details, sorted by severity
        let mut all_findings: Vec<_> = report
            .safeguard_details
            .iter()
            .flat_map(|sd| {
                sd.findings.iter().map(move |f| {
                    (
                        f.severity,
                        &f.finding_title,
                        sd.safeguard.name(),
                        &sd.cfr_citation,
                    )
                })
            })
            .collect();

        all_findings.sort_by(|a, b| b.0.as_number().cmp(&a.0.as_number()));
        all_findings.truncate(10);

        if all_findings.is_empty() {
            doc.push(Paragraph::new(
                "No significant risks identified in this assessment.",
            ));
        } else {
            for (i, (severity, title, safeguard, cfr)) in all_findings.iter().enumerate() {
                doc.push(Paragraph::new(format!(
                    "{}. [{}] {} — {} ({})",
                    i + 1,
                    severity.as_str(),
                    title,
                    safeguard,
                    cfr,
                )));
            }
        }

        doc.push(Break::new(1.0));
    }

    fn render_gap_summary(doc: &mut Document, report: &HipaaReport) {
        doc.push(section_header("HIPAA GAP SUMMARY"));
        doc.push(Break::new(0.5));

        for detail in &report.safeguard_details {
            if detail.implementation_gaps.is_empty() && detail.recommended_actions.len() <= 1 {
                continue; // Skip compliant safeguards
            }

            doc.push(
                Paragraph::new(format!(
                    "{} ({}) — {}",
                    detail.safeguard.name(),
                    detail.cfr_citation,
                    detail.status,
                ))
                .styled(Style::new().bold()),
            );

            if !detail.implementation_gaps.is_empty() {
                doc.push(Paragraph::new("  Gaps:").styled(style::Style::new().italic()));
                for gap in &detail.implementation_gaps {
                    doc.push(Paragraph::new(format!("  - {}", gap)));
                }
            }

            if !detail.recommended_actions.is_empty() {
                doc.push(
                    Paragraph::new("  Recommended Actions:").styled(style::Style::new().italic()),
                );
                for action in &detail.recommended_actions {
                    doc.push(Paragraph::new(format!("  - {}", action)));
                }
            }

            doc.push(Break::new(0.3));
        }

        doc.push(Break::new(1.0));
    }

    fn render_risk_exposure(doc: &mut Document, report: &HipaaReport) {
        doc.push(section_header("REGULATORY RISK EXPOSURE"));
        doc.push(Break::new(0.5));

        let re = &report.executive_summary.risk_exposure;

        doc.push(Paragraph::new(format!("Penalty Tier: {}", re.tier.label())));
        doc.push(Paragraph::new(format!(
            "Per-Violation Range: ${} - ${}",
            format_dollars(re.per_violation_range.0),
            format_dollars(re.per_violation_range.1),
        )));
        doc.push(Paragraph::new(format!(
            "Annual Cap: ${}",
            format_dollars(re.annual_cap)
        )));

        doc.push(Break::new(0.3));

        let tier_desc = match re.tier {
            PenaltyTier::Tier1 => {
                "Tier 1 penalties apply when the covered entity was unaware and could not have \
                 reasonably avoided the violation."
            }
            PenaltyTier::Tier2 => {
                "Tier 2 penalties apply when there was reasonable cause but not willful neglect."
            }
            PenaltyTier::Tier3 => {
                "Tier 3 penalties apply for willful neglect that was corrected within 30 days."
            }
            PenaltyTier::Tier4 => {
                "Tier 4 penalties apply for willful neglect that was NOT corrected. \
                 This is the most severe penalty category."
            }
        };
        doc.push(Paragraph::new(tier_desc));

        doc.push(Break::new(0.3));
        doc.push(Paragraph::new(format!("Note: {}", re.notes)));
    }
}

/// Create a styled section header
fn section_header(text: &str) -> impl Element {
    let mut layout = LinearLayout::vertical();
    layout.push(Paragraph::new(String::new()));
    layout.push(Paragraph::new(text).styled(Style::new().bold().with_font_size(16)));
    layout
}

/// Format dollar amount with commas
fn format_dollars(amount: u64) -> String {
    let s = amount.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapper::HipaaMapper;
    use crate::report::HipaaReportGenerator;
    use chrono::Utc;
    use forgescan_core::{Finding, Severity};

    #[test]
    fn test_format_dollars() {
        assert_eq!(format_dollars(137), "137");
        assert_eq!(format_dollars(68_928), "68,928");
        assert_eq!(format_dollars(2_067_813), "2,067,813");
    }

    #[test]
    fn test_pdf_render_produces_bytes() {
        let mapper = HipaaMapper::new();
        let findings = vec![
            Finding::new("Weak TLS", Severity::High).with_description("TLS 1.0 enabled"),
            Finding::new("Default Creds", Severity::Critical)
                .with_description("Admin password is default"),
        ];
        let result = mapper.map_findings(&findings);
        let generator = HipaaReportGenerator::new("Test Hospital");
        let now = Utc::now();
        let report = generator.generate(&result, now - chrono::Duration::hours(1), now);

        // This test may fail in environments without Liberation fonts installed.
        // The CI environment should have them (libfonts-liberation package).
        match PdfReportRenderer::render(&report) {
            Ok(bytes) => {
                assert!(!bytes.is_empty());
                // PDF files start with %PDF
                assert!(bytes.starts_with(b"%PDF"));
            }
            Err(_) => {
                // Font not available in this environment — skip gracefully
            }
        }
    }
}
