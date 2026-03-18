//! Performance benchmarks for ForgeScan scanner operations
//!
//! Run with: cargo bench --package forgescan-scanner

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use forgescan_core::{Finding, Severity};
use forgescan_hipaa::{HipaaMapper, HipaaReportGenerator};
use forgescan_vuln::FrsCalculator;

fn generate_sample_findings(count: usize) -> Vec<Finding> {
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    let cwe_ids: [Vec<String>; 5] = [
        vec!["CWE-79".into()],
        vec!["CWE-89".into()],
        vec!["CWE-327".into()],
        vec!["CWE-798".into()],
        vec!["CWE-200".into()],
    ];

    (0..count)
        .map(|i| {
            let severity = severities[i % severities.len()];
            let mut finding = Finding::new(
                format!("Finding-{}: Test vulnerability {}", i, severity.as_str()),
                severity,
            )
            .with_description(format!(
                "Test finding {} with {} severity for benchmarking",
                i,
                severity.as_str()
            ));
            finding.cwe_ids = cwe_ids[i % cwe_ids.len()].clone();
            finding.cvss_v3_score = Some(((i % 100) as f32) / 10.0);
            finding.cisa_kev = i % 10 == 0;
            finding
        })
        .collect()
}

fn bench_frs_calculation(c: &mut Criterion) {
    let calc = FrsCalculator::new();

    c.bench_function("frs_calculate_1000", |b| {
        b.iter(|| {
            for i in 0..1000u32 {
                let cvss = (i % 100) as f64 / 10.0;
                let is_kev = i % 10 == 0;
                let is_internet = i % 3 != 0;
                let has_exploit = i % 5 == 0;
                let criticality = (i % 10) as f64 / 10.0;
                black_box(calc.calculate(cvss, is_kev, is_internet, has_exploit, criticality));
            }
        });
    });
}

fn bench_hipaa_mapping(c: &mut Criterion) {
    let mapper = HipaaMapper::new();
    let findings = generate_sample_findings(1000);

    c.bench_function("hipaa_map_1000_findings", |b| {
        b.iter(|| {
            black_box(mapper.map_findings(&findings));
        });
    });
}

fn bench_report_generation(c: &mut Criterion) {
    let mapper = HipaaMapper::new();
    let findings = generate_sample_findings(1000);
    let compliance_result = mapper.map_findings(&findings);
    let generator = HipaaReportGenerator::new("Benchmark Hospital");
    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(1);

    c.bench_function("report_generate_1000_findings", |b| {
        b.iter(|| {
            black_box(generator.generate(&compliance_result, start, now));
        });
    });
}

fn bench_report_json_serialization(c: &mut Criterion) {
    let mapper = HipaaMapper::new();
    let findings = generate_sample_findings(1000);
    let compliance_result = mapper.map_findings(&findings);
    let generator = HipaaReportGenerator::new("Benchmark Hospital");
    let now = chrono::Utc::now();
    let report = generator.generate(&compliance_result, now - chrono::Duration::hours(1), now);

    c.bench_function("report_json_serialize", |b| {
        b.iter(|| {
            black_box(serde_json::to_string(&report).unwrap());
        });
    });
}

fn bench_yaml_check_loading(c: &mut Criterion) {
    // Only run if checks directory exists
    let checks_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("checks");

    if checks_dir.exists() {
        c.bench_function("yaml_load_all_checks", |b| {
            b.iter(|| {
                black_box(forgescan_checks::loader::load_checks_from_dir(&checks_dir).unwrap());
            });
        });
    }
}

criterion_group!(
    benches,
    bench_frs_calculation,
    bench_hipaa_mapping,
    bench_report_generation,
    bench_report_json_serialization,
    bench_yaml_check_loading,
);
criterion_main!(benches);
