//! SQLite database for NVD/CVE data

use forgescan_core::{CveInfo, Error, NvdDatabase, Result};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// NVD database backed by SQLite
#[derive(Clone)]
pub struct NvdDb {
    conn: Arc<Mutex<Connection>>,
}

impl NvdDb {
    /// Open or create the NVD database at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())
            .map_err(|e| Error::Database(format!("Failed to open NVD database: {}", e)))?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        db.init_schema()?;
        Ok(db)
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| Error::Database(format!("Failed to create in-memory database: {}", e)))?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                published_date TEXT,
                last_modified_date TEXT,
                cvss_v3_score REAL,
                cvss_v3_vector TEXT,
                cwe_ids TEXT,
                refs TEXT
            );

            CREATE TABLE IF NOT EXISTS cpe_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                cpe_uri TEXT NOT NULL,
                version_start TEXT,
                version_start_type TEXT,
                version_end TEXT,
                version_end_type TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            );

            CREATE TABLE IF NOT EXISTS cisa_kev (
                cve_id TEXT PRIMARY KEY,
                vendor TEXT,
                product TEXT,
                date_added TEXT,
                due_date TEXT,
                known_ransomware TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_cpe_matches_cve ON cpe_matches(cve_id);
            CREATE INDEX IF NOT EXISTS idx_cpe_matches_cpe ON cpe_matches(cpe_uri);
            "#,
        )
        .map_err(|e| Error::Database(format!("Failed to initialize schema: {}", e)))?;

        Ok(())
    }

    /// Insert or update a CVE
    pub fn upsert_cve(&self, cve: &CveInfo) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            INSERT OR REPLACE INTO cves (cve_id, description, published_date, cvss_v3_score, cvss_v3_vector, cwe_ids, refs)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                cve.cve_id,
                cve.description,
                cve.published_date,
                cve.cvss_v3_score,
                cve.cvss_v3_vector,
                serde_json::to_string(&cve.cwe_ids).unwrap_or_default(),
                serde_json::to_string(&cve.references).unwrap_or_default(),
            ],
        )
        .map_err(|e| Error::Database(format!("Failed to upsert CVE: {}", e)))?;

        Ok(())
    }

    /// Add a CVE to CISA KEV
    pub fn add_kev(
        &self,
        cve_id: &str,
        vendor: &str,
        product: &str,
        date_added: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO cisa_kev (cve_id, vendor, product, date_added) VALUES (?1, ?2, ?3, ?4)",
            params![cve_id, vendor, product, date_added],
        )
        .map_err(|e| Error::Database(format!("Failed to add KEV: {}", e)))?;

        Ok(())
    }

    /// Add a CPE match for a CVE
    pub fn add_cpe_match(
        &self,
        cve_id: &str,
        cpe_uri: &str,
        version_start_incl: Option<&str>,
        version_start_excl: Option<&str>,
        version_end_incl: Option<&str>,
        version_end_excl: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        let version_start = version_start_incl.or(version_start_excl);
        let version_start_type = if version_start_incl.is_some() {
            "including"
        } else if version_start_excl.is_some() {
            "excluding"
        } else {
            ""
        };

        let version_end = version_end_incl.or(version_end_excl);
        let version_end_type = if version_end_incl.is_some() {
            "including"
        } else if version_end_excl.is_some() {
            "excluding"
        } else {
            ""
        };

        conn.execute(
            r#"
            INSERT INTO cpe_matches (cve_id, cpe_uri, version_start, version_start_type, version_end, version_end_type)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![cve_id, cpe_uri, version_start, version_start_type, version_end, version_end_type],
        )
        .map_err(|e| Error::Database(format!("Failed to add CPE match: {}", e)))?;

        Ok(())
    }

    /// Find CVEs matching a CPE with version checking
    pub fn find_vulnerabilities(&self, cpe_uri: &str, version: &str) -> Vec<CveInfo> {
        use crate::cpe::{compare_versions, Cpe};

        let conn = self.conn.lock().unwrap();

        let cpe = match Cpe::parse(cpe_uri) {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        let search_pattern = format!("cpe:2.3:{}:{}:{}:%", cpe.part, cpe.vendor, cpe.product);

        let mut stmt = match conn.prepare(
            r#"
            SELECT DISTINCT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_vector,
                   c.cwe_ids, c.refs, c.published_date,
                   m.version_start, m.version_start_type, m.version_end, m.version_end_type
            FROM cves c
            JOIN cpe_matches m ON c.cve_id = m.cve_id
            WHERE m.cpe_uri LIKE ?1
            "#,
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };

        let mut results = Vec::new();

        let rows = match stmt.query_map([&search_pattern], |row| {
            Ok((
                CveInfo {
                    cve_id: row.get(0)?,
                    description: row.get(1)?,
                    cvss_v3_score: row.get(2)?,
                    cvss_v3_vector: row.get(3)?,
                    cwe_ids: serde_json::from_str(&row.get::<_, String>(4).unwrap_or_default())
                        .unwrap_or_default(),
                    references: serde_json::from_str(&row.get::<_, String>(5).unwrap_or_default())
                        .unwrap_or_default(),
                    published_date: row.get(6)?,
                },
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8).unwrap_or_default(),
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10).unwrap_or_default(),
            ))
        }) {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        for row in rows.flatten() {
            let (cve_info, version_start, version_start_type, version_end, version_end_type) = row;

            let mut matches = true;

            if let Some(ref start) = version_start {
                let cmp = compare_versions(version, start);
                if (version_start_type == "including" && cmp < 0)
                    || (version_start_type == "excluding" && cmp <= 0)
                {
                    matches = false;
                }
            }

            if matches {
                if let Some(ref end) = version_end {
                    let cmp = compare_versions(version, end);
                    if (version_end_type == "including" && cmp > 0)
                        || (version_end_type == "excluding" && cmp >= 0)
                    {
                        matches = false;
                    }
                }
            }

            if matches {
                results.push(cve_info);
            }
        }

        results
    }

    /// Get CVE count
    pub fn cve_count(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cves", [], |row| row.get(0))
            .map_err(|e| Error::Database(format!("Failed to count CVEs: {}", e)))?;
        Ok(count as u64)
    }

    /// Get KEV count
    pub fn kev_count(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cisa_kev", [], |row| row.get(0))
            .map_err(|e| Error::Database(format!("Failed to count KEV: {}", e)))?;
        Ok(count as u64)
    }
}

impl NvdDatabase for NvdDb {
    fn lookup_cpe(&self, cpe: &str) -> Vec<CveInfo> {
        let conn = self.conn.lock().unwrap();

        // Simple prefix match - full CPE matching would be more complex
        let mut stmt = conn
            .prepare(
                r#"
                SELECT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_vector, c.cwe_ids, c.refs, c.published_date
                FROM cves c
                JOIN cpe_matches m ON c.cve_id = m.cve_id
                WHERE m.cpe_uri LIKE ?1
                "#,
            )
            .ok();

        if let Some(ref mut stmt) = stmt {
            let pattern = format!("{}%", cpe.trim_end_matches('*'));
            stmt.query_map([pattern], |row| {
                Ok(CveInfo {
                    cve_id: row.get(0)?,
                    description: row.get(1)?,
                    cvss_v3_score: row.get(2)?,
                    cvss_v3_vector: row.get(3)?,
                    cwe_ids: serde_json::from_str(&row.get::<_, String>(4).unwrap_or_default())
                        .unwrap_or_default(),
                    references: serde_json::from_str(&row.get::<_, String>(5).unwrap_or_default())
                        .unwrap_or_default(),
                    published_date: row.get(6)?,
                })
            })
            .ok()
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
        } else {
            vec![]
        }
    }

    fn is_cisa_kev(&self, cve_id: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT 1 FROM cisa_kev WHERE cve_id = ?1", [cve_id], |_| {
            Ok(true)
        })
        .unwrap_or(false)
    }

    fn get_cve(&self, cve_id: &str) -> Option<CveInfo> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            r#"
            SELECT cve_id, description, cvss_v3_score, cvss_v3_vector, cwe_ids, refs, published_date
            FROM cves WHERE cve_id = ?1
            "#,
            [cve_id],
            |row| {
                Ok(CveInfo {
                    cve_id: row.get(0)?,
                    description: row.get(1)?,
                    cvss_v3_score: row.get(2)?,
                    cvss_v3_vector: row.get(3)?,
                    cwe_ids: serde_json::from_str(&row.get::<_, String>(4).unwrap_or_default())
                        .unwrap_or_default(),
                    references: serde_json::from_str(&row.get::<_, String>(5).unwrap_or_default())
                        .unwrap_or_default(),
                    published_date: row.get(6)?,
                })
            },
        )
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_db() {
        let db = NvdDb::in_memory().unwrap();
        assert_eq!(db.cve_count().unwrap(), 0);
    }

    #[test]
    fn test_upsert_cve() {
        let db = NvdDb::in_memory().unwrap();

        let cve = CveInfo {
            cve_id: String::from("CVE-2021-44228"),
            description: String::from("Log4Shell"),
            cvss_v3_score: Some(10.0),
            cvss_v3_vector: Some(String::from("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")),
            cwe_ids: vec![String::from("CWE-502")],
            references: vec![],
            published_date: String::from("2021-12-10"),
        };

        db.upsert_cve(&cve).unwrap();
        assert_eq!(db.cve_count().unwrap(), 1);

        let retrieved = db.get_cve("CVE-2021-44228").unwrap();
        assert_eq!(retrieved.cvss_v3_score, Some(10.0));
    }

    #[test]
    fn test_kev() {
        let db = NvdDb::in_memory().unwrap();
        db.add_kev("CVE-2021-44228", "Apache", "Log4j", "2021-12-10")
            .unwrap();

        assert!(db.is_cisa_kev("CVE-2021-44228"));
        assert!(!db.is_cisa_kev("CVE-9999-9999"));
    }
}
