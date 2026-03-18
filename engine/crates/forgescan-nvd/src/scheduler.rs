//! NVD auto-update scheduler
//!
//! Provides a background task that periodically refreshes the local NVD database
//! and tracks currency (last update timestamp, CVE/KEV counts).

use crate::database::NvdDb;
use crate::sync::NvdSync;
use chrono::Utc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn};

/// Metadata keys stored in the `sync_metadata` table
const META_LAST_SYNC: &str = "last_sync_time";
const META_LAST_SYNC_STATUS: &str = "last_sync_status";
const META_CVE_COUNT: &str = "cve_count";
const META_KEV_COUNT: &str = "kev_count";

/// Current NVD database currency status
#[derive(Debug, Clone)]
pub struct NvdCurrency {
    /// ISO 8601 timestamp of last successful sync
    pub last_sync_time: Option<String>,
    /// Status of last sync ("success" or error message)
    pub last_sync_status: String,
    /// Total CVEs in database
    pub cve_count: u64,
    /// Total CISA KEV entries
    pub kev_count: u64,
}

/// NVD auto-update scheduler
///
/// Runs incremental NVD syncs on a configurable interval (default: 24 hours).
/// Tracks currency metadata so dashboards can display freshness.
pub struct NvdScheduler {
    db: NvdDb,
    api_key: Option<String>,
    interval: Duration,
    shutdown_rx: watch::Receiver<bool>,
}

impl NvdScheduler {
    /// Create a new scheduler.
    ///
    /// Returns the scheduler and a shutdown sender. Drop or send `true` to stop.
    pub fn new(
        db: NvdDb,
        api_key: Option<String>,
        interval: Duration,
    ) -> (Self, watch::Sender<bool>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        (
            Self {
                db,
                api_key,
                interval,
                shutdown_rx,
            },
            shutdown_tx,
        )
    }

    /// Get the current NVD currency status from metadata
    pub fn currency(db: &NvdDb) -> NvdCurrency {
        NvdCurrency {
            last_sync_time: db.get_metadata(META_LAST_SYNC).ok().flatten(),
            last_sync_status: db
                .get_metadata(META_LAST_SYNC_STATUS)
                .ok()
                .flatten()
                .unwrap_or_else(|| "never".to_string()),
            cve_count: db.cve_count().unwrap_or(0),
            kev_count: db.kev_count().unwrap_or(0),
        }
    }

    /// Run the scheduler loop. Blocks until shutdown signal.
    pub async fn run(mut self) {
        info!(
            "NVD auto-update scheduler started (interval: {}s)",
            self.interval.as_secs()
        );

        // Do an initial sync if we've never synced before
        let last_sync = self.db.get_metadata(META_LAST_SYNC).ok().flatten();
        if last_sync.is_none() {
            info!("No previous sync found — running initial NVD sync");
            self.do_sync(None).await;
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {
                    let since = self.db.get_metadata(META_LAST_SYNC).ok().flatten();
                    self.do_sync(since.as_deref()).await;
                }
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("NVD scheduler shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Perform a single sync cycle
    async fn do_sync(&self, since: Option<&str>) {
        let now = Utc::now().to_rfc3339();
        let sync_client = NvdSync::new(self.db.clone(), self.api_key.clone());

        // Incremental or full sync
        let result = if let Some(since_date) = since {
            info!("Running incremental NVD sync since {}", since_date);
            sync_client.incremental_sync(since_date).await
        } else {
            info!("Running full NVD sync");
            sync_client.full_sync().await
        };

        match result {
            Ok(stats) => {
                info!(
                    "NVD sync complete: {} CVEs processed, {} errors",
                    stats.cves_processed, stats.errors
                );
                let _ = self.db.set_metadata(META_LAST_SYNC, &now);
                let _ = self.db.set_metadata(META_LAST_SYNC_STATUS, "success");
            }
            Err(e) => {
                error!("NVD sync failed: {}", e);
                let _ = self
                    .db
                    .set_metadata(META_LAST_SYNC_STATUS, &format!("error: {}", e));
            }
        }

        // Sync KEV catalog
        match sync_client.sync_kev().await {
            Ok(count) => info!("KEV sync: {} entries", count),
            Err(e) => warn!("KEV sync failed: {}", e),
        }

        // Update counts in metadata
        if let Ok(count) = self.db.cve_count() {
            let _ = self.db.set_metadata(META_CVE_COUNT, &count.to_string());
        }
        if let Ok(count) = self.db.kev_count() {
            let _ = self.db.set_metadata(META_KEV_COUNT, &count.to_string());
        }
    }
}

/// Spawn the NVD auto-update scheduler as a background task.
///
/// Returns a shutdown sender — send `true` to stop the scheduler.
pub fn spawn_nvd_scheduler(
    db: NvdDb,
    api_key: Option<String>,
    interval: Duration,
) -> watch::Sender<bool> {
    let (scheduler, shutdown_tx) = NvdScheduler::new(db, api_key, interval);
    tokio::spawn(scheduler.run());
    shutdown_tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_currency_empty_db() {
        let db = NvdDb::in_memory().unwrap();
        let currency = NvdScheduler::currency(&db);
        assert!(currency.last_sync_time.is_none());
        assert_eq!(currency.last_sync_status, "never");
        assert_eq!(currency.cve_count, 0);
        assert_eq!(currency.kev_count, 0);
    }

    #[test]
    fn test_metadata_roundtrip() {
        let db = NvdDb::in_memory().unwrap();
        db.set_metadata("test_key", "test_value").unwrap();
        assert_eq!(
            db.get_metadata("test_key").unwrap(),
            Some("test_value".to_string())
        );
        assert_eq!(db.get_metadata("nonexistent").unwrap(), None);
    }
}
