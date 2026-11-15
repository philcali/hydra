//! Degradation manager (REQ-012): when programmatic control of a device
//! is unavailable, activate a graceful fallback and surface the event.

use mbse::links_to;
use mbse::mbse_exempt;

/// State of a device's programmatic control (REQ-012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[mbse_exempt("data type — not a model node")]
pub enum DegradationState {
    Healthy,
    /// Control lost; fallback in force.
    Degraded,
}

/// Graceful fallback applied while a device is degraded (REQ-012).
#[derive(Debug, Clone, PartialEq, Eq)]
#[mbse_exempt("data type — not a model node")]
pub enum FallbackAction {
    /// Serve the last-known-good configuration from the catalog.
    ServeCachedConfig,
    /// Route the operation to an operator for manual action.
    ManualReview,
}

/// Tracks per-device control failures and activates the graceful
/// fallback when programmatic control is unavailable (REQ-012 /
/// CONOPS-004).
#[links_to("REQ-012", component = "ARCH-DRIVERS")]
pub struct DegradationManager {
    /// Consecutive failures that trip degradation.
    threshold: usize,
    failures: std::collections::HashMap<String, usize>,
    degraded: std::collections::HashSet<String>,
}

impl DegradationManager {
    pub fn new(threshold: usize) -> Self {
        Self {
            threshold: threshold.max(1),
            failures: std::collections::HashMap::new(),
            degraded: std::collections::HashSet::new(),
        }
    }

    /// Record a control attempt. Returns `true` if this attempt tripped
    /// the device into degradation.
    pub fn record(&mut self, device: &str, success: bool) -> bool {
        if success {
            self.failures.remove(device);
            self.degraded.remove(device);
            false
        } else {
            let count = self.failures.entry(device.to_string()).or_insert(0);
            *count += 1;
            if *count >= self.threshold && !self.degraded.contains(device) {
                self.degraded.insert(device.to_string());
                tracing::warn!(device, "degradation activated — programmatic control unavailable");
                true
            } else {
                false
            }
        }
    }

    pub fn state(&self, device: &str) -> DegradationState {
        if self.degraded.contains(device) {
            DegradationState::Degraded
        } else {
            DegradationState::Healthy
        }
    }

    /// How many devices are currently degraded.
    pub fn degraded_count(&self) -> usize {
        self.degraded.len()
    }

    /// The graceful fallback in force for a degraded device (REQ-012);
    /// `None` while control is healthy.
    pub fn fallback(&self, device: &str) -> Option<FallbackAction> {
        if self.state(device) == DegradationState::Degraded {
            Some(FallbackAction::ServeCachedConfig)
        } else {
            None
        }
    }
}

impl Default for DegradationManager {
    fn default() -> Self {
        Self::new(2)
    }
}
