//! Tests for hydra-discovery — verifies requirements via `#[links_to]`.

use crate::engine::{DiscoveryError, DiscoveryService};
use crate::sources::{DiscoveredDevice, MdnsSource, PollSource, ScanSource};

use mbse::links_to;

mbse_graph::collect_test!();

#[mbse::mbse_exempt("test helper — not a model node")]
fn run<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Runtime::new().unwrap().block_on(fut)
}

#[mbse::mbse_exempt("test helper — not a model node")]
fn device(address: &str, vendor: &str) -> DiscoveredDevice {
    DiscoveredDevice {
        address: address.into(),
        device_type: "switch".into(),
        vendor: vendor.into(),
        capabilities: vec!["config".into()],
    }
}

/// Verifies REQ-008: a scan cycle discovers devices on the edge network.
#[links_to("REQ-008")]
#[test]
fn test_cycle_discovers_devices() {
    let mut svc = DiscoveryService::new(
        vec![Box::new(MdnsSource::new(vec![
            device("192.168.10.11", "acme"),
            device("192.168.10.12", "siemens"),
        ])) as Box<dyn ScanSource>],
        10_000,
    );
    let fresh = run(svc.run_cycle());
    assert_eq!(fresh.len(), 2);
    assert!(svc.seen().contains("192.168.10.11"));
}

/// Verifies REQ-008: devices are deduped across cycles — re-seen devices
/// are not re-emitted.
#[links_to("REQ-008")]
#[test]
fn test_dedupe_across_cycles() {
    let source = MdnsSource::new(vec![device("192.168.10.11", "acme")]);
    let mut svc = DiscoveryService::new(vec![Box::new(source) as Box<dyn ScanSource>], 10_000);
    assert_eq!(run(svc.run_cycle()).len(), 1);
    assert_eq!(run(svc.run_cycle()).len(), 0); // already known
}

/// Verifies REQ-008: multiple mechanisms (mDNS + poll) merge, and
/// duplicates across mechanisms collapse to one device.
#[links_to("REQ-008")]
#[test]
fn test_multiple_sources_merge() {
    let mut svc = DiscoveryService::new(vec![], 10_000);
    svc.add_source(MdnsSource::new(vec![device("10.0.0.5", "acme")]));
    svc.add_source(PollSource::new(vec![
        device("10.0.0.5", "acme"),   // duplicate of the mDNS hit
        device("10.0.0.6", "siemens"),
    ]));
    let fresh = run(svc.run_cycle());
    assert_eq!(fresh.len(), 2);
    assert!(fresh.iter().any(|d| d.address == "10.0.0.5"));
    assert!(fresh.iter().any(|d| d.address == "10.0.0.6"));
}

/// Verifies REQ-008 (P-DISCOVERY-INTERVAL): the poll interval budget.
#[links_to("REQ-008")]
#[test]
fn test_interval_budget() {
    let ok = DiscoveryService::new(vec![], 30_000);
    assert!(ok.validate_interval().is_ok());

    let too_slow = DiscoveryService::new(vec![], 120_000);
    match too_slow.validate_interval() {
        Err(DiscoveryError::IntervalExceeded(120_000, 60)) => {}
        other => panic!("expected IntervalExceeded, got {other:?}"),
    }
}

/// Verifies REQ-032: discovery applies the config's vendor/type filter —
/// only matching devices are hydrated/emitted.
#[links_to("REQ-032")]
#[test]
fn test_discovery_applies_config_filter() {
    use crate::config::DiscoveryConfig;

    let source = MdnsSource::new(vec![
        device("10.0.0.1", "acme"), // matches the filter
        device("10.0.0.2", "siemens"), // filtered out (vendor != acme)
    ]);
    let config = DiscoveryConfig {
        id: "cfg".into(),
        name: "acme only".into(),
        interval_ms: 30_000,
        vendor: Some("acme".into()),
        device_type: None,
    };
    let mut svc = DiscoveryService::new(vec![Box::new(source) as Box<dyn ScanSource>], 30_000)
        .with_config(config);
    let fresh = run(svc.run_cycle());
    assert_eq!(fresh.len(), 1);
    assert!(fresh.iter().any(|d| d.address == "10.0.0.1"));
}

/// Verifies REQ-033: discovery emits a `DeviceDiscovered` event on the
/// metric stream when it finds a new device, so consumers can react.
#[links_to("REQ-033")]
#[test]
fn test_discovery_emits_stream_event() {
    use hydra_telemetry::{MetricKind, MetricStream};

    let source = MdnsSource::new(vec![device("10.0.0.50", "acme")]);
    let stream = MetricStream::new(16);
    let mut rx = stream.subscribe();
    let mut svc = DiscoveryService::new(vec![Box::new(source) as Box<dyn ScanSource>], 10_000)
        .with_stream(stream);

    let fresh = run(svc.run_cycle());
    assert_eq!(fresh.len(), 1);

    let event = run(rx.recv()).unwrap();
    assert_eq!(event.device, "10.0.0.50");
    assert!(matches!(event.kind, MetricKind::DeviceDiscovered { .. }));
}
