//! Tests for hydra-telemetry — verifies requirements via `#[links_to]`.

use std::sync::Arc;

use crate::collector::{TelemetryCollector, TelemetryError, TelemetrySource};
use crate::fanout::{DeliveryTarget, FanOutService, RecordingHttpClient};
use crate::stream::{MetricEvent, MetricKind, MetricStream, TelemetryPoint};

use mbse::links_to;

mbse_graph::collect_test!();

fn run<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Runtime::new().unwrap().block_on(fut)
}

/// A pollable source with canned points.
struct FakeSource {
    points: Vec<TelemetryPoint>,
}

#[async_trait::async_trait]
impl TelemetrySource for FakeSource {
    async fn collect(&self) -> Vec<TelemetryPoint> {
        self.points.clone()
    }
}

fn point(device: &str, metric: &str, value: f64) -> TelemetryPoint {
    TelemetryPoint {
        device: device.into(),
        metric: metric.into(),
        value,
        ts_ms: crate::stream::now_ms(),
    }
}

/// Verifies REQ-013: the poll model collects points from a source.
#[links_to("REQ-013")]
#[test]
fn test_poll_model_collects() {
    let source = FakeSource {
        points: vec![point("dev-1", "temp_c", 41.5), point("dev-1", "load", 0.7)],
    };
    let collector = TelemetryCollector::new(source, MetricStream::new(16), 1000);
    let points = run(collector.collect_once()).unwrap();
    assert_eq!(points.len(), 2);
    assert_eq!(points[0].metric, "temp_c");
}

/// Verifies REQ-013: the push model ingests device-pushed points.
#[links_to("REQ-013")]
#[test]
fn test_push_model_ingests() {
    let collector =
        TelemetryCollector::new(FakeSource { points: vec![] }, MetricStream::new(16), 1000);
    let event = collector.push(point("dev-2", "voltage", 230.0)).unwrap();
    match event.kind {
        MetricKind::Point(p) => assert_eq!(p.value, 230.0),
        _ => panic!("expected a Point event"),
    }
}

/// Verifies REQ-013 (P-TELEM-INTERVAL): the interval budget is enforced.
#[links_to("REQ-013")]
#[test]
fn test_interval_budget() {
    let ok = TelemetryCollector::new(FakeSource { points: vec![] }, MetricStream::new(16), 1000);
    assert!(ok.validate_interval().is_ok());

    let too_slow =
        TelemetryCollector::new(FakeSource { points: vec![] }, MetricStream::new(16), 60_000);
    match too_slow.validate_interval() {
        Err(TelemetryError::IntervalExceeded(60_000, 30)) => {}
        other => panic!("expected IntervalExceeded, got {other:?}"),
    }
}

/// Verifies REQ-015: device-unhealthy events reach subscribers (CONOPS-004).
#[links_to("REQ-015")]
#[test]
fn test_unhealthy_event_reaches_subscriber() {
    let stream = MetricStream::new(16);
    let mut rx = stream.subscribe();
    stream
        .publish(
            MetricKind::DeviceUnhealthy {
                reason: "driver timeout".into(),
            },
            "dev-9",
        )
        .unwrap();
    let event = run(rx.recv()).unwrap();
    assert_eq!(event.device, "dev-9");
    assert!(matches!(event.kind, MetricKind::DeviceUnhealthy { .. }));
}

/// Verifies REQ-015: delivery stays within the P-METRIC-STREAM-LAG budget.
#[links_to("REQ-015")]
#[test]
fn test_stream_lag_within_budget() {
    let stream = MetricStream::new(16);
    let mut rx = stream.subscribe();
    stream.publish(MetricKind::DeviceRecovered, "dev-3").unwrap();
    let delivered = run(rx.recv()).unwrap();
    let lag_ms = crate::stream::now_ms().saturating_sub(delivered.ts_ms);
    assert!(
        lag_ms <= u128::from(crate::stream::METRIC_STREAM_LAG_MS),
        "lag {lag_ms}ms exceeded budget"
    );
}

/// Verifies REQ-015: multiple subscribers each receive the event.
#[links_to("REQ-015")]
#[test]
fn test_multiple_subscribers() {
    let stream = MetricStream::new(16);
    let mut rx1 = stream.subscribe();
    let mut rx2 = stream.subscribe();
    stream.publish(MetricKind::DeviceRecovered, "dev-4").unwrap();
    assert!(run(rx1.recv()).is_ok());
    assert!(run(rx2.recv()).is_ok());
}

/// Verifies REQ-026: the driver-backed source pulls telemetry **per
/// device**, through each device's driver, tagged by device id — including
/// a telemetry-only sensor (the REQ-018 fidelity floor).
#[links_to("REQ-026")]
#[test]
fn test_driver_source_pulls_per_device() {
    use std::sync::Arc;

    use hydra_drivers::{Driver, ModbusDriver, SensorDriver, SimDevice};

    use crate::source::DriverTelemetrySource;

    // A telemetry-only sensor — the fidelity floor — now contributes points.
    let sensor = Arc::new(SimDevice::new(0));
    {
        let mut raw = sensor.raw.lock().unwrap();
        raw.insert("temp_c".into(), serde_json::json!(21.5));
        raw.insert("humidity".into(), serde_json::json!(48.0));
    }
    // A full-fidelity PLC with a different (register) wire format.
    let plc = Arc::new(SimDevice::new(0));
    {
        let mut raw = plc.raw.lock().unwrap();
        raw.insert("reg:load".into(), serde_json::json!(0.7));
    }

    let source = DriverTelemetrySource::new()
        .add("sensor-1", Arc::new(SensorDriver::new(sensor)) as Arc<dyn Driver>)
        .add("plc-1", Arc::new(ModbusDriver::new(plc)) as Arc<dyn Driver>);
    assert_eq!(source.len(), 2);

    let points = run(source.collect());

    // Per-device tagging: each device's points carry its own id.
    let sensor_pts: Vec<_> = points.iter().filter(|p| p.device == "sensor-1").collect();
    let plc_pts: Vec<_> = points.iter().filter(|p| p.device == "plc-1").collect();
    assert_eq!(sensor_pts.len(), 2);
    assert_eq!(plc_pts.len(), 1);

    assert!(points
        .iter()
        .any(|p| p.device == "sensor-1" && p.metric == "temp_c" && p.value == 21.5));
    assert!(points
        .iter()
        .any(|p| p.device == "plc-1" && p.metric == "load" && p.value == 0.7));
}

// ── Data-plane metric fan-out (push targets) — REQ-027..REQ-029 ────────

fn event_for(device: &str) -> MetricEvent {
    MetricEvent {
        kind: MetricKind::DeviceRecovered,
        device: device.into(),
        ts_ms: crate::stream::now_ms(),
    }
}

/// Verifies REQ-027: the data plane pushes a metric event to a registered
/// delivery target (push target).
#[links_to("REQ-027")]
#[test]
fn test_fanout_delivers_to_target() {
    let received = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let rec = received.clone();
    let target = DeliveryTarget::new("monitor", Vec::<String>::new(), move |ev: MetricEvent| {
        rec.lock().unwrap().push(ev.device);
    });
    let mut fan = FanOutService::new();
    fan.register(target);
    assert_eq!(fan.target_count(), 1);

    let n = fan.deliver(&event_for("dev-1"));
    assert_eq!(n, 1);
    assert_eq!(*received.lock().unwrap(), vec!["dev-1".to_string()]);
}

/// Verifies REQ-028: a delivery target only receives events for the devices
/// it is scoped to.
#[links_to("REQ-028")]
#[test]
fn test_fanout_scoped_to_devices() {
    let a = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let b = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let (a1, b1) = (a.clone(), b.clone());
    let mut fan = FanOutService::new();
    fan.register(DeliveryTarget::new(
        "target-a",
        vec!["dev-1".to_string()],
        move |ev| {
            a1.lock().unwrap().push(ev.device);
        },
    ));
    fan.register(DeliveryTarget::new(
        "target-b",
        vec!["dev-2".to_string()],
        move |ev| {
            b1.lock().unwrap().push(ev.device);
        },
    ));

    fan.deliver(&event_for("dev-1"));
    fan.deliver(&event_for("dev-2"));
    fan.deliver(&event_for("dev-3")); // nobody is scoped to dev-3

    assert_eq!(*a.lock().unwrap(), vec!["dev-1".to_string()]);
    assert_eq!(*b.lock().unwrap(), vec!["dev-2".to_string()]);
}

/// Verifies REQ-029: fan-out is a separate, independently scalable unit —
/// multiple instances run independently with no shared control-plane state.
#[links_to("REQ-029")]
#[test]
fn test_fanout_is_independent_unit() {
    let r1 = Arc::new(std::sync::Mutex::new(0u32));
    let r2 = Arc::new(std::sync::Mutex::new(0u32));
    let (r1a, r2a) = (r1.clone(), r2.clone());
    let mut f1 = FanOutService::new();
    let mut f2 = FanOutService::new();
    f1.register(DeliveryTarget::new("t1", Vec::<String>::new(), move |_| {
        *r1a.lock().unwrap() += 1;
    }));
    f2.register(DeliveryTarget::new("t2", Vec::<String>::new(), move |_| {
        *r2a.lock().unwrap() += 1;
    }));

    let ev = event_for("dev-1");
    f1.deliver(&ev);
    f2.deliver(&ev);

    assert_eq!(*r1.lock().unwrap(), 1); // each unit delivers independently
    assert_eq!(*r2.lock().unwrap(), 1);
}

/// Verifies REQ-030: the stream→fan-out bridge delivers metric stream events
/// to the registered delivery targets (closes the loop).
#[links_to("REQ-030")]
#[tokio::test]
async fn test_stream_fanout_bridge() {
    use std::time::{Duration, Instant};

    let received = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let rec = received.clone();

    let mut fan = FanOutService::new();
    fan.register(DeliveryTarget::new(
        "monitor",
        Vec::<String>::new(),
        move |ev: MetricEvent| {
            rec.lock().unwrap().push(ev.device);
        },
    ));
    let fan = std::sync::Arc::new(fan);

    let stream = MetricStream::new(16);
    let task_stream = stream.clone();
    let fan_for_task = fan.clone();
    let handle = tokio::spawn(async move {
        fan_for_task.pump(&task_stream).await;
    });

    // Let the bridge subscribe, then publish into the stream.
    tokio::time::sleep(Duration::from_millis(20)).await;
    stream.publish(MetricKind::DeviceRecovered, "dev-1").unwrap();

    // Poll for delivery (the bridge forwards it to the target).
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        if received.lock().unwrap().iter().any(|d| d == "dev-1") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(received.lock().unwrap().iter().any(|d| d == "dev-1"));

    handle.abort();
}

// ── Pluggable transport / HTTP adapter — REQ-031 ────────────────────────

/// Verifies REQ-031: a delivery target can be backed by an HTTP transport —
/// the event is serialized to JSON and POSTed to the endpoint.
#[links_to("REQ-031")]
#[test]
fn test_http_target_posts_event() {
    let client = std::sync::Arc::new(RecordingHttpClient::new(200));
    let mut fan = FanOutService::new();
    fan.register(DeliveryTarget::http(
        "monitor",
        Vec::<String>::new(),
        "https://ingest.hydra.internal/metrics",
        client.clone(),
    ));

    let n = fan.deliver(&event_for("dev-1"));
    assert_eq!(n, 1);

    let reqs = client.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].0, "https://ingest.hydra.internal/metrics");
    let body: serde_json::Value = serde_json::from_str(&reqs[0].1).unwrap();
    assert_eq!(body["device"], "dev-1");
}

/// Verifies REQ-031: the transport is pluggable — the same target shape
/// works in-process (callback) and as an HTTP endpoint, each scoped to its
/// devices.
#[links_to("REQ-031")]
#[test]
fn test_transport_is_pluggable() {
    let client = std::sync::Arc::new(RecordingHttpClient::new(200));
    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let rec = received.clone();

    let mut fan = FanOutService::new();
    // In-process (callback) target, scoped to dev-1.
    fan.register(DeliveryTarget::new(
        "inproc",
        vec!["dev-1".to_string()],
        move |ev: MetricEvent| {
            rec.lock().unwrap().push(ev.device);
        },
    ));
    // HTTP target, scoped to dev-2.
    fan.register(DeliveryTarget::http(
        "http",
        vec!["dev-2".to_string()],
        "https://ingest.hydra.internal/metrics",
        client.clone(),
    ));

    // dev-1 → only the callback target; dev-2 → only the HTTP target.
    assert_eq!(fan.deliver(&event_for("dev-1")), 1);
    assert_eq!(fan.deliver(&event_for("dev-2")), 1);
    assert_eq!(fan.deliver(&event_for("dev-3")), 0); // neither is scoped to it

    assert_eq!(*received.lock().unwrap(), vec!["dev-1".to_string()]);
    let reqs = client.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].0, "https://ingest.hydra.internal/metrics");
}
