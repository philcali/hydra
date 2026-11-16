# Hydra

An edge device orchestration platform in Rust: operators authenticate, discover and
onboard heterogeneous devices (PLCs, sensors, …), group them into fleets, dispatch
flows to vendor-specific drivers, collect telemetry, and degrade gracefully — with
every action on an immutable audit log.

The defining property of this codebase: **the MBSE model is provably bound to the
code.** The design lives in a version-controlled graph (`mbse_graph.json`), the code
declares which model node each item implements or verifies, and the
[`mbse-verify`](../mbse-verify) toolchain checks the binding at build time —
including the *values* the code enforces against the *bounds* the model specifies.

```
71 model nodes (7 CONOPS · 35 requirements · 19 components · 10 parameters)
127 model edges    ·   8 crates        ·   98 tests, all passing
35/35 requirements implemented · 35/35 verified · 10/10 parameters anchored
cargo mbse check → 0 error(s) — PASS
```

---

## The model, bound to code — how the proof works

Hydra is wired into [mbse-verify](../mbse-verify) in three steps, all declared
in the repo itself (no side-channel tooling, no external state):

### 1. The model is a file in the repo

[`mbse_graph.json`](mbse_graph.json) is a flat `nodes` + `edges` graph:

- **CONOPS** (7) — the operational scenarios, from operator onboarding (CONOPS-001)
  through device discovery (CONOPS-002), flow execution (CONOPS-003), graceful
  degradation (CONOPS-004), scale (CONOPS-005), telemetry (CONOPS-006), to the
  discovery→provisioning loop (CONOPS-007).
- **Requirements** (35) — e.g. *REQ-002 "granular ACL for authorization"*,
  *REQ-011 "communicating to heterogeneous device types and vendors"*.
- **Architecture components** (19) — `ARCH-AUTH`, `ARCH-DRIVERS`,
  `ARCH-PROVISIONING`, … with `part_of` structure down to storage backends
  (`ARCH-STORAGE-SQLITE` / `ARCH-STORAGE-POSTGRES`).
- **Parameters** (10) — the quantitative bounds, e.g.
  *P-ACL-EVAL-LATENCY: max 100 ms per ACL evaluation*,
  *P-SCALE-DEVICE-COUNT: max 1000 devices per node*.

A requirement `satisfies` a CONOPS scenario, `constrains` a parameter; a component
`realizes` a requirement, `enforces` a parameter. That is the design-side contract
the checker adjudicates.

### 2. The code declares its binding with annotations

Every model-bearing item carries an explicit link — the binding is *in the source*,
reviewable in PRs, and diffable:

```rust
// hydra-auth/src/acl.rs — production code `implements` a requirement
#[links_to("REQ-002", component = "ARCH-AUTH")]
#[links_to("REQ-003", component = "ARCH-AUTH")]
pub struct AclEngine { /* … */ }
```

```rust
// hydra/src/tests.rs — a test `verifies` a requirement
#[links_to("REQ-008")]
#[tokio::test]
async fn test_onboard_discovered_device() { /* discovered → registered → audited */ }
```

```rust
// hydra-auth/src/acl.rs — a constant `enforces` a model parameter
// The checker reads the literal the code actually enforces and compares
// it to the model value — drift is a finding, not a hope.
#[links_to("REQ-002", parameter = "P-ACL-EVAL-LATENCY", value = 100.0)]
pub const ACL_EVAL_BUDGET_MS: u64 = 100;
```

```rust
// Deliberately not a model node — exempted *with a stated reason*,
// so "unlinked" is never an escape hatch, it is a decision on record.
#[mbse_exempt("data type — not a model node")]
pub struct AclRule { /* … */ }
```

Each crate registers its link registry with a single line in `src/lib.rs`:

```rust
mbse_graph::collect_test!();
```

### 3. `cargo mbse check` proves the binding

```bash
cargo mbse check --all
```

What it establishes, and what it would flag if the model and code ever drift:

| Check | Hydra today | If the code drifted |
|---|---|---|
| Every requirement has implementing code | 35/35 ✓ | `orphan` — a requirement with no code |
| Every requirement is verified by a test | 35/35 ✓ | `unverified` — implemented, untested |
| Every public item is linked to the model or exempted with a reason | ✓ (advisory warnings for test helpers) | `unlinked` |
| Every parameter bound is enforced by code that enforces the right value | 10/10 ✓, witness present | `param-unenforced` / value drift |
| Model edges resolve to real nodes | ✓ (dangling edges are hard errors) | build check fails |

Actual output from this tree:

```
  coverage  35/35 requirements implemented · 35/35 verified
  result    0 error(s), 25 warning(s), 0 info — PASS
  design regime    P-ACL-EVAL-LATENCY=100  ∧  P-AUDIT-FLUSH-LATENCY=100  ∧  P-AUTH-TIMEOUT=5000
                   ∧  P-CATALOG-SYNC-LAG=5  ∧  P-CATALOG-WRITE-LATENCY=100  ∧  P-DISCOVERY-INTERVAL=60
                   ∧  P-DRIVER-TIMEOUT=3000  ∧  P-METRIC-STREAM-LAG=1000  ∧  P-SCALE-DEVICE-COUNT=1000
                   ∧  P-TELEM-INTERVAL=30
```

The **design regime** line is the witness: a coherent operating point where every
code-enforced value satisfies its model bound. Exit codes are CI-friendly
(0 pass / 1 fail / 2 config), and `--deny orphan,unverified` promotes any advisory
rule to a hard error when you want the gate strict.

Explore further:

```bash
cargo mbse cross REQ-002     # a node's full cross-reference + verdict
cargo mbse chain P-ACL-EVAL-LATENCY  # bound → design → code conformance chain
cargo mbse viz --all         # offline HTML: graph + audit matrix + findings
```

---

## Architecture

| Crate | Model components | Responsibility |
|---|---|---|
| [`hydra`](crates/hydra) | `ARCH-SYS-MGMT`, `ARCH-PROVISIONING` | System orchestrator: bootstrap, the CONOPS flows, and the discovery→provisioning loop (REQ-034/035) |
| [`hydra-auth`](crates/hydra-auth) | `ARCH-AUTH`, `ARCH-IAM`, `ARCH-PKI` | Identity pool (OIDC + device certs), granular ACL engine with role/principal scoping, local IAM, device certificate authority |
| [`hydra-api`](crates/hydra-api) | `ARCH-CTRL-GW`, `ARCH-DATA-GW` | Control-plane and data-plane gateways; every request takes the full path: authenticate → authorize → execute → audit |
| [`hydra-catalog`](crates/hydra-catalog) | `ARCH-CATALOG-SVC`, `ARCH-FLEET`, `ARCH-STORAGE*` | Queryable device catalog (CRUD), fleets, swappable storage (SQLite edge / Postgres multi-node) |
| [`hydra-discovery`](crates/hydra-discovery) | `ARCH-DISCOVERY` | Edge-network device discovery (mDNS, scan, poll) emitting `DeviceDiscovered` events |
| [`hydra-drivers`](crates/hydra-drivers) | `ARCH-DRIVERS` | Driver registry and heterogeneous drivers (Modbus, OPC-UA, sensor), communication bus, degradation manager |
| [`hydra-telemetry`](crates/hydra-telemetry) | `ARCH-TELEMETRY`, `ARCH-FANOUT` | Metric stream, per-device telemetry pull through drivers, fan-out to delivery targets |
| [`hydra-audit`](crates/hydra-audit) | `ARCH-AUDIT` | Append-only SHA-256 hash-chained audit log — immutability is structural, and `verify` detects tampering |

The crates communicate through small traits and the shared metric stream; the
orchestrator assembles them and drives the CONOPS scenarios end-to-end.

## Quickstart

```bash
cargo build --workspace
cargo test --workspace      # 98 tests across 8 crates

# The MBSE proof (cargo-mbse lives in the sibling mbse-verify repo):
PATH="$(cd ../mbse-verify && pwd)/target/debug:$PATH" cargo mbse check --all
```

## Repository layout

```
mbse_graph.json            the MBSE model (nodes + edges), the design contract
crates/
  hydra/                   system orchestrator + CONOPS flow tests
  hydra-auth/              identity, ACL, IAM, PKI
  hydra-api/               control/data plane gateways
  hydra-catalog/           catalog, fleets, storage
  hydra-discovery/         edge-network discovery
  hydra-drivers/           driver framework + degradation
  hydra-telemetry/         metric stream + fan-out
  hydra-audit/             hash-chained audit log
```

## License

MIT
