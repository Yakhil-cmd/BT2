All cited code is confirmed in the repository. Let me verify the key components:

1. **`random.rs` L8-14**: Seed is exactly `time().to_le_bytes() ++ [42u8; 24]` — confirmed.
2. **`canister.rs` L30-67**: `inspect_message` only covers `add_config`, `disclose_rules` (update), and `get_config` (replicated query). `get_rule_by_id` is a plain `#[query]` — regular query calls bypass `inspect_message` entirely on the IC.
3. **`getter.rs` L224-246 + `confidentiality_formatting.rs` L34-42**: For `RestrictedRead` callers, `RuleConfidentialityFormatter` only redacts `rule_raw` and `description` when `disclosed_at.is_none()`, but `incident_id`, `added_in_version`, and `removed_in_version` are always returned.
4. **`getter.rs` L219-222**: `NotFound` is returned only when the UUID doesn't exist, creating a clear existence oracle.

---

Audit Report

## Title
Predictable ChaCha20Rng Seed Enables UUID Prediction and Undisclosed Rule Metadata Enumeration — (`rs/boundary_node/rate_limits/canister/random.rs`)

## Summary
The `ChaCha20Rng` in the rate-limit canister is seeded with only 8 bytes of publicly observable IC block time padded with 24 constant `42` bytes, making the entire RNG state reconstructible by any observer. Because `get_rule_by_id` is a plain `#[query]` method that bypasses `inspect_message`, any unprivileged caller can predict generated rule UUIDs and query the canister to learn the `incident_id`, `added_in_version`, and `removed_in_version` of undisclosed confidential rules, as well as confirm their existence.

## Finding Description

**Root cause — weak seed in `random.rs`:**

```rust
thread_local! {
  static RNG: RefCell<ChaCha20Rng> = {
    let mut seed = [42; 32];
    seed[..8].copy_from_slice(&time().to_le_bytes());
    RefCell::new(ChaCha20Rng::from_seed(seed))
  };
}
``` [1](#0-0) 

The 32-byte seed has only 8 variable bytes (the IC consensus block time in nanoseconds); the remaining 24 bytes are the constant `42`. `ic_cdk::api::time()` returns the publicly observable consensus block time. In the IC Wasm environment, heap memory (including `thread_local!` statics) is reset on install/upgrade, so the RNG is re-initialized on the first `generate_random_uuid()` call after each upgrade — which occurs inside `add_config` at: [2](#0-1) 

The `getrandom` call in `generate_random_uuid` draws from this RNG via `custom_getrandom_bytes_impl`: [3](#0-2) 

**`inspect_message` does not protect `get_rule_by_id`:**

`inspect_message` only covers `add_config`, `disclose_rules`, and `get_config` (replicated query): [4](#0-3) 

`get_rule_by_id` is a plain `#[query]` method: [5](#0-4) 

On the IC, regular (non-replicated) query calls never pass through `inspect_message`. The catch-all trap in `inspect_message` (L62-67) only fires for ingress messages, not for query calls. Any anonymous or unprivileged caller can invoke `get_rule_by_id` as a query.

**Metadata leakage for undisclosed rules:**

`RuleConfidentialityFormatter` only redacts `rule_raw` and `description` when `disclosed_at.is_none()`, but always returns `incident_id`, `added_in_version`, and `removed_in_version`: [6](#0-5) 

The `RuleGetter` applies this formatter for `RestrictedRead` callers: [7](#0-6) 

**Existence oracle:**

`NotFound` is returned only when the UUID does not exist in storage: [8](#0-7) 

This allows an attacker to distinguish "rule exists but undisclosed" from "rule does not exist."

**Full exploit path:**
1. Monitor the IC state tree for the block timestamp of the first `add_config` call after canister install/upgrade (publicly available via certified state reads).
2. Reconstruct the seed: `seed[..8] = block_time_ns.to_le_bytes(); seed[8..] = [42u8; 24]`.
3. Instantiate `ChaCha20Rng::from_seed(seed)` locally and replay `fill_bytes` calls to predict all subsequent rule UUIDs.
4. Call `get_rule_by_id(predicted_uuid)` as an anonymous query (bypassing `inspect_message`).
5. Receive `incident_id`, `added_in_version`, `removed_in_version` for undisclosed rules, and confirm their existence.

## Impact Explanation
This is a **High** severity finding. The boundary node rate-limit canister is explicitly in scope. An unprivileged attacker can enumerate the existence of confidential security-incident rules and extract their `incident_id` (linking the rule to a security incident before public disclosure), `added_in_version`, and `removed_in_version`. This breaks the stated confidentiality invariant of undisclosed rules and constitutes a significant boundary/API infrastructure security impact with concrete harm: premature disclosure of security incident metadata to any observer of the chain.

## Likelihood Explanation
Exploitation requires no privileges, no key material, no brute force, and no consensus corruption. The IC block timestamp is publicly observable with nanosecond precision via certified state reads. The only prerequisite is monitoring the chain for the first `add_config` call after an install/upgrade, which is trivially detectable. The attack is fully deterministic and repeatable after every canister upgrade.

## Recommendation
Replace the time-seeded `thread_local!` initialization with a cryptographically unpredictable source. On the IC, use `ic_cdk::api::management_canister::main::raw_rand()` (an async call returning 32 bytes of threshold-BLS randomness) during `init`/`post_upgrade` to seed the RNG, storing the seed in stable memory or a canister-held variable. The `thread_local!` lazy initialization pattern using `time()` must be removed entirely.

## Proof of Concept

```rust
// Deterministic replay — run locally against a PocketIC instance
let block_time_ns: u64 = /* observed from IC state tree at first add_config after upgrade */;
let mut seed = [42u8; 32];
seed[..8].copy_from_slice(&block_time_ns.to_le_bytes());
let mut rng = ChaCha20Rng::from_seed(seed);

for _ in 0..N {
    let mut buf = [0u8; 16];
    rng.fill_bytes(&mut buf);
    let predicted_uuid = Uuid::from_slice(&buf).unwrap();
    // Issue anonymous query: get_rule_by_id(predicted_uuid.to_string())
    // Assert: response is Ok (not NotFound) — rule exists
    // Assert: incident_id, added_in_version, removed_in_version are present in response
    // Assert: rule_raw and description are None (redacted but existence confirmed)
}
```

A deterministic integration test using PocketIC can set a fixed mock time, call `add_config` N times, then replay the above to assert all N predicted UUIDs match stored rules and that their metadata is returned to an anonymous query caller.

### Citations

**File:** rs/boundary_node/rate_limits/canister/random.rs (L8-14)
```rust
thread_local! {
  static RNG: RefCell<ChaCha20Rng> = {
    let mut seed = [42; 32];
    seed[..8].copy_from_slice(&time().to_le_bytes());
    RefCell::new(ChaCha20Rng::from_seed(seed))
  };
}
```

**File:** rs/boundary_node/rate_limits/canister/random.rs (L22-29)
```rust
pub fn custom_getrandom_bytes_impl(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        rng.fill_bytes(dest);
    });

    Ok(())
}
```

**File:** rs/boundary_node/rate_limits/canister/add_config.rs (L115-115)
```rust
                let rule_id = RuleId(generate_random_uuid()?);
```

**File:** rs/boundary_node/rate_limits/canister/canister.rs (L30-31)
```rust
const UPDATE_METHODS: [&str; 2] = ["add_config", "disclose_rules"];
const REPLICATED_QUERY_METHOD: &str = "get_config";
```

**File:** rs/boundary_node/rate_limits/canister/canister.rs (L123-133)
```rust
#[query]
fn get_rule_by_id(rule_id: RuleId) -> GetRuleByIdResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter = RuleConfidentialityFormatter;
        let getter = RuleGetter::new(state, formatter, access_resolver);
        getter.get(&rule_id)
    })?;
    Ok(response)
}
```

**File:** rs/boundary_node/rate_limits/canister/confidentiality_formatting.rs (L34-42)
```rust
    fn format(&self, rule: OutputRuleMetadata) -> OutputRuleMetadata {
        let mut rule = rule;
        // Redact (hide) fields of non-disclosed rule
        if rule.disclosed_at.is_none() {
            rule.description = None;
            rule.rule_raw = None;
        }
        rule
    }
```

**File:** rs/boundary_node/rate_limits/canister/getter.rs (L219-222)
```rust
        let stored_rule = self
            .canister_api
            .get_rule(&rule_id)
            .ok_or_else(|| GetEntityError::NotFound(rule_id.0.to_string()))?;
```

**File:** rs/boundary_node/rate_limits/canister/getter.rs (L234-245)
```rust
        let is_authorized_viewer = self.access_resolver.get_access_level()
            == AccessLevel::FullAccess
            || self.access_resolver.get_access_level() == AccessLevel::FullRead;

        if is_authorized_viewer {
            return Ok(output_rule.into());
        }

        // Hide non-disclosed rules from unauthorized viewers.
        let output_rule = self.formatter.format(output_rule);

        Ok(output_rule.into())
```
