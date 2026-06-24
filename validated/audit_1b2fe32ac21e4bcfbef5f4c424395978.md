Audit Report

## Title
Missing Memory-Size Validation in `validate_ingress_payload` Allows Byzantine Proposer to Exhaust Replica Memory — (`File: rs/ingress_manager/src/ingress_selector.rs`)

## Summary

`validate_ingress_payload` enforces message count and per-message size limits but never checks the total in-memory payload size against `max_ingress_bytes_per_block`. When `hashes_in_blocks_enabled()` is active, the function returns only the wire size (sum of ~40-byte message IDs) to the outer block validator, which checks it against the wire-size limit `max_block_payload_size`. A single Byzantine block proposer below the consensus fault threshold can therefore include up to 1,000 messages of 2 MB each (~2 GB total in memory) in one block, which every honest node will accept, induct, and potentially OOM on.

## Finding Description

**Block building** enforces two independent limits:

```rust
// rs/ingress_manager/src/ingress_selector.rs L212-220
if accumulated_wire_size + size_estimates.wire > wire_byte_limit { break 'outer; }
if accumulated_memory_size + size_estimates.memory > memory_byte_limit { break 'outer; }
``` [1](#0-0) 

`memory_byte_limit` is derived from `max_ingress_bytes_per_block` and is independent of the wire limit when `hashes_in_blocks_enabled()` is true: [2](#0-1) 

**Block validation** (`validate_ingress_payload`) checks message count and per-message validity, then returns only `size_estimates.wire` — the memory size is never checked: [3](#0-2) 

`payload_size_estimates` computes both values, but only `wire` is ever used in the validation return path: [4](#0-3) 

With `hashes_in_blocks_enabled()`, `wire_bytes` is set to `payload.total_ids_size_estimate()` (~40 bytes per message), while `memory_bytes` includes the full message content. The outer `PayloadBuilderImpl::validate_payload` accumulates only wire sizes and checks against `max_block_payload_size`: [5](#0-4) 

The relevant constants confirm the divergence: [6](#0-5) 

## Impact Explanation

With `hashes_in_blocks_enabled()`:

| Quantity | Value |
|---|---|
| `max_ingress_messages_per_block` | 1,000 |
| `max_ingress_bytes_per_message` | 2 MB |
| Maximum memory footprint | 1,000 × 2 MB = **~2 GB** |
| Wire size of same payload | 1,000 × ~40 bytes = **~40 KB** |
| `max_block_payload_size` check | 40 KB ≪ 4 MB → **passes** |
| `max_ingress_bytes_per_block` check | **never performed during validation** |

All honest nodes accept the block, induct ~2 GB of ingress messages into replicated state, and can trigger OOM and subnet halt. This matches the allowed impact: **High — Application/platform-level DoS, consensus blocking, or subnet availability impact not based on raw volumetric DDoS.**

## Likelihood Explanation

The attacker requires exactly one Byzantine block proposer — a single node below the consensus fault threshold (f out of 3f+1 nodes). This is explicitly within the IC's Byzantine fault tolerance threat model. Each ingress message is individually valid (≤ 2 MB, valid signature, sufficient cycles). The proposer simply selects more messages than the memory limit allows, bypassing the local `memory_byte_limit` guard in `get_ingress_payload`. No threshold corruption, key compromise, or governance majority is required. The attack is repeatable every block round.

## Recommendation

In `validate_ingress_payload`, after computing `size_estimates`, add a memory-size check mirroring the one in `get_ingress_payload`:

```rust
let size_estimates = self.payload_size_estimates(payload);

let memory_byte_limit = self
    .get_ingress_message_settings(context.registry_version)
    .expect("Couldn't get IngressMessageSettings from the registry.")
    .max_ingress_bytes_per_block as u64;

if size_estimates.memory > NumBytes::new(memory_byte_limit) {
    return Err(ValidationError::InvalidArtifact(
        InvalidIngressPayloadReason::IngressPayloadTooLarge(
            size_estimates.memory,
            NumBytes::new(memory_byte_limit),
        ),
    ));
}

Ok(size_estimates.wire)
```

This mirrors the existing `memory_byte_limit` function already present in the same file. [2](#0-1) 

## Proof of Concept

1. Submit 1,000 ingress messages each with a ~2 MB payload to a target subnet canister. Each message is individually valid (size ≤ `MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET` = 2 MB, valid sender signature, canister has sufficient cycles).
2. Wait for messages to be gossiped to all subnet nodes and enter their validated ingress pools.
3. On the Byzantine block proposer node, override `get_ingress_payload` (or directly craft a `BatchPayload`) to include all 1,000 messages, bypassing the local `memory_byte_limit` guard at lines 217-220.
4. Propose the block. Its wire size is ~40 KB (1,000 × ~40-byte IDs), well within `max_block_payload_size` = 4 MB.
5. Every honest node calls `validate_ingress_payload`:
   - `payload.message_count()` = 1,000 ≤ `max_ingress_messages_per_block` = 1,000 → **passes**
   - Each message individually ≤ 2 MB → **passes**
   - Returns `size_estimates.wire` ≈ 40 KB
   - Outer check: 40 KB ≤ 4 MB × 2 → **passes**
6. Block is finalized. All nodes induct ~2 GB of ingress messages into replicated state, triggering OOM and subnet halt.

A deterministic integration test can reproduce this by constructing an `IngressPayload` with 1,000 near-maximum-size messages, calling `validate_ingress_payload` directly, and asserting it returns `Ok(...)` — confirming the missing rejection — then verifying the fix causes it to return `Err(IngressPayloadTooLarge(...))`.

### Citations

**File:** rs/ingress_manager/src/ingress_selector.rs (L212-220)
```rust
                    // Break criterion #1: global byte limit
                    if accumulated_wire_size + size_estimates.wire > wire_byte_limit {
                        self.metrics.observe_limit_reached("wire_byte_limit");
                        break 'outer;
                    }
                    if accumulated_memory_size + size_estimates.memory > memory_byte_limit {
                        self.metrics.observe_limit_reached("memory_byte_limit");
                        break 'outer;
                    }
```

**File:** rs/ingress_manager/src/ingress_selector.rs (L420-422)
```rust
        let size_estimates = self.payload_size_estimates(payload);

        Ok(size_estimates.wire)
```

**File:** rs/ingress_manager/src/ingress_selector.rs (L619-642)
```rust
    fn memory_byte_limit(
        &self,
        wire_byte_limit: NumBytes,
        registry_version: RegistryVersion,
    ) -> Result<NumBytes, String> {
        let memory_byte_limit = self
            .get_ingress_message_settings(registry_version)
            .map_err(|err| {
                format!(
                    "Failed to get ingress message settings \
                    at registry version {registry_version}: {err}"
                )
            })?
            .max_ingress_bytes_per_block as u64;

        if self.hashes_in_blocks_enabled() {
            Ok(NumBytes::new(memory_byte_limit))
        } else {
            Ok(NumBytes::new(std::cmp::min(
                wire_byte_limit.get(),
                memory_byte_limit,
            )))
        }
    }
```

**File:** rs/ingress_manager/src/ingress_selector.rs (L644-658)
```rust
    fn payload_size_estimates(&self, payload: &IngressPayload) -> SizeEstimates {
        let memory_bytes =
            payload.total_messages_size_estimate() + payload.total_ids_size_estimate();

        let wire_bytes = if self.hashes_in_blocks_enabled() {
            payload.total_ids_size_estimate()
        } else {
            memory_bytes
        };

        SizeEstimates {
            memory: memory_bytes,
            wire: wire_bytes,
        }
    }
```

**File:** rs/consensus/src/consensus/payload_builder.rs (L144-168)
```rust
        let mut accumulated_size = NumBytes::new(0);
        for builder in &self.section_builder {
            accumulated_size +=
                builder.validate_payload(height, batch_payload, proposal_context, past_payloads)?;
        }

        // Check the combined size of the payloads using a 2x safety margin.
        // We allow payloads that are bigger than the maximum size but log an error.
        // And reject outright payloads that are more than twice the maximum size.
        if accumulated_size > max_block_payload_size {
            error!(
                self.logger,
                "The overall block size is too large, even though the individual payloads are valid: {}",
                CRITICAL_ERROR_PAYLOAD_TOO_LARGE
            );
            self.metrics.critical_error_payload_too_large.inc();
        }
        if accumulated_size > max_block_payload_size * 2 {
            return Err(ValidationError::InvalidArtifact(
                InvalidPayloadReason::PayloadTooBig {
                    expected: max_block_payload_size,
                    received: accumulated_size,
                },
            ));
        }
```

**File:** rs/limits/src/lib.rs (L71-78)
```rust
pub const MAX_BLOCK_PAYLOAD_SIZE: u64 = 4 * MEGABYTE;
/// How big an ingress payload can be *when stored in memory*. Increasing this value could lead to
/// increased memory usage of replicas.
/// Note that with hashes-in-blocks feature enabled, increasing this value doesn't necessarily mean
/// that we would send more data to peers when transmitting a block, because ingress messages are
/// stripped before disseminating blocks.
pub const MAX_INGRESS_BYTES_PER_BLOCK: u64 = 4 * MEGABYTE;
pub const MAX_INGRESS_MESSAGES_PER_BLOCK: u64 = 1000;
```
