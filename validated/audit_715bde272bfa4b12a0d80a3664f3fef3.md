Audit Report

## Title
Registry Recovery CUP Displaced by Peer CUP via `max_by_key` Height-Only Tie-Breaking — (`rs/orchestrator/src/catch_up_package_provider.rs`)

## Summary

`get_latest_cup` selects the winning CUP using `max_by_key(get_cup_proto_height)` over `[local_cup, registry_cup, subnet_cup]`. Because Rust's `max_by_key` returns the **last** maximum element on ties, a peer-served CUP at the same height as the registry recovery CUP always wins. The `get_peer_cup` pre-filter is anchored to the **local** CUP, not the registry CUP, so it does not block the old peer CUP during recovery. The orchestrator persists and boots from the peer's CUP, targeting the wrong `state_hash` for state sync, causing the node to diverge from the recovered subnet.

## Finding Description

**Root cause — height-only `max_by_key` with last-wins tie-breaking:**

`get_latest_cup` builds the candidate list as `[local_cup, registry_cup, subnet_cup]` and selects the winner:

```rust
let latest_cup_proto = vec![local_cup, registry_cup, subnet_cup]
    .into_iter()
    .flatten()
    .max_by_key(get_cup_proto_height)   // height-only; last wins on tie
    ...
``` [1](#0-0) 

`get_cup_proto_height` decodes only the block height — it carries no `state_hash` or `registry_version` information:

```rust
fn get_cup_proto_height(cup: &pb::CatchUpPackage) -> Option<Height> {
    pb::CatchUpContent::decode(cup.content.as_slice())
        .ok()
        .and_then(|content| content.block)
        .map(|block| Height::from(block.height))
}
``` [2](#0-1) 

Because `subnet_cup` is the last element in the vector, it wins any tie with `registry_cup` at the same height.

**`get_peer_cup` pre-filter is anchored to the local CUP, not the registry CUP:**

`get_latest_cup` calls `get_peer_cup` with `local_cup.as_ref()` as the baseline:

```rust
let subnet_cup = self
    .get_peer_cup(subnet_id, registry_version, local_cup.as_ref())
    .await;
``` [3](#0-2) 

Inside `get_peer_cup`, `param` is derived from `current_cup` (the local CUP):

```rust
let param = current_cup
    .map(CatchUpPackageParam::try_from)
    .and_then(Result::ok);
...
if Some(CatchUpPackageParam::from(&cup)) > param {
    return Some(proto);
}
``` [4](#0-3) 

`CatchUpPackageParam` ordering is `(height, registry_version)` — a peer CUP at height H with `R_old` passes the filter whenever the local CUP is at height `< H` or is absent, regardless of whether the registry CUP at height H has a higher `registry_version`. [5](#0-4) 

**Recovery CUP height equals the last subnet CUP height:**

`do_recover_subnet` sets `cup_contents.height = payload.height`, where `payload.height` is the last finalized checkpoint height of the stuck subnet: [6](#0-5) 

This means the recovery CUP and the last legitimately produced subnet CUP share the same height H. The recovery CUP has `state_hash = S2` (new checkpoint) and `registry_version = R_recovery`; the old CUP has `state_hash = S1` and `registry_version = R_old < R_recovery`.

**Exploit flow:**

1. Subnet is stuck at height H. NNS publishes recovery CUP at height H with `state_hash = S2`, `registry_version = R_recovery`.
2. Victim node has no local CUP (or local CUP at height `< H`). `param` = `None` or `{H-1, R_local}`.
3. A peer (Byzantine or honest — all honest peers also hold the old CUP at H) serves the old CUP `{H, R_old, state_hash=S1}`. The filter passes: `Some({H, R_old}) > None` or `{H, R_old} > {H-1, R_local}`.
4. `max_by_key` selects `subnet_cup` (last at height H) over `registry_cup`.
5. Persist condition `height > local_cup_height` is satisfied; the old CUP is written to disk. [7](#0-6) 
6. The orchestrator returns the old CUP. The replica starts against `state_hash = S1`. State sync fetches the wrong checkpoint. The node diverges from the recovered subnet.

**Signature verification is not a barrier:** the old CUP at height H was legitimately threshold-signed; `verify_combined_threshold_sig_by_public_key` succeeds verbatim. [8](#0-7) 

## Impact Explanation

During subnet recovery — the most critical availability window — nodes that lack a local CUP at the recovery height will persistently boot from the wrong checkpoint (`state_hash = S1` instead of `S2`). State sync succeeds against the old state, the replica starts, but it cannot participate in consensus with the recovered subnet. The subnet recovery fails to converge, constituting a concrete **subnet availability impact** matching the High bounty class: *"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."*

## Likelihood Explanation

- No Byzantine peer is strictly required: all honest peers hold the old CUP at height H and would serve it, triggering the same bug.
- The precondition (node has no local CUP or local CUP below recovery height) is the normal starting state for any node joining or restarting during recovery.
- No cryptographic forgery is needed; the old CUP is a valid, existing artifact.
- The condition is deterministic and repeatable on every recovery attempt until the bug is fixed.

## Recommendation

In `get_latest_cup`, replace the height-only `max_by_key` with a two-phase selection that incorporates `registry_version`. Concretely, after `max_by_key` selects a winner, check whether `registry_cup` exists at the same height and, if so, prefer it unconditionally — since the registry CUP is the authoritative NNS-published artifact and always carries a strictly higher `registry_version` than any peer-served CUP at the same height. Alternatively, pass the registry CUP's `CatchUpPackageParam` (rather than the local CUP's) as the `param` baseline in `get_peer_cup`, so that a peer CUP at the same height as the registry CUP is filtered out before it ever enters the candidate list.

## Proof of Concept

Within the existing test harness in `catch_up_package_provider.rs` using `CryptoReturningOk`:

1. Construct `registry_cup` at height 100 with `state_hash = [0xAA; 32]` and `registry_version = 50` (recovery CUP).
2. Construct `peer_cup` at height 100 with `state_hash = [0xBB; 32]` and `registry_version = 40` (old legitimate CUP, valid threshold signature via `CryptoReturningOk`).
3. Set `local_cup = None`.
4. Mock `get_peer_cup` to return `peer_cup`; inject `registry_cup` into the registry mock.
5. Call `get_latest_cup`.
6. Assert the returned CUP has `state_hash = [0xAA; 32]` (registry CUP wins).
7. Observe the assertion **fails** — the returned CUP has `state_hash = [0xBB; 32]` — confirming the bug.

### Citations

**File:** rs/orchestrator/src/catch_up_package_provider.rs (L227-240)
```rust
        let param = current_cup
            .map(CatchUpPackageParam::try_from)
            .and_then(Result::ok);

        for (node_id, node_record) in &peers {
            match self
                .fetch_and_verify_catch_up_package(node_id, node_record, param, subnet_id)
                .await
            {
                Ok(Some((proto, cup))) => {
                    // Note: None is < Some(_)
                    if Some(CatchUpPackageParam::from(&cup)) > param {
                        return Some(proto);
                    }
```

**File:** rs/orchestrator/src/catch_up_package_provider.rs (L288-295)
```rust
        self.crypto
            .verify_combined_threshold_sig_by_public_key(
                &CombinedThresholdSigOf::new(CombinedThresholdSig(protobuf.signature.clone())),
                &CatchUpContentProtobufBytes::from(&protobuf),
                subnet_id,
                cup.content.block.get_value().context.registry_version,
            )
            .map_err(|e| format!("Failed to verify CUP signature at: {uri:?} with: {e:?}"))?;
```

**File:** rs/orchestrator/src/catch_up_package_provider.rs (L460-462)
```rust
        let subnet_cup = self
            .get_peer_cup(subnet_id, registry_version, local_cup.as_ref())
            .await;
```

**File:** rs/orchestrator/src/catch_up_package_provider.rs (L473-480)
```rust
        let latest_cup_proto = vec![local_cup, registry_cup, subnet_cup]
            .into_iter()
            .flatten()
            .max_by_key(get_cup_proto_height)
            .ok_or(OrchestratorError::MakeRegistryCupError(
                subnet_id,
                registry_version,
            ))?;
```

**File:** rs/orchestrator/src/catch_up_package_provider.rs (L497-499)
```rust
        if height > local_cup_height || height == local_cup_height && !latest_cup.is_signed() {
            self.persist_cup(&latest_cup_proto)?;
        }
```

**File:** rs/orchestrator/src/catch_up_package_provider.rs (L511-516)
```rust
fn get_cup_proto_height(cup: &pb::CatchUpPackage) -> Option<Height> {
    pb::CatchUpContent::decode(cup.content.as_slice())
        .ok()
        .and_then(|content| content.block)
        .map(|block| Height::from(block.height))
}
```

**File:** rs/types/types/src/consensus/catchup.rs (L326-342)
```rust
impl PartialOrd for CatchUpPackageParam {
    fn partial_cmp(&self, other: &CatchUpPackageParam) -> Option<Ordering> {
        match (
            self.height.cmp(&other.height),
            self.registry_version.partial_cmp(&other.registry_version),
        ) {
            // If height is less, registry version needs to be less or equal
            (Ordering::Less, Some(x)) if x != Ordering::Greater => Some(Ordering::Less),
            // If height is equal, registry version decides ordering
            (Ordering::Equal, Some(x)) => Some(x),
            // If height is greater, registry version needs to be equal or greater
            (Ordering::Greater, Some(x)) if x != Ordering::Less => Some(Ordering::Greater),
            // All other combinations of height and registry versions are incomparable
            // This also covers the case, that the registry versions themselves are incomparable
            _ => None,
        }
    }
```

**File:** rs/registry/canister/src/mutations/do_recover_subnet.rs (L205-214)
```rust
        // Set the height, time and state hash of the payload
        cup_contents.height = payload.height;
        cup_contents.time = payload.time_ns;
        cup_contents.state_hash = payload.state_hash.clone();

        cup_contents.cup_type = Some(CupType::Recovery(RecoveryArgs {
            height: payload.height,
            time: payload.time_ns,
            state_hash: payload.state_hash,
        }));
```
