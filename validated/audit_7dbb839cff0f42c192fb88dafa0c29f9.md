Audit Report

## Title
Unbounded Duplicate `(NodeIndex, IDkgArtifactId)` Entries in `StrippedBlockProposal` Spawn N Concurrent Fetch Tasks Without Deduplication — (`rs/p2p/artifact_downloader/src/fetch_stripped_artifact/types/stripped.rs`, `assembler.rs`)

## Summary

`TryFrom<pb::StrippedBlockProposal>` collects `stripped_idkg_dealings` into a plain `Vec` with no uniqueness check. A Byzantine peer can craft a proto with N duplicate `(NodeIndex, IDkgArtifactId)` entries, causing `BlockProposalAssembler::new()` to build a `signed_dealings` Vec with N identical entries, `missing_stripped_messages()` to return N identical IDs, and `assemble_message` to spawn N concurrent `get_or_fetch` Tokio tasks for the same dealing — each of which issues live RPC calls to subnet peers in an unbounded retry loop. Assembly then permanently fails (`AssembleResult::Unwanted`) on the second duplicate insertion, but all N tasks have already been dispatched.

## Finding Description

**Root cause — no deduplication at deserialization boundary (`stripped.rs` L110–128):**

`TryFrom<pb::StrippedBlockProposal>` iterates `value.stripped_idkg_dealings` and collects into a plain `Vec<(NodeIndex, IDkgArtifactId)>` with no uniqueness check:

```rust
stripped_idkg_dealings: StrippedIDkgDealings {
    stripped_dealings: value
        .stripped_idkg_dealings
        .into_iter()
        .map(|dealing| { ... Ok((dealing.dealer_index, idkg_artifact_id)) })
        .collect::<Result<Vec<_>, ProxyDecodeError>>()?,
},
``` [1](#0-0) 

**No deduplication in `BlockProposalAssembler::new()` (`assembler.rs` L580–585):**

`signed_dealings` is built directly from the iterator, preserving all N duplicates:

```rust
signed_dealings: stripped_block_proposal
    .stripped_idkg_dealings
    .stripped_dealings
    .iter()
    .map(|(node_index, dealing_id)| ((*node_index, dealing_id.clone()), None))
    .collect(),
``` [2](#0-1) 

**N tasks spawned per Vec entry (`assembler.rs` L211–226):**

`missing_stripped_messages()` returns all `None`-valued entries — all N duplicates — and `assemble_message` spawns one `get_or_fetch` task per entry before the bouncer is consulted: [3](#0-2) 

**Each task issues live RPC calls in an unbounded retry loop (`download.rs` L301–375):**

`download_stripped_message` uses `with_max_elapsed_time(None)` — no overall timeout — and loops forever until a peer responds. The first RPC attempt is made immediately (with a per-attempt timeout of `MIN_ARTIFACT_RPC_TIMEOUT = 5s`): [4](#0-3) 

**Assembly permanently fails on first duplicate insertion (`assembler.rs` L262–271):**

`try_insert` for `SignedIDkgDealing` does a linear scan and always finds the first matching entry. After the first task inserts the dealing, the second task finds the same (now-`Some`) entry and returns `InsertionError::AlreadyInserted`, causing `assemble_message` to return `AssembleResult::Unwanted` and drop the `join_set` (aborting remaining tasks): [5](#0-4) [6](#0-5) 

**Exploit path:**
1. Byzantine peer advertises a `StrippedConsensusMessageId` whose `unstripped_consensus_message_id` points to any real block proposal hash (ID check passes because the ID is derived solely from `unstripped_consensus_message_id`, not from the dealing list).
2. When the victim fetches the stripped artifact, the Byzantine peer responds with a crafted `pb::StrippedBlockProposal` containing N copies of the same `StrippedIDkgDealing` entry.
3. Deserialization succeeds (no duplicate check), producing a `StrippedBlockProposal` with N identical entries in `stripped_dealings`.
4. `BlockProposalAssembler::new()` creates `signed_dealings` with N `None`-valued entries for the same dealing ID.
5. `missing_stripped_messages()` returns N identical `StrippedMessageId::IDkgDealing` values.
6. `assemble_message` spawns N `get_or_fetch` tasks. Each checks the local IDKG pool; if the dealing is absent (e.g., a fake or future dealing ID), each task enters `download_stripped_message`'s infinite retry loop and immediately issues an RPC call to a random peer.
7. The first task to complete inserts the dealing. The second triggers `AlreadyInserted` → `AssembleResult::Unwanted`. The `join_set` is dropped, aborting remaining tasks — but all N RPC calls have already been dispatched.
8. The victim never assembles the block from this peer and must retry, while the Byzantine peer repeats the attack each consensus round.

**Existing checks are insufficient:** The only validation in `TryFrom` checks that the `IDkgArtifactId` is a `Dealing` variant and that the `unstripped_consensus_message_id` is a `BlockProposal` hash — neither check prevents duplicate entries. The `try_assemble()` ID-mismatch check is never reached because assembly aborts earlier.

## Impact Explanation

A single Byzantine peer can sustain an amplified RPC storm against honest subnet peers: with N=1000 duplicate entries and one crafted message per consensus round (~1 s), the victim fires ~1000 concurrent `transport.rpc()` calls per second to random peers for the same dealing. This constitutes an application-level DoS on the victim replica's outbound RPC capacity and on the receiving peers' inbound RPC handlers, without requiring raw volumetric DDoS infrastructure. Additionally, the victim replica permanently fails to assemble any block proposal received from the Byzantine peer, degrading its block-assembly latency and potentially its ability to keep up with consensus under sustained attack.

**Severity: High** — matches "Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."

## Likelihood Explanation

- Requires only a single Byzantine peer, well below the consensus fault threshold (f < n/3).
- The crafted proto is trivially constructed: repeat the same `StrippedIDkgDealing` proto entry N times in the `stripped_idkg_dealings` repeated field.
- No privileged access, key material, or majority corruption required.
- The attack is repeatable every consensus round (~1 s) with no per-round cost beyond sending one crafted proto message.
- The Byzantine peer only needs to advertise a `StrippedConsensusMessageId` for any real block proposal hash currently in the victim's bouncer window.

## Recommendation

Deduplicate `stripped_idkg_dealings` at the earliest validation boundary in `TryFrom<pb::StrippedBlockProposal>`. The strictest fix is to return a `ProxyDecodeError` on any duplicate, since a well-formed stripped block proposal produced by an honest node will never contain duplicate `(NodeIndex, IDkgArtifactId)` pairs:

```rust
let mut seen = std::collections::HashSet::new();
stripped_idkg_dealings: StrippedIDkgDealings {
    stripped_dealings: value
        .stripped_idkg_dealings
        .into_iter()
        .map(|dealing| {
            let idkg_artifact_id: IDkgArtifactId = try_from_option_field(
                dealing.dealing_id,
                "StrippedIDkgDealings::dealing_id",
            )?;
            if !matches!(idkg_artifact_id, IDkgArtifactId::Dealing(_, _)) {
                return Err(ProxyDecodeError::Other(...));
            }
            let key = (dealing.dealer_index, idkg_artifact_id.clone());
            if !seen.insert(key) {
                return Err(ProxyDecodeError::Other(
                    "Duplicate (NodeIndex, IDkgArtifactId) in stripped_idkg_dealings".into()
                ));
            }
            Ok((dealing.dealer_index, idkg_artifact_id))
        })
        .collect::<Result<Vec<_>, ProxyDecodeError>>()?,
},
```

The same deduplication should be applied to `ingress_messages` in the same `TryFrom` implementation to close the analogous path for ingress entries.

## Proof of Concept

Unit test sketch (safe, no mainnet interaction):

```rust
#[test]
fn duplicate_stripped_dealings_spawn_n_tasks() {
    use crate::fetch_stripped_artifact::test_utils::{
        fake_idkg_dealing, fake_stripped_block_proposal_with_messages,
    };
    use ic_types_test_utils::ids::NODE_1;

    let dealing_id = fake_idkg_dealing(NODE_1, 1).id();
    // Build a StrippedBlockProposal with 1000 duplicate dealing entries
    let mut stripped = fake_stripped_block_proposal_with_messages(vec![]);
    for _ in 0..1000 {
        stripped
            .stripped_idkg_dealings
            .stripped_dealings
            .push((1u32, dealing_id.clone()));
    }
    let assembler = BlockProposalAssembler::new(stripped);
    let missing = assembler.missing_stripped_messages();
    // Without deduplication, missing.len() == 1000; with fix it should be 1
    assert_eq!(missing.len(), 1, "Expected deduplication; got {} tasks", missing.len());
}
```

This test will fail (asserting 1 but getting 1000) against the current code, confirming the bug. A complementary test should verify that `TryFrom<pb::StrippedBlockProposal>` returns `Err(ProxyDecodeError)` when the proto contains duplicate entries after the fix is applied.

### Citations

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/types/stripped.rs (L110-128)
```rust
            stripped_idkg_dealings: StrippedIDkgDealings {
                stripped_dealings: value
                    .stripped_idkg_dealings
                    .into_iter()
                    .map(|dealing| {
                        let idkg_artifact_id: IDkgArtifactId = try_from_option_field(
                            dealing.dealing_id,
                            "StrippedIDkgDealings::dealing_id",
                        )?;
                        if !matches!(idkg_artifact_id, IDkgArtifactId::Dealing(_, _)) {
                            return Err(ProxyDecodeError::Other(format!(
                                "The stripped IDKG artifact id {:?} is NOT for a dealing",
                                idkg_artifact_id,
                            )));
                        }
                        Ok((dealing.dealer_index, idkg_artifact_id))
                    })
                    .collect::<Result<Vec<_>, ProxyDecodeError>>()?,
            },
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L211-226)
```rust
        let stripped_message_ids = assembler.missing_stripped_messages();
        // For each stripped object in the message, try to fetch it either from the local pools
        // or from a random peer who is advertising it.
        for stripped_message_id in stripped_message_ids {
            join_set.spawn(get_or_fetch(
                stripped_message_id,
                self.ingress_pool.clone(),
                self.idkg_pool.clone(),
                self.transport.clone(),
                id.as_ref().clone(),
                self.log.clone(),
                self.metrics.clone(),
                self.node_id,
                peer_rx.clone(),
            ));
        }
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L262-271)
```rust
            if let Err(err) = assembler.try_insert_stripped_message(message) {
                warn!(
                    self.log,
                    "Failed to insert stripped message of type {}: {}. This is a bug.",
                    message_type.as_str(),
                    err
                );

                return AssembleResult::Unwanted;
            }
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L488-508)
```rust
    fn try_insert(
        &mut self,
        signed_dealing_id: IDkgArtifactId,
        signed_dealing: SignedIDkgDealing,
    ) -> Result<(), InsertionError> {
        let IDkgArtifactId::Dealing(_, _) = &signed_dealing_id else {
            return Err(InsertionError::NotNeeded);
        };

        let (_, dealing) = self
            .signed_dealings
            .iter_mut()
            .find(|((_, id), _maybe_dealing)| *id == signed_dealing_id)
            .ok_or(InsertionError::NotNeeded)?;

        if dealing.is_some() {
            Err(InsertionError::AlreadyInserted)
        } else {
            *dealing = Some(signed_dealing);
            Ok(())
        }
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L580-585)
```rust
            signed_dealings: stripped_block_proposal
                .stripped_idkg_dealings
                .stripped_dealings
                .iter()
                .map(|(node_index, dealing_id)| ((*node_index, dealing_id.clone()), None))
                .collect(),
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/download.rs (L301-375)
```rust
    let mut artifact_download_timeout = ExponentialBackoffBuilder::new()
        .with_initial_interval(MIN_ARTIFACT_RPC_TIMEOUT)
        .with_max_interval(MAX_ARTIFACT_RPC_TIMEOUT)
        .with_max_elapsed_time(None)
        .build();

    let mut rng = SmallRng::from_entropy();

    let request = match &stripped_message_id {
        StrippedMessageId::Ingress(signed_ingress_id) => {
            let request = GetIngressMessageInBlockRequest {
                signed_ingress_id: signed_ingress_id.clone(),
                block_proposal_id,
            };
            let bytes = Bytes::from(pb::GetIngressMessageInBlockRequest::proxy_encode(request));
            Request::builder().uri(INGRESS_URI).body(bytes).unwrap()
        }
        StrippedMessageId::IDkgDealing(dealing_id, node_index) => {
            let request = GetIDkgDealingInBlockRequest {
                node_index: *node_index,
                dealing_id: dealing_id.clone(),
                block_proposal_id,
            };
            let bytes = Bytes::from(pb::GetIDkgDealingInBlockRequest::proxy_encode(request));
            Request::builder()
                .uri(IDKG_DEALING_URI)
                .body(bytes)
                .unwrap()
        }
    };

    loop {
        let next_request_at = Instant::now()
            + artifact_download_timeout
                .next_backoff()
                .unwrap_or(MAX_ARTIFACT_RPC_TIMEOUT);
        if let Some(peer) = { peer_rx.peers().into_iter().choose(&mut rng) } {
            match timeout_at(next_request_at, transport.rpc(&peer, request.clone())).await {
                Ok(Ok(response)) if response.status() == StatusCode::OK => {
                    match parse_response(&stripped_message_id, response.into_body()) {
                        Ok(stripped_message) => {
                            metrics.report_finished_stripped_message_download(message_type);
                            return (stripped_message, peer);
                        }
                        Err(ParseResponseError::MessageIdMismatch) => {
                            metrics.report_download_error(
                                "mismatched_stripped_message_id",
                                message_type,
                            );
                            warn!(
                                log,
                                "Peer {} responded with wrong {} message for advert",
                                peer,
                                message_type.as_str(),
                            );
                        }
                        Err(ParseResponseError::ParsingError(reason)) => {
                            metrics.report_download_error(reason, message_type);
                        }
                    };
                }
                Ok(Ok(_response)) => {
                    metrics.report_download_error("status_not_ok", message_type);
                }
                Ok(Err(_rpc_error)) => {
                    metrics.report_download_error("rpc_error", message_type);
                }
                Err(_timeout) => {
                    metrics.report_download_error("timeout", message_type);
                }
            }
        }

        sleep_until(next_request_at).await;
    }
```
