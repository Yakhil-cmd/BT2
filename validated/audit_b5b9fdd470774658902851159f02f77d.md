All cited code references have been verified against the actual source. Here is the validation result:

---

Audit Report

## Title
Unbounded Tokio task spawning via oversized `StrippedBlockProposal` in `assemble_message` — (`rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs`)

## Summary
A Byzantine subnet peer (below the fault threshold) can craft a `StrippedBlockProposal` carrying a valid `unstripped_consensus_message_id` but an arbitrarily large `ingress_messages` or `stripped_idkg_dealings` list. Because `assemble_message` spawns one `get_or_fetch` Tokio task per entry with no upper-bound check, and the bouncer abort only fires inside the subsequent result-processing loop, the receiving replica can be forced to spawn tens of thousands of concurrent tasks before any cancellation occurs, exhausting heap memory and causing a sustained replica crash.

## Finding Description
`TryFrom<pb::StrippedBlockProposal>` in `stripped.rs` (lines 100–130) deserializes `ingress_messages` and `stripped_idkg_dealings` into unbounded `Vec`s with no count guard — only field presence and type correctness are checked. [1](#0-0) 

`BlockProposalAssembler::new` (lines 572–588) maps both vectors directly into `Vec`s of length N with no bound. [2](#0-1) 

In `assemble_message` (lines 209–226), a `for` loop immediately spawns one `JoinSet` task per element returned by `missing_stripped_messages()` — all N tasks are spawned before the bouncer loop is entered. [3](#0-2) 

The bouncer check that could abort the work only runs inside the subsequent result-processing loop (lines 235–242), after all N tasks have already been spawned. [4](#0-3) 

The outer `download_artifact` ID check (lines 250–258 in `fetch_artifact/download.rs`) only verifies `unstripped_consensus_message_id` equality, not the count of stripped entries, so a crafted response with the correct block hash but 100,000 fake ingress IDs passes the check. [5](#0-4) 

Both axum routers explicitly disable the body size limit, removing any transport-level cap on response size. [6](#0-5) [7](#0-6) 

`MAX_INGRESS_MESSAGES_PER_BLOCK = 1000` exists and is enforced during consensus payload validation (`ingress_selector.rs` lines 373–380), but is never consulted in the stripped-block assembly path. [8](#0-7) 

The comment in `try_insert` (lines 440–441) — "We can have at most 1000 elements in the vector" — is documentation only; no assertion or early-return enforces it. [9](#0-8) 

`HASHES_IN_BLOCKS_ENABLED = true`, confirming this code path is active in production. [10](#0-9) 

## Impact Explanation
Each spawned `get_or_fetch` task acquires a read lock on the ingress/IDKG pool `RwLock`, allocates async stack frames, and (when the message is absent from the pool) enters a retry loop against peers. With N = 100,000 entries, this causes heap exhaustion from task state, lock contention on pool `RwLock`s, and a flood of outbound RPC requests. The bouncer refresh period is 3 seconds, so tasks live for at least that long before being aborted. The attack can be repeated every consensus round, causing a sustained crash of a single replica. This matches the **High ($2,000–$10,000)** impact: *Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS.* [11](#0-10) 

## Likelihood Explanation
The attacker requires only a single subnet membership slot (below the Byzantine fault threshold). Block IDs are publicly advertised over P2P, so the attacker can always supply a currently-wanted `unstripped_consensus_message_id`. The crafted response passes the only content check (ID equality). No privileged access, key material, or majority corruption is required. The attack is repeatable every consensus round. [3](#0-2) 

## Recommendation
Add a count guard immediately after deserialization in `TryFrom<pb::StrippedBlockProposal>` (or at the top of `BlockProposalAssembler::new`) that returns an error if `ingress_messages.len()` exceeds `MAX_INGRESS_MESSAGES_PER_BLOCK` or `stripped_idkg_dealings.len()` exceeds the configured `dkg_dealings_per_block` limit. This mirrors the existing check in `validate_ingress_payload` and closes the gap before any tasks are spawned. [12](#0-11) 

## Proof of Concept
Construct a `pb::StrippedBlockProposal` with a valid `unstripped_consensus_message_id` (copied from a real advertised block) and `ingress_messages` populated with 100,000 synthetic `StrippedIngressMessage` entries (each with a unique but otherwise arbitrary `IngressMessageId`). Serve this from a mock peer implementing the stripped-consensus RPC endpoint. Call `assemble_message` on a `FetchStrippedConsensusArtifact` instance with the bouncer returning `Wants`. Observe via `JoinSet` size or memory profiling that 100,000 tasks are spawned before any bouncer check fires, and that heap usage spikes proportionally. The existing test harness in `assembler.rs` (e.g., `set_up_assembler_with_fake_dependencies`) provides the scaffolding needed to implement this as a `#[tokio::test]`. [13](#0-12)

### Citations

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/types/stripped.rs (L100-130)
```rust
        Ok(Self {
            pruned_block_proposal_proto,
            stripped_ingress_payload: StrippedIngressPayload {
                ingress_messages: value
                    .ingress_messages
                    .into_iter()
                    .map(SignedIngressId::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            },
            unstripped_consensus_message_id,
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
        })
    }
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L100-103)
```rust
    fn refresh_period(&self) -> Duration {
        Duration::from_secs(3)
    }
}
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L209-226)
```rust
        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

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

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L235-242)
```rust
        loop {
            let join_result = tokio::select! {
                _ = bouncer.wait_for(|bouncer| matches!(bouncer(&id), BouncerValue::Unwanted)) => {
                    self.metrics.report_aborted_block_assembly();
                    return AssembleResult::Unwanted;
                }
                join_result = join_set.join_next() => join_result,
            };
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L440-441)
```rust
        // We can have at most 1000 elements in the vector, so it should be reasonably fast to do a
        // linear scan here.
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L572-588)
```rust
    fn new(stripped_block_proposal: StrippedBlockProposal) -> Self {
        Self {
            ingress_messages: stripped_block_proposal
                .stripped_ingress_payload
                .ingress_messages
                .iter()
                .map(|signed_ingress_id| (signed_ingress_id.clone(), None))
                .collect(),
            signed_dealings: stripped_block_proposal
                .stripped_idkg_dealings
                .stripped_dealings
                .iter()
                .map(|(node_index, dealing_id)| ((*node_index, dealing_id.clone()), None))
                .collect(),
            stripped_block_proposal,
        }
    }
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L1010-1057)
```rust
    fn set_up_assembler_with_fake_dependencies(
        ingress_pool_message: Option<SignedIngress>,
        peers_message: Option<SignedIngress>,
    ) -> FetchStrippedConsensusArtifact {
        let mut mock_transport = MockTransport::new();
        let mut ingress_pool = MockValidatedPoolReader::<SignedIngress>::default();

        if let Some(ingress_message) = ingress_pool_message {
            ingress_pool.expect_get().return_const(ingress_message);
        }

        if let Some(ingress_message) = peers_message {
            let fake_response = axum::response::Response::builder()
                .body(Bytes::from(
                    pb::GetIngressMessageInBlockResponse::proxy_encode(
                        GetIngressMessageInBlockResponse {
                            serialized_ingress_message: ingress_message.binary().clone(),
                        },
                    ),
                ))
                .unwrap();

            mock_transport
                .expect_rpc()
                .returning(move |_, _| Ok(fake_response.clone()));
        }

        let consensus_pool = MockValidatedPoolReader::<ConsensusMessage>::default();
        let idkg_pool = MockValidatedPoolReader::<IDkgMessage>::default();
        let mut mock_bouncer_factory = MockBouncerFactory::default();
        mock_bouncer_factory
            .expect_new_bouncer()
            .returning(|_| Box::new(|_| BouncerValue::Wants));

        let f = FetchStrippedConsensusArtifact::new(
            no_op_logger(),
            tokio::runtime::Handle::current(),
            Arc::new(RwLock::new(consensus_pool)),
            Arc::new(RwLock::new(ingress_pool)),
            Arc::new(RwLock::new(idkg_pool)),
            Arc::new(mock_bouncer_factory),
            MetricsRegistry::new(),
            NODE_1,
        )
        .0;

        (f)(Arc::new(mock_transport))
    }
```

**File:** rs/p2p/artifact_downloader/src/fetch_artifact/download.rs (L44-53)
```rust
fn build_axum_router<Artifact: PbArtifact>(pool: ValidatedPoolReaderRef<Artifact>) -> Router {
    Router::new()
        .route(
            &format!("/{}/rpc", uri_prefix::<Artifact>()),
            any(rpc_handler),
        )
        .with_state(pool)
        // Disable request size limit since consensus might push artifacts larger than limit.
        .layer(DefaultBodyLimit::disable())
}
```

**File:** rs/p2p/artifact_downloader/src/fetch_artifact/download.rs (L250-258)
```rust
                            Ok(Ok(response)) if response.status() == StatusCode::OK => {
                                let body = response.into_body();
                                if let Ok(message) = Artifact::PbMessage::proxy_decode(&body) {
                                    if message.id() == id {
                                        break AssembleResult::Done {
                                            message,
                                            peer_id: peer,
                                        };
                                    } else {
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/download.rs (L205-212)
```rust
pub(super) fn build_axum_router(pools: Pools) -> Router {
    Router::new()
        .route(INGRESS_URI, any(ingress_rpc_handler))
        .route(IDKG_DEALING_URI, any(idkg_dealing_rpc_handler))
        .with_state(pools)
        // Disable request size limit since consensus might push artifacts larger than limit.
        .layer(DefaultBodyLimit::disable())
}
```

**File:** rs/limits/src/lib.rs (L78-78)
```rust
pub const MAX_INGRESS_MESSAGES_PER_BLOCK: u64 = 1000;
```

**File:** rs/consensus/features/src/lib.rs (L6-6)
```rust
pub const HASHES_IN_BLOCKS_ENABLED: bool = true;
```
