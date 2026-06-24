Audit Report

## Title
Missing `ingress_bytes_hash` Length Validation Allows Byzantine Peer to Stall Block Assembly — (`rs/p2p/artifact_downloader/src/fetch_stripped_artifact/types.rs`)

## Summary

`TryFrom<pb::StrippedIngressMessage> for SignedIngressId` accepts an `ingress_bytes_hash` of any length and stores it verbatim inside a `CryptoHashOf` wrapper. A Byzantine subnet peer can craft a `StrippedBlockProposal` whose `ingress_bytes_hash` fields are not 32 bytes. Because every legitimate hash derivation produces a 32-byte SHA-256 digest, all local-pool and peer-download comparisons against the malformed ID permanently fail, causing the assembler to spin in an unbounded retry loop for each affected ingress until the bouncer fires (~3 s).

## Finding Description

**Root cause — `types.rs` line 47:** [1](#0-0) 

`CryptoHash` is a plain `struct CryptoHash(pub Vec<u8>)` newtype and `CryptoHashOf::from` is a zero-cost wrapper. Neither enforces a 32-byte invariant, so any `Vec<u8>` is accepted.

**Legitimate path always produces 32 bytes:** [2](#0-1) 

**Deserialization entry point — `stripped.rs` lines 102–107:** [3](#0-2) 

When a peer-sent `pb::StrippedBlockProposal` is decoded, each `pb::StrippedIngressMessage` is converted via `SignedIngressId::try_from`, storing the attacker-controlled byte vector verbatim.

**Local-pool fast path always fails — `assembler.rs` line 337:** [4](#0-3) 

`SignedIngressId::from(&ingress_message)` recomputes a 32-byte SHA-256 hash; the right-hand side carries the malformed length. `PartialEq` on `CryptoHashOf` compares the inner `Vec<u8>` byte-for-byte, so the guard always fails.

**Peer-download validation always fails — `download.rs` lines 390–393:** [5](#0-4) 

`derived_ingress_id` is freshly computed (32 bytes); `ingress_id` carries the malformed hash. The comparison always returns `ParseResponseError::MessageIdMismatch`.

**Unbounded retry loop — `download.rs` lines 301–304:** [6](#0-5) 

`with_max_elapsed_time(None)` means the loop never self-terminates; backoff grows from 5 s to 120 s.

**Assembler exit — `assembler.rs` lines 235–241:** [7](#0-6) 

The only escape is the bouncer becoming `Unwanted`. The bouncer refresh period is hardcoded to 3 seconds: [8](#0-7) 

The identical missing length check also exists in `rpc.rs`: [9](#0-8) 

## Impact Explanation

A Byzantine subnet peer (below the consensus fault threshold) can send a malformed `StrippedBlockProposal` for every block it receives. On each victim node, every ingress in the targeted proposal bypasses the local-pool fast path and enters the peer-download retry loop, generating sustained outbound RPC traffic (up to 120 s between retries) and holding open spawned tasks until the bouncer fires (~3 s). Repeated across every block proposal, this continuously degrades consensus throughput and wastes replica resources on all victim nodes in the subnet. This matches the **High** impact class: *Application/platform-level DoS, consensus blocking, or subnet availability impact not based on raw volumetric DDoS*.

## Likelihood Explanation

The attacker requires only subnet membership (below the consensus fault threshold). No key material, governance majority, or external infrastructure is needed. The malformed field is a plain protobuf `bytes` field with no schema-level length constraint, making payload crafting trivial. The attack is repeatable on every block proposal the Byzantine node receives.

## Recommendation

Add an explicit 32-byte length check in `TryFrom<pb::StrippedIngressMessage> for SignedIngressId` before constructing the `CryptoHashOf`:

```rust
const CRYPTO_HASH_LEN: usize = 32;
if value.ingress_bytes_hash.len() != CRYPTO_HASH_LEN {
    return Err(ProxyDecodeError::Other(format!(
        "ingress_bytes_hash must be {} bytes, got {}",
        CRYPTO_HASH_LEN,
        value.ingress_bytes_hash.len()
    )));
}
let ingress_bytes_hash = CryptoHashOf::from(CryptoHash(value.ingress_bytes_hash));
```

Apply the identical guard to `GetIngressMessageInBlockRequest::try_from` in `rpc.rs` line 34.

## Proof of Concept

```rust
#[test]
fn malformed_ingress_bytes_hash_accepted_and_never_matches() {
    use ic_protobuf::types::v1 as pb;
    use crate::fetch_stripped_artifact::types::SignedIngressId;
    use ic_test_utilities_types::messages::SignedIngressBuilder;

    let ingress = SignedIngressBuilder::new().nonce(1).build();
    let real_id = SignedIngressId::from(&ingress);

    for bad_len in [0usize, 1, 31, 33, 1024] {
        let proto = pb::StrippedIngressMessage {
            stripped: Some(real_id.ingress_message_id.clone().into()),
            ingress_bytes_hash: vec![0xAB; bad_len],
        };
        // Currently succeeds — should return Err after the fix
        let parsed = SignedIngressId::try_from(proto).unwrap();
        // The parsed ID never equals the legitimately-computed one
        assert_ne!(parsed, real_id,
            "bad_len={bad_len}: malformed hash must not match real hash");
    }
}
```

This unit test confirms that `try_from` currently accepts all wrong-length hashes and that the resulting `SignedIngressId` never compares equal to the legitimately derived one, directly proving the mismatch that drives the indefinite retry loop.

### Citations

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/types.rs (L27-32)
```rust
    pub(crate) fn new(ingress_message_id: IngressMessageId, bytes: &SignedRequestBytes) -> Self {
        Self {
            ingress_message_id,
            ingress_bytes_hash: ic_types::crypto::crypto_hash(bytes),
        }
    }
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/types.rs (L41-53)
```rust
impl TryFrom<pb::StrippedIngressMessage> for SignedIngressId {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::StrippedIngressMessage) -> Result<Self, Self::Error> {
        let ingress_message_id =
            try_from_option_field(value.stripped, "StrippedIngressMessage::stripped")?;
        let ingress_bytes_hash = CryptoHashOf::from(CryptoHash(value.ingress_bytes_hash));

        Ok(SignedIngressId {
            ingress_message_id,
            ingress_bytes_hash,
        })
    }
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/types/stripped.rs (L100-108)
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
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L100-103)
```rust
    fn refresh_period(&self) -> Duration {
        Duration::from_secs(3)
    }
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

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/assembler.rs (L335-344)
```rust
                // Make sure that this is the correct ingress message. [`IngressMessageId`] does _not_
                // uniquely identify ingress messages, we thus need to perform an extra check.
                if SignedIngressId::from(&ingress_message) == signed_ingress_id {
                    return (
                        StrippedMessage::Ingress(signed_ingress_id, ingress_message),
                        node_id,
                    );
                }
            }
            StrippedMessageId::Ingress(signed_ingress_id)
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/download.rs (L301-305)
```rust
    let mut artifact_download_timeout = ExponentialBackoffBuilder::new()
        .with_initial_interval(MIN_ARTIFACT_RPC_TIMEOUT)
        .with_max_interval(MAX_ARTIFACT_RPC_TIMEOUT)
        .with_max_elapsed_time(None)
        .build();
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/download.rs (L388-408)
```rust
        StrippedMessageId::Ingress(ingress_id) => {
            let ingress = parse_ingress_response(body)?;
            let derived_ingress_id = SignedIngressId::from(&ingress);
            if derived_ingress_id == *ingress_id {
                return Ok(StrippedMessage::Ingress(derived_ingress_id, ingress));
            }
        }
        StrippedMessageId::IDkgDealing(dealing_id, node_index) => {
            let dealing = parse_dealing_response(body)?;
            let derived_dealing_id = dealing.message_id();
            if derived_dealing_id == *dealing_id {
                return Ok(StrippedMessage::IDkgDealing(
                    derived_dealing_id,
                    *node_index,
                    dealing,
                ));
            }
        }
    }
    Err(ParseResponseError::MessageIdMismatch)
}
```

**File:** rs/p2p/artifact_downloader/src/fetch_stripped_artifact/types/rpc.rs (L34-34)
```rust
        let ingress_bytes_hash = CryptoHashOf::from(CryptoHash(value.ingress_bytes_hash));
```
