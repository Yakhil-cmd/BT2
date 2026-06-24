The code evidence is confirmed. Let me verify the `retain_active_transcripts` path and the `INACTIVE_TRANSCRIPT_PURGE_SECS` trigger.

Audit Report

## Title
Missing stashed pre-signature transcripts in `get_active_transcripts` causes key deletion and threshold signing failures — (`rs/consensus/idkg/src/lib.rs`)

## Summary

`get_active_transcripts` in `rs/consensus/idkg/src/lib.rs` iterates `pre_signature_stashes` but inserts only `stash.key_transcript` into the active set, omitting all pre-signature transcripts stored within each stash. `retain_keys_for_transcripts` then deletes every canister threshold key not identified by an active transcript. After pre-signatures are delivered to execution and cleared from `available_pre_signatures`, their keys are deleted on the next purge cycle, causing `create_sig_share` to fail with `SecretSharesNotFound` when those pre-signatures are consumed for signing.

## Finding Description

**Root cause — `get_active_transcripts` (`rs/consensus/idkg/src/lib.rs`, lines 415–429):**

The loop over `pre_signature_stashes` inserts only the stash's `key_transcript`:

```rust
for stash in state.pre_signature_stashes().values() {
    active_transcripts.insert((*stash.key_transcript).clone()); // pre-sig transcripts omitted
}
```

It never iterates `stash.pre_signatures.values().flat_map(|p| p.iter_idkg_transcripts())`.

**Correct reference — `complaints.rs::active_transcripts` (`rs/consensus/idkg/src/complaints.rs`, lines 752–757):**

```rust
let stashed_pre_sig_transcripts = state
    .pre_signature_stashes()
    .values()
    .flat_map(|stash| stash.pre_signatures.values())
    .flat_map(|pre_sig| pre_sig.iter_idkg_transcripts())
    .map(|transcript| (transcript.transcript_id, transcript));
```

This function correctly includes both key and pre-signature transcripts from every stash.

**Blockchain path provides no coverage:** `create_data_payload_helper_2` explicitly clears `available_pre_signatures` in every new payload (`rs/consensus/idkg/src/payload_builder.rs`, line 655):

```rust
idkg_payload.available_pre_signatures.clear();
```

Once pre-signatures are in `pre_signature_stashes` in replicated state, they are absent from every subsequent IDKG payload. `IDkgPayload::active_transcripts()` covers only `available_pre_signatures` and `pre_signatures_in_creation`, providing no protection.

**Key deletion mechanism — `retain_keys_for_transcripts` (`rs/crypto/src/sign/canister_threshold_sig/idkg/retain_active_keys.rs`, lines 47–52):**

```rust
let active_key_ids = internal_transcripts?
    .iter()
    .map(|active_transcript| KeyId::from(active_transcript.combined_commitment.commitment()))
    .collect();
vault.idkg_retain_active_keys(active_key_ids, oldest_public_key)
```

Every key whose transcript is absent from the active set is permanently deleted from the vault.

**Exploit flow:**
1. Pre-signatures complete and appear in `available_pre_signatures` in the IDKG payload.
2. They are delivered to execution and merged into `pre_signature_stashes` in replicated state.
3. The next IDKG payload clears `available_pre_signatures` — transcripts now exist only in the stash.
4. `purge_inactive_transcripts` fires (every `INACTIVE_TRANSCRIPT_PURGE_SECS`), calls `get_active_transcripts`, which omits the stashed pre-signature transcripts.
5. `retain_keys_for_transcripts` deletes the canister threshold keys for those transcripts.
6. A signing request is matched with a stashed pre-signature.
7. `create_sig_share` fails with `SecretSharesNotFound` — the keys are gone.

**Test confirms the bug:** `test_get_active_transcripts` (`rs/consensus/idkg/src/lib.rs`, line 706) sets `stashed_transcripts = stashes.len() as u64` — counting only one transcript per stash (the key transcript) — and asserts `chain_transcripts + stashed_transcripts`. With `fake_pre_signature_stash(&key_id, 5)` creating 5 pre-signatures per stash, the test passes precisely because it encodes the buggy behavior. The `complaints.rs` test at line 1172 asserts `9` transcripts (1 key + 2×4 pre-signature transcripts) for the same stash structure, demonstrating the correct count.

## Impact Explanation

Threshold signing requests matched against stashed pre-signatures fail permanently on every node in every subnet that uses threshold signing, after any purge cycle following pre-signature delivery. This is a deterministic, subnet-wide availability failure for the threshold signing protocol — a core IC infrastructure component. This matches **High ($2,000–$10,000): Application/platform-level DoS, consensus blocking, or subnet availability impact not based on raw volumetric DDoS**.

## Likelihood Explanation

No adversarial action is required. The failure is deterministic: any subnet that (a) has completed pre-signatures, (b) delivered them to execution (moving them into `pre_signature_stashes`), and (c) experienced one `purge_inactive_transcripts` cycle will have the affected keys deleted. This is normal operation for any subnet actively using threshold signing. The purge fires periodically on every node independently.

## Recommendation

In `get_active_transcripts` (`rs/consensus/idkg/src/lib.rs`, lines 418–421), add the same pre-signature transcript iteration already present in `complaints.rs::active_transcripts`:

```rust
for stash in state.pre_signature_stashes().values() {
    active_transcripts.insert((*stash.key_transcript).clone());
    // Add: retain pre-signature transcripts
    for pre_sig in stash.pre_signatures.values() {
        for transcript in pre_sig.iter_idkg_transcripts() {
            active_transcripts.insert(transcript.clone());
        }
    }
}
```

Update `test_get_active_transcripts` to compute `stashed_transcripts` as `stashes.len() + total_pre_sig_transcript_count` to prevent regression.

## Proof of Concept

The existing test infrastructure directly demonstrates the differential. In `test_get_active_transcripts` (`rs/consensus/idkg/src/lib.rs`, lines 701–719), stashes are created with `fake_pre_signature_stash(&key_id, 5)` (5 pre-signatures per stash). The assertion at line 716–719 passes with `stashed_transcripts = stashes.len()` (one per stash), confirming only key transcripts are counted. Running the same state through `complaints.rs::active_transcripts` (as done in the test at line 1172, which asserts 9 transcripts for 2 pre-signatures) would yield a strictly larger set. A differential unit test instantiating the same `PreSignatureStash` state and comparing the output of both functions directly proves the omission. Additionally, an integration test that: (1) delivers pre-signatures to execution, (2) triggers `purge_inactive_transcripts`, then (3) attempts `create_sig_share` using a stashed pre-signature, will reproduce the `SecretSharesNotFound` failure deterministically.