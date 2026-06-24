Audit Report

## Title
Byzantine Dealer Out-of-Range Plaintext Chunks Bypass `verify_dealing`, Triggering Hours-Long `CheatingDealerDlogSolver` BSGS Stall on Honest Receivers — (`rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/groth20_bls12_381/dealing.rs`)

## Summary

The NIZK chunking proof verifier (`verify_chunking`) enforces only that response scalars `z_s` fall within a bound `zz` that is orders of magnitude larger than `CHUNK_MAX = 0xFFFF`, without checking that the committed plaintext chunk values themselves lie in `[0, CHUNK_MAX]`. A Byzantine subnet node acting as a DKG dealer can craft a dealing with out-of-range chunks that passes every check in `verify_dealing` and is included in the transcript. Every honest receiver that subsequently calls `compute_threshold_signing_key` will trigger `CheatingDealerDlogSolver` — a BSGS solver over a ~2^40 search space that the production code itself comments "may take hours" — stalling the replica and blocking subnet participation.

## Finding Description

**Root cause — `verify_chunking` does not enforce `[0, CHUNK_MAX]` on plaintexts.**

In `nizk_chunking.rs` lines 343–351, the only scalar bound checked is:

```rust
let ss = n * m * (CHUNK_SIZE - 1) * CHALLENGE_MASK;
let zz = 2 * NUM_ZK_REPETITIONS * ss;
let zz_big = Scalar::from_usize(zz);

for z_sk in nizk.z_s.iter() {
    if z_sk >= &zz_big {
        return Err(ZkProofChunkingError::InvalidProof);
    }
}
```

`zz` is vastly larger than `CHUNK_MAX`. The proof never binds the prover to use chunks in `[0, CHUNK_MAX]`; a Byzantine dealer can choose any chunk value that keeps `z_s` within `[-zz, zz)`.

**`verify_dealing` contains no plaintext range check.**

The call chain in `dealing.rs` lines 258–271 is: `verify_all_shares_are_present_and_well_formatted` → `verify_public_coefficients_match_threshold` → `verify_zk_proofs`. None of these steps check that the committed plaintext chunk values are within `[0, CHUNK_MAX]`.

**The existing test `should_decrypt_correctly_for_cheating_dealer` confirms the bypass.**

In `tests/forward_secure.rs` lines 132–204, the test explicitly constructs chunks with values `> CHUNK_MAX` via `PlaintextChunks::new_unchecked`, encrypts them, and asserts `verify_ciphertext_integrity` returns `Ok(())` — confirming the dealing passes all verification.

**`dec_chunks` unconditionally invokes `CheatingDealerDlogSolver` on any out-of-range chunk.**

In `forward_secure.rs` lines 820–834, after `HonestDealerDlogLookupTable` (which covers only `[0, 0xFFFF]`) returns `None` for any chunk, the code constructs `CheatingDealerDlogSolver::new(n, m)` and runs BSGS. The production comment is explicit: "It may take hours to brute force a cheater's discrete log."

**`CheatingDealerDlogSolver` is designed for a ~2^40 search space.**

In `dlog_recovery.rs` lines 340–366, the solver allocates up to 2 GiB (`MAX_TABLE_MBYTES = 2 * 1024`) and iterates `scale_range = 1 << CHALLENGE_BITS` (= 256) delta values, each requiring a full BSGS pass over a range of `2*zz - 1 ≈ 2^40`. The test comment at `tests/dlog_recovery.rs` lines 108–110 confirms: "a malicious DKG participant can force us to search around 2^40 candidates for a discrete log."

## Impact Explanation

This is a **High** severity finding matching the allowed impact: "Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS."

A single Byzantine dealing causes every honest receiver replica to CPU-stall for hours during `compute_threshold_signing_key`. With `NUM_CHUNKS = 16` chunks per dealing, a maximally malicious dealing forces 16 sequential BSGS invocations per receiver. The stall blocks the receiver from participating in consensus and signing threshold signatures for the duration of key loading. The attack is non-volumetric: one crafted dealing suffices.

## Likelihood Explanation

The attacker must be a registered DKG dealer — a subnet node — which is a Byzantine protocol peer below the consensus fault threshold. No privileged key, governance majority, or threshold corruption is required. Crafting the dealing is straightforward: the prover loop in `prove_chunking` already retries until `z_s` is in range regardless of chunk magnitude, so a valid NIZK proof over out-of-range chunks is trivially constructable. The attack is locally testable via the existing test `should_decrypt_correctly_for_cheating_dealer` and the `#[ignore]`-tagged benchmark `print_time_for_cheating_dlog_solver_to_run`.

## Recommendation

Add an explicit plaintext-range check inside `verify_chunking` or `verify_zk_proofs` that rejects any dealing whose ciphertext chunks would fall outside `[0, CHUNK_MAX]`. The most direct fix is to tighten the `z_s` bound in `verify_chunking` from `zz = 2 * NUM_ZK_REPETITIONS * n * m * (CHUNK_SIZE - 1) * CHALLENGE_MASK` to a bound derived from `n * m * CHUNK_MAX`, which would reject any proof produced with out-of-range chunks. Alternatively, add a range proof or verify that the combined ciphertext group elements lie in the subgroup `{g^0, g^1, ..., g^CHUNK_MAX}` during dealing verification, ensuring `CheatingDealerDlogSolver` is never reachable from a verified dealing.

## Proof of Concept

The existing test `should_decrypt_correctly_for_cheating_dealer` in `tests/forward_secure.rs` already validates the full exploit path (steps 1–4):

1. Construct chunks with values `> CHUNK_MAX` using `PlaintextChunks::new_unchecked`.
2. Encrypt with `enc_chunks` — succeeds.
3. Assert `verify_ciphertext_integrity` returns `Ok(())` — confirmed by the test assertion at line 194.
4. Call `dec_chunks` — triggers `CheatingDealerDlogSolver` internally.

The timing impact can be confirmed by running the `#[ignore]`-tagged benchmark `print_time_for_cheating_dlog_solver_to_run` in `tests/cheating_dealer.rs` lines 49–79, which measures wall-clock time for 16 BSGS invocations on a 13-node subnet.