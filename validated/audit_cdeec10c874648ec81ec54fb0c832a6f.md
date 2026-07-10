### Title
Any Single Participant Can Permanently Deny CKD and DKG/Reshare/Refresh by Withholding Their Protocol Message — (`src/protocol/helpers.rs`, `src/confidential_key_derivation/protocol.rs`, `src/dkg.rs`)

### Summary

The `recv_from_others` helper in `src/protocol/helpers.rs` loops indefinitely until **every** participant in the session has delivered a message. There is no timeout, no skip-and-continue path, and no recovery mechanism. Any single participant in a CKD, DKG, reshare, or refresh session can permanently stall the protocol for all honest parties simply by never sending their round message. This is the direct analog of the Axis Finance EMPAM private-key withholding bug: a required contributor can grief the entire session with no recourse.

### Finding Description

**Root cause — `src/protocol/helpers.rs`, lines 19–24:**

```rust
while !seen.full() {
    let (from, msg) = chan.recv(waitpoint).await?;
    if seen.put(from) {
        messages.push((from, msg));
    }
}
```

`seen.full()` is only true when every participant (including the withholder) has been marked. `chan.recv` is an unbounded `await` with no deadline. The loop never exits unless all `n` participants contribute.

**CKD coordinator path — `src/confidential_key_derivation/protocol.rs`, lines 50–55:**

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

The coordinator must aggregate shares from **all** participants, not just a threshold. One silent participant causes `recv_from_others` to block forever, and `do_ckd_coordinator` never returns a `CKDOutput`. The CKD result is permanently unavailable to all honest parties.

**DKG / reshare / refresh path — `src/dkg.rs`, lines 422–426 and 514–528:**

`do_keyshare` calls `recv_from_others` twice: once to collect commitment hashes (round 1) and once to collect secret signing shares (round 5). Either call blocks forever if any participant withholds. Because `do_reshare` and the refresh path both delegate to `do_keyshare`, the same denial applies to reshare and refresh.

**No recovery mechanism exists.** There is no abort signal, no partial-result path, no timeout parameter, and no documented way for the remaining honest parties to restart with a reduced participant set.

### Impact Explanation

- **CKD**: A single malicious participant permanently denies the coordinator (and all honest parties) the derived confidential key for any `app_id`. The TEE application that depends on CKD output is permanently blocked.
- **DKG / reshare / refresh**: A single malicious participant permanently prevents the group from establishing or rotating a shared signing key. All subsequent signing operations are also blocked.

Both impacts fall squarely within the allowed scope:
> *High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions.*

### Likelihood Explanation

- **Attacker requirement**: Being a registered participant in the session — no privileged access, no leaked secrets.
- **Trigger**: Simply do not call `chan.send_private` / `chan.send_many` for the relevant waitpoint. The attacker's own protocol instance can return early or crash; the honest parties' instances will block indefinitely.
- **Motivation**: A participant who loses economic interest in the outcome (e.g., a departing node in a reshare, or a competitor in a CKD-gated service) can grief the entire group at zero cost.

### Recommendation

1. **Add a deadline to `recv_from_others`**: Accept an optional `Duration` or a cancellation token; return `ProtocolError::Timeout` if the deadline elapses before `seen.full()`.
2. **Allow threshold-based completion for CKD**: If the cryptographic scheme permits reconstruction from a threshold of shares (Lagrange interpolation already present in `participants.lagrange`), accept `t` shares instead of `n`.
3. **Expose an abort/cancel handle** from `make_protocol` so the application layer can time-out a stalled session and restart with a different participant set.

### Proof of Concept

**Scenario: CKD denial**

1. Three participants `[P1, P2, P3]` run `ckd(...)` with `P1` as coordinator.
2. `P2` and `P3` call `ckd(...)` normally; `P2` sends its `(norm_big_y, norm_big_c)` to `P1`.
3. `P3` (malicious) never calls `chan.send_private` — it simply drops its protocol handle.
4. Inside `do_ckd_coordinator`, `recv_from_others` reaches `seen.put(P2)` → `seen` is not full (missing `P3`) → loops back to `chan.recv(waitpoint).await` and suspends forever.
5. `P1` never returns `CKDOutput`; the confidential key is permanently unavailable.

**Scenario: DKG denial**

1. Three participants `[P1, P2, P3]` run `keygen(...)`.
2. In round 1 of `do_keyshare`, `recv_from_others` at line 422 waits for commitment hashes from `P2` and `P3`.
3. `P3` (malicious) never sends its commitment hash.
4. `recv_from_others` blocks forever; `P1` and `P2` never obtain a `KeygenOutput`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/protocol/helpers.rs (L19-24)
```rust
    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }
```

**File:** src/confidential_key_derivation/protocol.rs (L50-55)
```rust
    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
```

**File:** src/dkg.rs (L422-426)
```rust
    for (from, their_commitment_hash) in
        recv_from_others(&chan, wait_round_1, &participants, me).await?
    {
        all_hash_commitments.put(from, their_commitment_hash);
    }
```

**File:** src/dkg.rs (L514-528)
```rust
    for (from, signing_share_from) in
        recv_from_others(&chan, wait_round_3, &participants, me).await?
    {
        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        let full_commitment_from = all_full_commitments.index(from)?;
        // Step 5.2
        validate_received_share::<C>(me, from, &signing_share_from, full_commitment_from)?;

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        // Step 5.3
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
    }
```
