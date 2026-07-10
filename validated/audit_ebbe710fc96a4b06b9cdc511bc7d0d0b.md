### Title
Unauthenticated `e_j` Share in Round 1 Allows Any Participant to Abort Presign for All Honest Parties — (`src/ecdsa/ot_based_ecdsa/presign.rs`)

### Summary

In `do_presign`, each participant broadcasts their Lagrange-weighted share `e_i` of the Beaver triple's `c` component. The only validation applied to received shares is a zero-check. There is no per-participant commitment binding `e_j` to the public triple commitment `big_e`. A single malicious participant can send any non-zero scalar (e.g., `Scalar::ONE`) to corrupt the reconstructed sum `e`, causing the group-element consistency check to fail for every honest party simultaneously, with no way to identify the culprit.

### Finding Description [1](#0-0) 

`big_e` is the public commitment to the **aggregate** `e = k·d`, not to any individual share. [2](#0-1) 

Each participant broadcasts their scalar `e_i` and accumulates received `e_j` values. The only guard is: [3](#0-2) 

This rejects zero but accepts **any other scalar**, including `Scalar::ONE` or any attacker-chosen value. There is no per-participant commitment `E_j = e_j · G` that would allow honest parties to verify individual contributions before summing.

The aggregate check then fails for all honest parties: [4](#0-3) 

Because `big_e` encodes the correct sum `e_correct · G`, but the accumulated `e` now contains the attacker's forged share, the check fails deterministically for every honest participant. The error message `"received incorrect shares of kd"` gives no indication of which party sent the bad value.

The protocol specification confirms no per-share commitment is required: [5](#0-4) 

### Impact Explanation

A single malicious participant can abort every presign attempt indefinitely. Because the check at line 127 is a global aggregate check with no per-sender attribution, honest parties cannot distinguish which `e_j` was wrong. The malicious party can repeat this across every presign invocation, permanently denying the ability to produce presignatures (and therefore signatures) for all honest parties.

This matches: **High — Permanent denial of signing for honest parties under valid protocol inputs.**

### Likelihood Explanation

Any participant in the presign protocol controls their own `e_j` broadcast. No external capability is required — the attacker simply calls `presign()` with their real inputs but substitutes `Scalar::ONE` (or any non-zero scalar) for `e_i` in the message they send to peers. The attack is trivially repeatable and requires no cryptographic break.

### Recommendation

Before summing, each participant should broadcast a commitment `E_j = e_j · G` alongside `e_j`, and every receiver should verify `e_j · G == E_j` and that the set of `E_j` values is consistent with the public `big_e` (i.e., `Σ E_j == big_e · G`). This allows honest parties to identify and exclude the malicious sender. Alternatively, use a verifiable secret sharing scheme for the triple shares so that individual share validity can be checked against public commitments established during triple generation.

### Proof of Concept

```rust
// Pseudocode: one party sends e_j = Scalar::ONE instead of real share
// All honest parties hit ProtocolError::AssertionFailed at line 127
// No party can determine which participant sent the bad value

let malicious_e_i = Scalar::ONE; // instead of lambda_me * triple0.0.c
chan.send_many(wait0, &malicious_e_i)?;
// Honest parties compute e = (correct shares) + 1
// big_e != (GENERATOR * e).to_affine()  →  AssertionFailed for all
``` [6](#0-5)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L84-89)
```rust
    let e_i = args.triple0.0.c;

    // Extracting triples public variables (K, D, E)
    let big_k: ProjectivePoint = args.triple0.1.big_a.into();
    let big_d = args.triple0.1.big_b;
    let big_e = args.triple0.1.big_c;
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L107-131)
```rust
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &e_i)?;

    // Receive ej and compute e = SUM_j ej
    // Spec 1.3
    let mut e = e_i;

    for (_, e_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        if e_j.is_zero().into() {
            return Err(ProtocolError::AssertionFailed(
                "Received zero share of kd, indicating a triple wasn't available.".to_string(),
            ));
        }

        // Spec 1.4
        e += e_j;
    }

    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }
```

**File:** docs/ecdsa/ot_based_ecdsa/signing.md (L37-41)
```markdown
2. $\star$ Each $P_i$ sends $e_i$ to every party.
3. $\bullet$ Each $P_i$ waits to receive $e_j$ from each $P_j$.
4. Each $P_i$ sets $e \gets \sum_j e_j$.
5. $\blacktriangle$ Each $P_i$ *asserts* that $e \cdot G = E$.

```
