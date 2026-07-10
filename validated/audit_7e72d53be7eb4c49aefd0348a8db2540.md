### Title
Missing Participant-Set Binding on Triple Consumption Corrupts Presignature Outputs — (`src/ecdsa/ot_based_ecdsa/presign.rs`)

---

### Summary

The OT-based ECDSA presign protocol explicitly omits the check that the participant set consuming a Beaver triple matches the participant set that generated it. A malicious coordinator can supply a triple generated for a larger participant set to a presign session with a different (overlapping) participant set. Because Lagrange coefficients are computed over the presign participant set rather than the triple-generation participant set, the resulting presignature is cryptographically invalid. Honest parties accept and store this corrupted output, permanently blocking signing for that presignature slot.

---

### Finding Description

`TriplePub` records the participant set that generated the triple: [1](#0-0) 

When `presign()` consumes a triple, it validates only that the threshold values match, and contains an explicit comment acknowledging the participant-set check is omitted: [2](#0-1) 

The rationale given — *"presumably they need to have been present in order to have shares"* — is insufficient. Consider:

- Triple generated for participant set **P₀ = {A, B, C, D}** with threshold **t₀ = 3**.
- Presign session launched for participant set **P₁ = {A, B, C}** with threshold **t₁ = 3**.

Because P₁ ⊆ P₀, participants A, B, C each hold a valid triple share from the 4-party generation. The threshold check `t₀ == t₁` passes. The presign protocol proceeds, but Lagrange coefficients are now computed over **P₁ = {A, B, C}** instead of **P₀ = {A, B, C, D}**. The secret reconstruction identity `a = Σ λᵢ(P₀) · aᵢ` no longer holds when evaluated with `λᵢ(P₁)`, so the reconstructed Beaver triple value is wrong. The presignature output `(R, k_share, χ_share)` is silently corrupted.

The `ParticipantList` type used throughout the protocol is designed to be hashed into transcripts and compared, making a binding check straightforward: [3](#0-2) 

No such comparison is performed between `args.triple0.1.participants` / `args.triple1.1.participants` and the presign `participants` list.

---

### Impact Explanation

**High — Corruption of presign outputs so honest parties accept unusable cryptographic outputs.**

Every honest participant completes the presign protocol and stores a `PresignOutput` that is internally inconsistent: the embedded `R` value does not correspond to the Lagrange-weighted sum of the participants' `k` shares under the actual signing set. Any subsequent `sign()` call using this presignature will produce an invalid ECDSA signature. Because presignatures are consumed on use, the slot is permanently wasted. If a coordinator systematically poisons all pre-generated presignatures this way, signing is permanently denied for honest parties — matching the **High: Permanent denial of signing** impact category.

---

### Likelihood Explanation

The attack requires a **malicious coordinator** who controls which triples are assigned to which presign sessions. This is an explicitly documented trust assumption in the OT-based ECDSA orchestration model, where the coordinator assigns triples from a pool: [4](#0-3) 

A coordinator who deviates from the honest assignment — e.g., by assigning a triple from a 4-party generation to a 3-party presign session — triggers the bug with no cryptographic capability required. The attack is deterministic and requires only knowledge of which triples were generated for which participant sets, information the coordinator necessarily possesses.

---

### Recommendation

Add an explicit participant-set equality check in `presign()` immediately after the threshold check:

```rust
// Verify that the triple participant sets match the presign participant set
if args.triple0.1.participants != participants.participants().to_vec()
    || args.triple1.1.participants != participants.participants().to_vec()
{
    return Err(InitializationError::BadParameters(
        "Triple participant set must exactly match presign participant set".to_string(),
    ));
}
```

Remove the misleading comment that implies participant presence is a sufficient guard. The `TriplePub.participants` field already carries the necessary information; it simply needs to be validated.

---

### Proof of Concept

1. Run triple generation for **P₀ = {0, 1, 2, 3}**, threshold = 3. Each of {0,1,2,3} receives a `TripleShare` and a `TriplePub` with `participants = [0,1,2,3]`.
2. Launch a presign session for **P₁ = {0, 1, 2}**, threshold = 3, supplying the triples from step 1 to participants {0,1,2}.
3. The threshold check at `presign.rs:43` passes (`3 == 3`). The participant-set check is absent.
4. Inside `do_presign`, Lagrange coefficients are computed via `participants.lagrange(me)` where `participants` is the 3-element list `{0,1,2}`. The triple shares were generated under the 4-element Lagrange basis `{0,1,2,3}`.
5. The resulting `PresignOutput` encodes an `R` and key-share values that are inconsistent. A subsequent `sign()` call produces a signature that fails standard ECDSA verification against the master public key. [5](#0-4)

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L655-667)
```rust
        ret.push((
            TripleShare {
                a: *a_i,
                b: *b_i,
                c: *c_i,
            },
            TriplePub {
                big_a,
                big_b,
                big_c,
                participants: participants.clone().into(),
                threshold,
            },
```

**File:** src/ecdsa/ot_based_ecdsa/presign.rs (L20-61)
```rust
pub fn presign(
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.value(),
            max: participants.len(),
        });
    }

    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(ctx.shared_channel(), participants, me, args);
    Ok(make_protocol(ctx, fut))
```

**File:** src/participants.rs (L74-84)
```rust
/// Represents a sorted list of participants.
///
/// The advantage of this data structure is that it can be hashed in the protocol transcript,
/// since everybody will agree on its order.
#[derive(Clone, Debug, Serialize)]
pub struct ParticipantList {
    participants: Vec<Participant>,
    /// This maps each participant to their index in the vector above.
    #[serde(skip_serializing)]
    indices: HashMap<Participant, usize>,
}
```

**File:** docs/ecdsa/ot_based_ecdsa/orchestration.md (L64-79)
```markdown
## Discarding information

Each phase can be run many times in advance, recording the information
public information produced, as well as the list of parties which produced it.
Then, this output is consumed by having a set of parties use it
for a subsequent phase.
It's **critical** that the output is then destroyed, so that no other
group of parties attempts to re-use that output for another phase.
In particular, the parties need some way of agreeing on which
outputs have been created and used.
If the threshold $t_i$ is such that $N_{i} \leq 2t - 1$, then it's impossible
to have two non-overlapping quorums, so if each party locally registers the
fact that an output has been used, then agreement can be had not to
use a certain output.
Otherwise, you might have two independent groups of parties trying
to use the same output, which is bad.
```
