### Title
Missing Vector Length Validation Before Index Access in `do_generation_many` Causes Panic-Based Protocol Abort — (File: src/ecdsa/ot_based_ecdsa/triples/generation.rs)

### Summary
In `do_generation_many`, messages received from other participants contain `Vec`-typed fields that are indexed with `[i]` for `i in 0..N` without any prior length validation. A malicious participant can send a crafted message with fewer than `N` elements in any of these vectors, triggering an out-of-bounds index panic in every honest node's protocol execution, permanently aborting triple generation and thus signing for all honest parties.

### Finding Description

`do_generation_many<const N: usize>` in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` receives several network messages whose fields are `Vec`-typed and then immediately indexed with `[i]` for `i in 0..N`. There is no guard that checks `vec.len() == N` before any of these accesses.

**Instance 1 — Round 2 commitment collection (line 180–183):**

```rust
let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
for i in 0..N {
    all_commitments_vec[i].put(from, commitments[i]); // panics if commitments.len() < N
}
``` [1](#0-0) 

**Instance 2 — Round 3 `PolynomialCommitmentsMessageMany` processing (lines 335–342):**

```rust
for i in 0..N {
    let their_big_e   = &their.big_e_v[i];      // panics if big_e_v.len() < N
    let their_big_f   = &their.big_f_v[i];      // panics if big_f_v.len() < N
    let their_big_l   = &their.big_l_v[i];      // panics if big_l_v.len() < N
    let their_randomizer  = &their.randomizer_v[i];   // panics
    let their_phi_proof0  = &their.phi_proof0_v[i];   // panics
    let their_phi_proof1  = &their.phi_proof1_v[i];   // panics
``` [2](#0-1) 

The `PolynomialCommitmentsMessageMany` struct holds six independent `Vec` fields, none of which are length-checked: [3](#0-2) 

**Instance 3 — Round 3 private share accumulation (lines 406–411):** [4](#0-3) 

**Instance 4 — Round 4 `big_c_j_v` / `their_phi_proofs` (lines 470–475):** [5](#0-4) 

**Instance 5 — Round 5 `c_j_i_v` accumulation (lines 629–631):** [6](#0-5) 

The protocol executor drives the async future via `poke()`: [7](#0-6) 

A Rust index-out-of-bounds access (`vec[i]` where `i >= vec.len()`) is an unconditional panic. Because the future is polled inside `poke()` with no panic boundary, the panic propagates directly to the application layer, crashing the thread running the protocol. All honest participants that have already committed to this session are left with no way to complete triple generation.

The attacker entry point is `Protocol::message(from, data)`, the public API through which the application delivers incoming network messages: [8](#0-7) 

The attacker is any participant enrolled in a `generate_triple_many` session. They know `N` because it is a compile-time constant shared by all participants. They craft a single message for the target waitpoint with any of the six `Vec` fields set to length 0 (or any value less than `N`). The message passes deserialization (MessagePack happily decodes an empty array), and the panic fires on the first `[0]` access.

The analog to the external report is exact: the external report's root cause is that the code iterates over all transactions without first asserting the list has the expected length (2). Here, the code iterates `for i in 0..N` over attacker-supplied vectors without first asserting each vector has exactly `N` elements.

### Impact Explanation
**High** — A single malicious participant in any `generate_triple` or `generate_triple_many` session can permanently abort triple generation for all honest parties in that session by sending one crafted message. Because OT-based ECDSA presigning depends on triples, this constitutes permanent denial of signing for honest parties under valid protocol inputs. The panic propagates out of `poke()` with no recovery path. [9](#0-8) 

### Likelihood Explanation
**Medium** — Any enrolled participant (no special privilege required) can trigger this with a single crafted message at any of five distinct protocol rounds. The attacker only needs to be a legitimate participant in the session, which is the documented trust assumption for this protocol.

### Recommendation
Before the `for i in 0..N` loop in each of the five instances, add an explicit length check and return a `ProtocolError` instead of panicking. For example, for `PolynomialCommitmentsMessageMany`:

```rust
if their.big_e_v.len() != N || their.big_f_v.len() != N
    || their.big_l_v.len() != N || their.randomizer_v.len() != N
    || their.phi_proof0_v.len() != N || their.phi_proof1_v.len() != N
{
    return Err(ProtocolError::AssertionFailed(format!(
        "message from {from:?} has wrong number of elements (expected {N})"
    )));
}
```

Apply the same pattern to the `commitments`, `(a_j_i_v, b_j_i_v)`, `(big_c_j_v, their_phi_proofs)`, and `c_j_i_v` receive sites. This mirrors the external report's recommendation to "verify the transaction list length."

### Proof of Concept

1. Start a `generate_triple_many::<2>` session with three participants: honest `P1`, honest `P2`, and malicious `P3`.
2. `P3` participates honestly through Round 2 (commitment exchange).
3. At Round 3 (waitpoint `wait2`), instead of sending a valid `PolynomialCommitmentsMessageMany` with all six vectors of length 2, `P3` sends a message where `big_e_v` is an empty `Vec` (`[]`).
4. `P1` and `P2` receive this message via `recv_from_others` at `wait2`.
5. The loop `for i in 0..2` executes; on `i = 0`, `their.big_e_v[0]` panics with index out of bounds.
6. The panic propagates through `fut.poll_unpin()` inside `poke()`, crashing the thread on both `P1` and `P2`.
7. Triple generation is permanently aborted; no signing can proceed.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L97-106)
```rust
#[derive(Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
struct PolynomialCommitmentsMessageMany {
    big_e_v: Vec<PolynomialCommitment>,
    big_f_v: Vec<PolynomialCommitment>,
    big_l_v: Vec<PolynomialCommitment>,
    randomizer_v: Vec<Randomness>,
    phi_proof0_v: Vec<dlog::Proof<Secp256K1Sha256>>,
    phi_proof1_v: Vec<dlog::Proof<Secp256K1Sha256>>,
}
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L180-184)
```rust
        let (from, commitments): (_, Vec<_>) = chan.recv(wait0).await?;
        for i in 0..N {
            all_commitments_vec[i].put(from, commitments[i]);
        }
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L335-342)
```rust
            for i in 0..N {
                let all_commitments = &all_commitments_vec[i];
                let their_big_e = &their.big_e_v[i];
                let their_big_f = &their.big_f_v[i];
                let their_big_l = &their.big_l_v[i];
                let their_randomizer = &their.randomizer_v[i];
                let their_phi_proof0 = &their.phi_proof0_v[i];
                let their_phi_proof1 = &their.phi_proof1_v[i];
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L400-412)
```rust
        for (_, (a_j_i_v, b_j_i_v)) in recv_from_others::<(
            Vec<SerializableScalar<C>>,
            Vec<SerializableScalar<C>>,
        )>(&chan, wait3, &participants, me)
        .await?
        {
            for i in 0..N {
                let a_j_i = &a_j_i_v[i];
                let b_j_i = &b_j_i_v[i];
                a_i_v[i] += &a_j_i.0;
                b_i_v[i] += &b_j_i.0;
            }
        }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L470-476)
```rust
            for i in 0..N {
                let big_e_j_zero = &big_e_j_zero_v[i];
                let big_f = &big_f_v[i];

                let big_c_j = big_c_j_v[i].value();
                let their_phi_proof = &their_phi_proofs[i];

```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L626-633)
```rust
    for (_, c_j_i_v) in
        recv_from_others::<Vec<SerializableScalar<C>>>(&chan, wait6, &participants, me).await?
    {
        for i in 0..N {
            let c_j_i = c_j_i_v[i].0;
            c_i_v[i] += c_j_i;
        }
    }
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L717-727)
```rust
pub fn generate_triple(
    participants: &[Participant],
    me: Participant,
    threshold: impl Into<ReconstructionLowerBound>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = TripleGenerationOutput>, InitializationError> {
    let (participants, threshold) = validate_triple_inputs(participants, threshold)?;
    let ctx = Comms::new();
    let fut = do_generation(ctx.clone(), participants, me, threshold, rng);
    Ok(make_protocol(ctx, fut))
}
```

**File:** src/protocol/internal.rs (L477-510)
```rust
    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError> {
        let mut polled_once_already = false;
        loop {
            // If there's outgoing messages, request to send them.
            if let Some(outgoing) = self.comms.outgoing() {
                return Ok(match outgoing {
                    Message::Many(m) => Action::SendMany(m),
                    Message::Private(to, m) => Action::SendPrivate(to, m),
                });
            }
            // If we already have a return result, return it.
            if let Some(result) = self.result.take() {
                return Ok(Action::Return(result?));
            }
            // If this is the second iteration, we already polled the future and there's no
            // progress that can be made.
            if polled_once_already {
                return Ok(Action::Wait);
            }
            // If we don't have a future, this is an extraneous poke() call, so return Wait.
            let Some(fut) = self.fut.as_mut() else {
                return Ok(Action::Wait);
            };
            // Now poll the future. It may generate some more messages to send or a return value,
            // so go back and check all of those again.
            polled_once_already = true;
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            if let std::task::Poll::Ready(result) = fut.poll_unpin(&mut cx) {
                self.result = Some(result);
                self.fut = None;
            }
        }
    }
```

**File:** src/protocol/internal.rs (L512-514)
```rust
    fn message(&mut self, from: Participant, data: MessageData) {
        self.comms.push_message(from, data);
    }
```
