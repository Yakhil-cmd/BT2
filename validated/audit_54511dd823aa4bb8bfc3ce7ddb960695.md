### Title
Missing Length Validation on Participant-Supplied Vectors Before Direct Indexing Causes Panic in Triple Generation - (File: src/ecdsa/ot_based_ecdsa/triples/generation.rs)

### Summary
In the OT-based ECDSA triple generation protocol, participant-supplied message payloads containing `Vec` fields are deserialized and then directly indexed with `[i]` inside a `for i in 0..N` loop without any prior length validation. A single malicious participant can send a message with an empty or undersized vector, triggering an index-out-of-bounds panic that crashes the honest party's protocol execution and permanently denies presigning.

### Finding Description

The `do_generate_triples` function in `src/ecdsa/ot_based_ecdsa/triples/generation.rs` receives `PolynomialCommitmentsMessageMany` from each other participant via `recv_from_others`, then immediately indexes into its `Vec` fields using `[i]` inside a `for i in 0..N` loop:

```rust
for (from, their) in
    recv_from_others::<PolynomialCommitmentsMessageMany>(&chan, wait2, &participants, me)
        .await?
{
    for i in 0..N {
        let their_big_e = &their.big_e_v[i];   // panics if len < N
        let their_big_f = &their.big_f_v[i];   // panics if len < N
        let their_big_l = &their.big_l_v[i];   // panics if len < N
        let their_randomizer = &their.randomizer_v[i];  // panics if len < N
        let their_phi_proof0 = &their.phi_proof0_v[i]; // panics if len < N
        let their_phi_proof1 = &their.phi_proof1_v[i]; // panics if len < N
``` [1](#0-0) 

The same unguarded pattern repeats in two additional receive rounds:

```rust
for (from, (big_c_j_v, their_phi_proofs)) in recv_from_others::<(...)>(...).await? {
    for i in 0..N {
        let big_c_j = big_c_j_v[i].value();       // panics if len < N
        let their_phi_proof = &their_phi_proofs[i]; // panics if len < N
``` [2](#0-1) 

```rust
for (from, (their_hat_big_c_i_points, their_phi_proofs)) in recv_from_others::<(...)>(...).await? {
    for i in 0..N {
        let their_hat_big_c = their_hat_big_c_i_points[i].value(); // panics if len < N
        let their_phi_proof = &their_phi_proofs[i];                // panics if len < N
``` [3](#0-2) 

`N` is the number of triples to generate, determined by the protocol parameters. The attacker controls the length of the `Vec` fields in their serialized message. `recv_from_others` validates that the sender is a legitimate participant in the list, but performs no validation of the message content or vector lengths. [4](#0-3) 

The `Protocol::message()` entry point accepts raw `MessageData` bytes and routes them into the `MessageBuffer` without any content validation. The deserialization of `PolynomialCommitmentsMessageMany` via `rmp_serde` succeeds for any valid MessagePack encoding, including one where the `Vec` fields have zero elements. The panic occurs only later, inside the `for i in 0..N` loop, when `[i]` is evaluated on an empty or short vector. [5](#0-4) 

In Rust, `vec[i]` on an out-of-bounds index is an unconditional panic. Because the protocol future is polled via `fut.poll_unpin` inside `ProtocolExecutor::poke`, the panic propagates out of `poke()` and crashes the honest party's execution context. [6](#0-5) 

### Impact Explanation

**High — Permanent denial of presigning for honest parties.**

Triple generation is the offline presigning phase of OT-based ECDSA. A single malicious participant (a legitimate member of the signing group) sends one crafted message with an empty `big_e_v` (or any other `Vec` field) to every honest party. Every honest party panics when it processes that message, permanently aborting the triple generation session. Without a valid triple, no ECDSA presignature can be produced, and signing is permanently denied for the affected session. Because the panic is deterministic and triggered by a single message, the attacker can repeat this against every future triple generation attempt.

### Likelihood Explanation

**Medium.** The attacker must be a legitimate participant in the triple generation protocol (i.e., hold a valid key share and be included in the participant list). This is a realistic threat model for a malicious-but-registered participant. No cryptographic material needs to be leaked or forged. The attack requires crafting a single malformed MessagePack message, which is trivial. The only constraint is that the attacker must be an enrolled participant.

### Recommendation

Before the `for i in 0..N` loop, validate that every received `Vec` field has exactly `N` elements and return a `ProtocolError` (not a panic) if the check fails:

```rust
if their.big_e_v.len() != N
    || their.big_f_v.len() != N
    || their.big_l_v.len() != N
    || their.randomizer_v.len() != N
    || their.phi_proof0_v.len() != N
    || their.phi_proof1_v.len() != N
{
    return Err(ProtocolError::AssertionFailed(format!(
        "participant {from:?} sent vectors of wrong length"
    )));
}
```

Apply the same guard before every `for i in 0..N` loop that indexes into participant-supplied `Vec` fields. Replace all direct `[i]` accesses on deserialized vectors with `.get(i).ok_or(ProtocolError::...)` to eliminate the panic path entirely.

### Proof of Concept

1. Enroll a malicious participant `M` in a triple generation session alongside honest participants `H1, H2, ...`.
2. When the protocol reaches `wait2` (the `PolynomialCommitmentsMessageMany` round), `M` serializes a `PolynomialCommitmentsMessageMany` where `big_e_v = []` (empty vector) and all other fields are also empty.
3. `M` sends this message to every honest participant via the `Protocol::message()` interface.
4. Each honest participant's `recv_from_others` accepts the message (sender `M` is in the participant list).
5. The deserialization of `PolynomialCommitmentsMessageMany` succeeds (empty `Vec` is valid MessagePack).
6. The `for i in 0..N` loop executes `their.big_e_v[0]` on an empty vector → **index out of bounds panic**.
7. The panic propagates through `fut.poll_unpin` inside `ProtocolExecutor::poke`, crashing the honest party's protocol execution.
8. Triple generation is permanently aborted; no presignature can be produced.

### Citations

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L331-342)
```rust
        for (from, their) in
            recv_from_others::<PolynomialCommitmentsMessageMany>(&chan, wait2, &participants, me)
                .await?
        {
            for i in 0..N {
                let all_commitments = &all_commitments_vec[i];
                let their_big_e = &their.big_e_v[i];
                let their_big_f = &their.big_f_v[i];
                let their_big_l = &their.big_l_v[i];
                let their_randomizer = &their.randomizer_v[i];
                let their_phi_proof0 = &their.phi_proof0_v[i];
                let their_phi_proof1 = &their.phi_proof1_v[i];
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L464-476)
```rust
        for (from, (big_c_j_v, their_phi_proofs)) in recv_from_others::<(
            Vec<CoefficientCommitment>,
            Vec<dlogeq::Proof<C>>,
        )>(&chan, wait4, &participants, me)
        .await?
        {
            for i in 0..N {
                let big_e_j_zero = &big_e_j_zero_v[i];
                let big_f = &big_f_v[i];

                let big_c_j = big_c_j_v[i].value();
                let their_phi_proof = &their_phi_proofs[i];

```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L581-592)
```rust
    for (from, (their_hat_big_c_i_points, their_phi_proofs)) in recv_from_others::<(
        Vec<CoefficientCommitment>,
        Vec<dlog::Proof<C>>,
    )>(
        &chan, wait5, &participants, me
    )
    .await?
    {
        for i in 0..N {
            let their_hat_big_c = their_hat_big_c_i_points[i].value();
            let their_phi_proof = &their_phi_proofs[i];

```

**File:** src/protocol/helpers.rs (L6-26)
```rust
pub async fn recv_from_others<T>(
    chan: &SharedChannel,
    waitpoint: u64,
    participants: &ParticipantList,
    me: Participant,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let mut messages = Vec::with_capacity(participants.others(me).count());

    while !seen.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        if seen.put(from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
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
