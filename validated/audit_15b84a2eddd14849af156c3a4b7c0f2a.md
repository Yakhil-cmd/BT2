### Title
Missing Validation of Participant Contributions in CKD Coordinator Allows Output Corruption - (File: src/confidential_key_derivation/protocol.rs)

### Summary

The `do_ckd_coordinator` function in `src/confidential_key_derivation/protocol.rs` receives `CKDOutput` values (`big_y`, `big_c`) from each participant and accumulates them directly without any cryptographic validation. A single malicious participant can submit arbitrary group elements, causing the coordinator to produce a corrupted CKD output that does not correspond to the actual master secret key, making the derived confidential key unusable or wrong for all honest parties.

### Finding Description

The CKD protocol is designed so that each participant $P_i$ computes:

$$Y_i = y_i \cdot G, \quad C_i = x_i \cdot H(\mathit{pk}, \mathit{app\_id}) + y_i \cdot \mathit{app\_pk}$$

and sends $(\lambda_i \cdot Y_i,\ \lambda_i \cdot C_i)$ to the coordinator. The coordinator sums these to obtain $(Y, C)$, which the application unmasks as $C - \mathit{app\_sk} \cdot Y = \mathit{msk} \cdot H(\mathit{pk}, \mathit{app\_id})$.

The coordinator's aggregation loop in `do_ckd_coordinator` is:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

There is **no proof of knowledge**, **no commitment check**, and **no consistency verification** that the received `big_y` and `big_c` were computed using the participant's actual private share $x_i$ and a valid ephemeral scalar $y_i$. The values are accepted and summed unconditionally. [1](#0-0) 

By contrast, every other multi-party protocol in this codebase that aggregates participant contributions enforces cryptographic consistency. For example, the DKG validates secret shares against polynomial commitments: [2](#0-1) 

And the triple-generation protocol verifies dlog and dlogeq proofs before accumulating polynomial values: [3](#0-2) 

The CKD protocol has no equivalent guard.

**Exploit path:**

1. A malicious participant $P_m$ participates in a legitimate CKD session with honest parties.
2. Instead of computing $(\lambda_m \cdot Y_m,\ \lambda_m \cdot C_m)$ correctly, $P_m$ sends arbitrary group elements $(\tilde{Y},\ \tilde{C})$ to the coordinator.
3. The coordinator accumulates these without rejection.
4. The final output $(Y, C)$ is shifted by $(\tilde{Y} - \lambda_m Y_m,\ \tilde{C} - \lambda_m C_m)$.
5. The application unmasks the result and obtains a value that is **not** $\mathit{msk} \cdot H(\mathit{pk}, \mathit{app\_id})$, rendering the derived confidential key incorrect.

No privileged access is required; any participant in the CKD session can trigger this. [4](#0-3) 

### Impact Explanation

**High — Corruption of CKD outputs so honest parties accept an unusable or incorrect derived key.**

The coordinator and any downstream consumer of the CKD output will silently accept a corrupted `(Y, C)` pair. The unmasked confidential key will be wrong, breaking the protocol's correctness guarantee. Because the corruption is additive and undetectable without a ground-truth reference, honest parties have no way to identify that the output is invalid.

This matches the allowed impact: *"High: Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs."*

### Likelihood Explanation

**Medium.** Any single participant in a CKD session — a role reachable without privileged assumptions — can trigger this by deviating from the protocol in a single message. The attack requires no cryptographic break, no leaked keys, and no external dependency. It is a straightforward protocol deviation.

### Recommendation

Each participant must accompany their `(big_y, big_c)` submission with a zero-knowledge proof of correct formation — specifically, a proof of knowledge of $(y_i, x_i)$ such that:

$$Y_i = y_i \cdot G \quad \text{and} \quad C_i = x_i \cdot H(\mathit{pk}, \mathit{app\_id}) + y_i \cdot \mathit{app\_pk}$$

where $x_i \cdot G$ equals the participant's known public key share. This is a standard Chaum–Pedersen / dlogeq proof, consistent with the `dlogeq` module already present in `src/crypto/proofs/dlogeq.rs`. [5](#0-4) 

The coordinator must verify this proof before accumulating each participant's contribution, mirroring the pattern used in triple generation.

### Proof of Concept

```
Setup:
  - 3 participants: P1 (coordinator), P2 (honest), P3 (malicious)
  - Shared master public key pk, app_id, app_pk known to all

Honest execution (P2):
  - Computes big_y2 = λ2 * y2 * G, big_c2 = λ2 * (x2 * H(pk, app_id) + y2 * app_pk)
  - Sends (big_y2, big_c2) to coordinator P1

Malicious execution (P3):
  - Instead of computing correctly, sends (big_y3 = IDENTITY, big_c3 = IDENTITY)
    (or any arbitrary group elements)

Coordinator P1:
  - Accumulates: Y = λ1*Y1 + big_y2 + IDENTITY, C = λ1*C1 + big_c2 + IDENTITY
  - No error is raised; the loop completes normally

Result:
  - Unmasked key = C - app_sk * Y ≠ msk * H(pk, app_id)
  - CKD output is silently corrupted; all honest parties accept it
``` [6](#0-5)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L35-57)
```rust
async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    key_pair: &KeygenOutput,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutputOption, ProtocolError> {
    let (mut norm_big_y, mut norm_big_c) =
        compute_signature_share(&participants, me, key_pair, app_id, app_pk, rng)?;

    // Receive everyone's inputs and add them together
    let waitpoint = chan.next_waitpoint();

    for (_, participant_output) in
        recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
    {
        norm_big_y += participant_output.big_y();
        norm_big_c += participant_output.big_c();
    }
    let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
    Ok(Some(ckd_output))
```

**File:** src/dkg.rs (L259-285)
```rust
fn validate_received_share<C: Ciphersuite>(
    me: Participant,
    from: Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError> {
    let id = me.to_identifier::<C>()?;

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(id, *signing_share_from, commitment.clone());

    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(from)
        } else {
            ProtocolError::AssertionFailed(format!(
                "could not
            extract the verification key matching the secret
            share sent by {from:?}"
            ))
        }
    })?;
    Ok(())
```

**File:** src/ecdsa/ot_based_ecdsa/triples/generation.rs (L353-396)
```rust
                if !all_commitments
                    .index(from)?
                    .check(
                        &(&their_big_e, &their_big_f, &their_big_l),
                        their_randomizer,
                    )
                    .map_err(|_| ProtocolError::PointSerialization)?
                {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "commitment from {from:?} did not match revealed F"
                    )));
                }
                let statement0 = dlog::Statement::<C> {
                    public: &their_big_e.eval_at_zero()?.value(),
                };
                if !dlog::verify(
                    &mut transcript.fork(b"dlog0", &from.bytes()),
                    statement0,
                    their_phi_proof0,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlog proof from {from:?} failed to verify"
                    )));
                }

                let statement1 = dlog::Statement::<C> {
                    public: &their_big_f.eval_at_zero()?.value(),
                };
                if !dlog::verify(
                    &mut transcript.fork(b"dlog1", &from.bytes()),
                    statement1,
                    their_phi_proof1,
                )? {
                    return Err(ProtocolError::AssertionFailed(format!(
                        "dlog proof from {from:?} failed to verify"
                    )));
                }

                big_e_j_zero_v[i].put(from, their_big_e.eval_at_zero()?);

                big_e_v[i] = big_e_v[i].add(their_big_e)?;
                big_f_v[i] = big_f_v[i].add(their_big_f)?;
                big_l_v[i] = big_l_v[i].add(their_big_l)?;
            }
```

**File:** src/crypto/proofs/dlogeq.rs (L139-163)
```rust
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError>
where
    Element<C>: ConstantTimeEq,
{
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_DLOGEQ_STATEMENT_LABEL, &statement.encode()?);

    let (phi0, phi1) = statement.phi(&proof.s.0);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    let enc = encode_two_points::<C>(&big_k0, &big_k1)?;

    transcript.message(NEAR_DLOGEQ_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_DLOGEQ_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    Ok(e == proof.e.0)
```
