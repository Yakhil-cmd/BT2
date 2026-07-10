### Title
Missing Proof of Correct Computation for CKD Participant Shares Allows Malicious Participant to Corrupt Derived Key Output - (File: src/confidential_key_derivation/protocol.rs)

### Summary
The CKD coordinator aggregates `(norm_big_y, norm_big_c)` contributions from all participants with no cryptographic proof that each contribution was honestly computed. A single malicious participant can send arbitrary group elements, causing the coordinator to output a corrupted `CKDOutput` that does not equal `msk · H(pk, app_id)`, making the derived confidential key unusable or wrong for the application.

### Finding Description
In `do_ckd_coordinator` (`src/confidential_key_derivation/protocol.rs`, lines 35–57), the coordinator receives each participant's `CKDOutput` and unconditionally adds the components together:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
``` [1](#0-0) 

Each participant is supposed to compute, per `compute_signature_share`:

- `norm_big_y = λ_i · y_i · G`
- `norm_big_c = λ_i · (x_i · H(pk, app_id) + y_i · app_pk)` [2](#0-1) 

No zero-knowledge proof or consistency check is attached to these values before they are accepted. The coordinator has no way to distinguish a correctly computed share from an arbitrary group element sent by a malicious participant.

The final `CKDOutput` is:

```
Y_final = Σ norm_big_y_i
C_final = Σ norm_big_c_i
``` [3](#0-2) 

If any participant substitutes arbitrary `(big_y_malicious, big_c_malicious)`, the aggregated output deviates from the intended `msk · H(pk, app_id)` when the application calls `unmask`:

```rust
pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
    self.big_c - self.big_y * secret_scalar
}
``` [4](#0-3) 

The result is a wrong group element, not the intended confidential key.

### Impact Explanation
This falls under **High: Corruption of CKD outputs so honest parties accept unusable cryptographic outputs**. The coordinator and the requesting application receive a `CKDOutput` that silently decrypts to the wrong value. The application (e.g., a TEE) derives an incorrect secret key with no indication of failure, since there is no post-aggregation integrity check. Every CKD invocation involving even one malicious participant is permanently corrupted.

### Likelihood Explanation
Any single participant in the CKD protocol can trigger this. No special privilege is required beyond being a listed participant. The attack is a simple substitution: instead of running `compute_signature_share` honestly, the malicious participant sends `(G, G)` or any other arbitrary pair. The coordinator has no mechanism to detect this. The attack is deterministic and requires no timing, side-channel, or cryptographic break.

### Recommendation
Require each participant to attach a non-interactive zero-knowledge proof of correct share formation alongside their `(norm_big_y, norm_big_c)` contribution. Concretely, each participant should prove in zero knowledge:

1. Knowledge of `y_i` such that `norm_big_y = λ_i · y_i · G`
2. Consistency of `norm_big_c` with their committed public share `λ_i · x_i · G2` (from DKG output) and the same `y_i`, i.e., `norm_big_c = λ_i · x_i · H(pk, app_id) + λ_i · y_i · app_pk`

This is analogous to requiring a "minimum amount out" check: the coordinator should only accept contributions that are provably well-formed before aggregating them into the final output.

### Proof of Concept

1. Run CKD with 3 participants where participant P2 is malicious.
2. P2 sends `(big_y = G, big_c = G)` (the generator point) instead of their honest share.
3. The coordinator aggregates: `Y_final = Y_P1 + G + Y_P3`, `C_final = C_P1 + G + C_P3`.
4. The application calls `unmask(app_sk)` and receives `C_final - app_sk * Y_final`, which is not equal to `msk · H(pk, app_id)`.
5. The application silently uses the wrong derived key. No error is raised anywhere in the protocol.

The existing test in `src/confidential_key_derivation/protocol.rs` (lines 211–283) confirms the happy-path correctness but contains no adversarial participant test, confirming the absence of any share-validity enforcement. [5](#0-4)

### Citations

**File:** src/confidential_key_derivation/protocol.rs (L44-57)
```rust
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

**File:** src/confidential_key_derivation/protocol.rs (L165-181)
```rust
    let big_y = ElementG1::generator() * y.0;

    // H(pk || app_id) when H is a random oracle
    let hash_point = hash_app_id_with_pk(&key_pair.public_key, app_id);

    // S <- x . H(app_id)
    let big_s = hash_point * private_share.to_scalar();

    // C <- S + y . A
    let big_c = big_s + app_pk * y.0;

    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<BLS12381SHA256>(me)?;
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = big_y * lambda_i;
    let norm_big_c = big_c * lambda_i;
    Ok((norm_big_y, norm_big_c))
```

**File:** src/confidential_key_derivation/protocol.rs (L184-283)
```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::confidential_key_derivation::{
        ciphersuite::{hash_to_curve, G2Projective},
        hash_app_id_with_pk, SigningShare, VerifyingKey,
    };
    use crate::test_utils::{
        check_one_coordinator_output, generate_participants, run_protocol, GenProtocol,
        MockCryptoRng,
    };
    use rand::{seq::SliceRandom as _, RngCore, SeedableRng};

    #[test]
    fn test_hash2curve() {
        let app_id = b"Hello Near";
        let app_id_same = b"Hello Near";
        let pt1 = hash_to_curve(&AppId::try_from(app_id).unwrap());
        let pt2 = hash_to_curve(&AppId::try_from(app_id_same).unwrap());
        assert_eq!(pt1, pt2);

        let app_id = b"Hello Near!";
        let pt2 = hash_to_curve(&AppId::try_from(app_id).unwrap());
        assert_ne!(pt1, pt2);
    }

    #[test]
    fn test_ckd() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        // Create the app necessary items
        let app_id = AppId::try_from(b"Near App").unwrap();
        let app_sk = Scalar::random(&mut rng);
        let app_pk = ElementG1::generator() * app_sk;

        let participants = generate_participants(3);

        // choose a coordinator at random
        let coordinator = *participants
            .choose(&mut rng)
            .expect("participant list is not empty");
        let participant_list = ParticipantList::new(&participants).unwrap();

        // Manually compute signing keys
        let mut private_shares = Vec::new();
        let mut msk = Scalar::ZERO;
        for (i, _) in participants.iter().enumerate() {
            let mut rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
            let private_share = SigningShare::new(Scalar::random(&mut rng_p));
            // compute lambda(i)
            let lambda_i = participant_list
                .lagrange::<BLS12381SHA256>(participant_list.get_participant(i).unwrap())
                .unwrap();

            msk += lambda_i * private_share.to_scalar();
            private_shares.push(private_share);
        }

        // Manually compute master verification
        let pk = VerifyingKey::new(G2Projective::generator() * msk);

        let mut protocols: GenProtocol<CKDOutputOption> = Vec::with_capacity(participants.len());
        for (i, p) in participants.iter().enumerate() {
            let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
            let key_pair = KeygenOutput {
                public_key: pk,
                private_share: private_shares[i],
            };

            let protocol = ckd(
                &participants,
                coordinator,
                *p,
                key_pair,
                app_id.clone(),
                app_pk,
                rng_p,
            )
            .unwrap();

            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols).unwrap();

        // test one single some for the coordinator
        let ckd_output = check_one_coordinator_output(result, coordinator).unwrap();

        // compute msk . H(pk, app_id)
        let confidential_key = ckd_output.unmask(app_sk);

        // H(pk || app_id) * msk
        let expected_confidential_key = hash_app_id_with_pk(&pk, &app_id) * msk;

        assert_eq!(
            confidential_key, expected_confidential_key,
            "Keys should be equal"
        );
        insta::assert_json_snapshot!(ckd_output);
    }
```

**File:** src/confidential_key_derivation/mod.rs (L54-56)
```rust
    pub fn unmask(&self, secret_scalar: Scalar) -> Signature {
        self.big_c - self.big_y * secret_scalar
    }
```
