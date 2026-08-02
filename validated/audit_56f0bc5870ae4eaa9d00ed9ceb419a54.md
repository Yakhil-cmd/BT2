No vulnerability found for this question.

`FULL_ROUNDS` is a hardcoded `const usize = 8` compiled into the verifier binary at `crates/aptos-crypto/src/poseidon_bn254/constants.rs:9`, used to build the fixed `PoseidonConstants` static tables (`POSEIDON_1`..`POSEIDON_16`) via the `neptune_constants!` macro [1](#0-0) . It is not an input parameter that flows from any transaction, JWT, or proof field — it is baked into the Rust source and used identically for every invocation of `poseidon_bn254::hash_scalars`, which is called deterministically from `hash_public_inputs` when computing the public-inputs hash [2](#0-1) .

An unprivileged prover has no way to "feed" a different `FULL_ROUNDS` value into the verifier — there is no deserialized field, API parameter, or authenticator structure that carries a round-count; the verifier always uses the same compiled constant for both PIH computation paths (`aptos-move/aptos-vm/src/keyless_validation.rs:312-321` and `keyless/pepper/service/src/dedicated_handlers/handlers.rs:456-466`) [3](#0-2) [4](#0-3) . If the Rust-side `FULL_ROUNDS` constant genuinely mismatched the circuit's compiled round count, that would be a deployment/integration bug in the trusted constants file itself, not something an "unprivileged" caller can trigger by choosing an "insufficient" value at request time — it fails the requirement that the exploit path start from attacker-controlled unprivileged transaction/authenticator/proof input. The Groth16 proof verification (`ZeroKnowledgeSig::verify_groth16_proof` / `Groth16Proof::verify_proof`) simply checks the fixed PIH against the on-chain `PreparedVerifyingKey` [5](#0-4) ; there is no runtime branch where round-count varies by caller input.

### Citations

**File:** crates/aptos-crypto/src/poseidon_bn254/constants.rs (L9-30)
```rust
const FULL_ROUNDS: usize = 8;
static PARTIAL_ROUNDS: Lazy<Vec<usize>> = Lazy::new(|| {
    vec![
        56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
    ]
});

static BN254_CONSTANTS: Lazy<(Vec<Vec<AltFr>>, Vec<Vec<Vec<AltFr>>>)> = Lazy::new(constants);

macro_rules! neptune_constants {
    ($constants:expr, $matrices:expr, $ui:ty) => {{
        let w = <$ui>::to_usize();
        PoseidonConstants::new_from_parameters(
            w + 1,
            $matrices[w - 1].clone(),
            $constants[w - 1].clone(),
            FULL_ROUNDS,
            PARTIAL_ROUNDS[w - 1],
            HashType::<AltFr, $ui>::Sponge,
            Strength::Standard,
        )
    }};
```

**File:** types/src/keyless/bn254_circom.rs (L354-368)
```rust
    let mut frs = vec![];
    frs.append(&mut epk_frs);
    frs.push(idc);
    frs.push(exp_timestamp_secs);
    frs.push(exp_horizon_secs);
    frs.push(iss_field_hash);
    frs.push(has_extra_field);
    frs.push(extra_field_hash);
    frs.push(jwt_header_hash);
    frs.push(jwk_hash);
    frs.push(override_aud_val_hash);
    frs.push(use_override_aud);
    // TODO(keyless): If we plan on avoiding verifying the same PIH twice, there should be no
    //  need for caching here. If we do not, we should cache the result here too.
    poseidon_bn254::hash_scalars(frs)
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L312-321)
```rust
                        let public_inputs_hash = get_public_inputs_hash(
                            signature,
                            public_key.inner_keyless_pk(),
                            rsa_jwk,
                            config,
                        )
                        .map_err(|_| {
                            // println!("[aptos-vm][groth16] PIH computation failed");
                            invalid_signature!("Could not compute public inputs hash")
                        })?;
```

**File:** keyless/pepper/service/src/dedicated_handlers/handlers.rs (L456-466)
```rust
    // Get the public inputs hash
    let rsa_jwk = get_rsa_jwk(keyless_public_key, keyless_signature, jwk_cache.clone())?;
    let public_inputs_hash = get_public_inputs_hash(
        keyless_signature,
        keyless_public_key,
        &rsa_jwk,
        keyless_config,
    )
    .map_err(|error| {
        PepperServiceError::BadRequest(format!("Failed to compute public inputs hash: {}", error))
    })?;
```

**File:** types/src/keyless/groth16_sig.rs (L215-235)
```rust
    pub fn verify_proof(
        &self,
        public_inputs_hash: Fr,
        pvk: &PreparedVerifyingKey<Bn254>,
    ) -> anyhow::Result<()> {
        // let start = std::time::Instant::now();
        let proof: Proof<Bn254> = Proof {
            a: self.a.deserialize_into_affine()?,
            b: self.b.deserialize_into_affine()?,
            c: self.c.deserialize_into_affine()?,
        };
        // println!("Deserialization time: {:?}", start.elapsed());

        // let start = std::time::Instant::now();
        let verified = Groth16::<Bn254>::verify_proof(pvk, &proof, &[public_inputs_hash])?;
        // println!("Proof verification time: {:?}", start.elapsed());
        if !verified {
            bail!("groth16 proof verification failed")
        }
        Ok(())
    }
```
