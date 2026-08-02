No vulnerability found for this question.

**Analysis:**

`get_scalars()` in `sigma_protocol_witness.move` is a `public(friend)` accessor on the internal `Witness` struct, restricted to a fixed friend list (`sigma_protocol_proof`, `sigma_protocol_homomorphism`, `sigma_protocol`, `sigma_protocol_registration`, `sigma_protocol_withdraw`, `sigma_protocol_transfer`, `sigma_protocol_key_rotation`, plus test-only friends). [1](#0-0) 

The critical fact is that the only function which actually consumes `Witness::get_scalars()` to produce a proof (`sigma_protocol::prove`) is annotated `#[test_only]`, not part of production code. [2](#0-1)  In production, ZK proofs are generated entirely off-chain by the client using their own secret key material; the on-chain admission path only ever receives a `Proof` (public commitment + response scalars) and a `Statement` (public group elements) — never a `Witness`. [3](#0-2) [4](#0-3) 

The domain separator's `sender` field is bound not through the witness at all, but through the `RegistrationSession`/`KeyRotationSession` struct, which is constructed from an actual `&signer` at session-creation time via `signer::address_of(sender)` — this is authenticated transaction signer material, not attacker-controlled input. [5](#0-4) [6](#0-5) 

Since `get_scalars()` never touches or influences the `sender` field of the domain separator, and the witness is never part of the on-chain verification path (`assert_verifies` → `sigma_protocol::verify`) that gates transaction admission, there is no way for a friend module or unprivileged caller to leak/replay a witness so as to corrupt the sender binding of a different session's domain separator. Any cross-session replay attempt would still require producing a valid `Proof` under the target session's actual `DomainSeparator` (which includes the real sender address and protocol ID via Fiat-Shamir), and the Fiat-Shamir challenge binds the statement, commitment, and response — a proof crafted for sender A's registration statement/DST cannot satisfy sender B's key-rotation statement/DST verification. [7](#0-6) 

This does not reach the transaction-admission boundary (mempool/vm-validator/authenticator) at all — it is purely internal Move-module crypto-library scoping, and no unprivileged transaction/authenticator/API path exists that would let `get_scalars()` corrupt sender/domain binding.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/sigma_protocol_witness.move (L1-17)
```text
module aptos_framework::sigma_protocol_witness {
    friend aptos_framework::sigma_protocol_proof;
    friend aptos_framework::sigma_protocol_homomorphism;
    friend aptos_framework::sigma_protocol;
    friend aptos_framework::sigma_protocol_registration;
    friend aptos_framework::sigma_protocol_withdraw;
    friend aptos_framework::sigma_protocol_transfer;
    friend aptos_framework::sigma_protocol_key_rotation;
    #[test_only]
    friend aptos_framework::sigma_protocol_pedeq_example;
    #[test_only]
    friend aptos_framework::sigma_protocol_schnorr_example;
    #[test_only]
    friend aptos_framework::sigma_protocol_proof_tests;
    #[test_only]
    friend aptos_framework::confidential_crypto_test_utils;

```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/sigma_protocol.move (L36-66)
```text
    #[test_only]
    /// Creates a proof and additionally returns the randomness $\alpha \in \mathbb{F}^k$ used to
    /// create the sigma protocol commitment $A = \psi(\alpha) \in \mathbb{G}^m$.
    public(friend) inline fun prove<P>(
        dst: DomainSeparator,
        psi: Homomorphism<P>,
        stmt: &Statement<P>,
        witn: &Witness,
    ): (Proof, Witness) {
        let k = witn.length();

        // Step 1: Pick a random \alpha \in \F^k
        let alpha = random_witness(k);

        // Step 2: A <- \psi(\alpha) \in \Gr^m
        let _A = evaluate_psi(|_X, w| psi(_X, w), stmt, &alpha);

        // Step 3: Derive a random-challenge `e` via Fiat-Shamir
        let compressed_A = compress_points(&_A);
        let (e, _) = fiat_shamir(dst, stmt, &compressed_A, &vector[], k);

        // Step 4: \sigma <- \alpha + e w
        let sigma = add_vec_scalars(
            alpha.get_scalars(),
            &mul_scalars(witn.get_scalars(), &e)
        );

        assert!(sigma.length() == k, error::internal(E_INTERNAL_INVARIANT_FAILED));

        (sigma_protocol_proof::new_proof(_A, compressed_A, sigma), alpha)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/proofs/sigma_protocol_registration.move (L123-128)
```text
    public(friend) fun new_session(sender: &signer, asset_type: Object<Metadata>): RegistrationSession {
        RegistrationSession {
            sender: signer::address_of(sender),
            asset_type,
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/proofs/sigma_protocol_registration.move (L174-185)
```text
    /// Asserts that a registration proof verifies.
    public(friend) fun assert_verifies(self: &RegistrationSession, stmt: &Statement<Registration>, proof: &Proof) {
        let success = sigma_protocol::verify(
            new_domain_separator(@aptos_framework, chain_id::get(), PROTOCOL_ID, bcs::to_bytes(self)),
            |_X, w| psi(_X, w),
            |_X| f(_X),
            stmt,
            proof
        );

        assert!(success, error::invalid_argument(E_INVALID_REGISTRATION_PROOF));
    }
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/proofs/sigma_protocol_key_rotation.move (L178-184)
```text
    public(friend) fun new_session(sender: &signer, token_type: Object<Metadata>): KeyRotationSession {
        KeyRotationSession {
            sender: signer::address_of(sender),
            token_type,
            num_chunks: get_num_available_chunks(),
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/proofs/sigma_protocol_key_rotation.move (L304-317)
```text
    /// Asserts that a key rotation proof verifies
    public(friend) fun assert_verifies(self: &KeyRotationSession, stmt: &Statement<KeyRotation>, proof: &Proof) {
        assert_key_rotation_statement_is_well_formed(stmt);

        let success = sigma_protocol::verify(
            new_domain_separator(@aptos_framework, chain_id::get(), PROTOCOL_ID, bcs::to_bytes(self)),
            |_X, w| psi(_X, w),
            |_X| f(_X),
            stmt,
            proof
        );

        assert!(success, error::invalid_argument(E_INVALID_KEY_ROTATION_PROOF));
    }
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/sigma_protocol_fiat_shamir.move (L80-104)
```text
    /// Returns the Sigma protocol challenge $e$ and $1,\beta,\beta^2,\ldots, \beta^{m-1}$
    public(friend) fun fiat_shamir<P>(
        dst: DomainSeparator,
        stmt: &Statement<P>,
        compressed_A: &vector<CompressedRistretto>,
        sigmas: &vector<Scalar>,
        k: u64): (Scalar, vector<Scalar>)
    {
        let m = compressed_A.length();
        assert!(m != 0, error::invalid_argument(E_PROOF_COMMITMENT_EMPTY));

        // We will hash an application-specific domain separator and the (full) public statement,
        // which will include any public parameters like group generators $G$, $H$.

        // Note: A more principled `Merlin` / `spongefish`-like approach would have been preferred, but... more code.

        // Note: A hardcodes $m$, the statement hardcodes $n_1$ and $n_2$, and $k$ is specified manually!;
        let seed = sha2_512_value(&FiatShamirInputs {
            dst,
            type_name: type_info::type_name<P>(),
            k,
            stmt_X: *stmt.get_compressed_points(),
            stmt_x: *stmt.get_scalars(),
            proof_A: *compressed_A
        });
```
