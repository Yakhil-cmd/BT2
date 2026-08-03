No vulnerability found for this question.

**Rationale:**

The premise of the exploit — that an attacker can construct a `Statement<Transfer>` referencing account B's ciphertexts while submitting/signing as account A — does not hold, because the confidential-asset module derives *all* account-bound statement inputs itself from the actual `signer`, not from attacker-supplied data.

In `confidential_transfer` (called by the entry function `confidential_transfer_raw`), the sender address is taken directly from the signer, and the encryption key and old balance used to build the sigma statement are looked up on-chain for that exact address: [1](#0-0) 

The entry function `confidential_transfer_raw` accepts only ciphertext bytes for the *new balance* and *transfer amount* — it has no parameter letting the caller specify whose account's `ek_sender`/`old_balance` the statement should use. `assert_valid_transfer_proof` receives `compressed_ek_sender`/`compressed_old_balance` that were already fetched via `get_encryption_key(from, asset_type)` and `get_available_balance(from, asset_type)`, where `from = signer::address_of(sender)`: [2](#0-1) 

So the `Statement<Transfer>` is always built to match the *executing signer's own* registered ciphertext state, before the proof is even checked — there is no "different sender" the caller could bind to via input, since the account whose ciphertexts get plugged into the statement is a function of `signer::address_of(sender)`, which is authenticated by the transaction's authenticator and cannot be spoofed by an unprivileged caller.

Additionally, sender-binding is reinforced cryptographically: `sigma_protocol_transfer::new_session` embeds `sender: signer::address_of(sender)` into the `TransferSession`, whose BCS bytes feed the Fiat-Shamir domain separator used inside `verify`: [3](#0-2) [4](#0-3) 

This means even a hypothetically forged statement over another account's ciphertexts would produce a different Fiat-Shamir challenge than one derived under the real signer, and — more fundamentally — the attacker lacks the discrete-log witness (decryption key) for account B's encryption key, so `sigma_protocol::verify` at [5](#0-4)  would reject any such proof regardless.

In short: `sigma_protocol.move`'s `verify` function is a generic, statement-agnostic ZK verifier — the sender-binding invariant is enforced upstream in `confidential_asset.move` and `sigma_protocol_transfer.move` by construction (deriving statement inputs from the authenticated signer address and embedding that address in the Fiat-Shamir transcript), not by `verify` itself. There is no admission-boundary path by which an unprivileged sender can cause the entry function to bind a statement to someone else's balance.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/confidential_asset.move (L629-643)
```text
        let from = signer::address_of(sender);
        assert!(from != to, error::invalid_argument(E_SELF_TRANSFER));
        let effective_auditor = get_effective_auditor_config(asset_type);
        let ek_sender = get_encryption_key(from, asset_type);
        let ek_recip = get_encryption_key(to, asset_type);
        let old_balance = get_available_balance(from, asset_type);

        // Note: Sender's amount in `TransferProof::compressed_amount::compressed_R_sender` is not used here; only included so it can be indexed for dapps that need it
        let (compressed_new_balance, amount, compressed_amount, ek_volun_auds) =
            assert_valid_transfer_proof(
                sender, to, asset_type,
                &ek_sender, &ek_recip,
                &old_balance, &effective_auditor.config.ek,
                proof
            );
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/confidential_asset.move (L1336-1373)
```text
    fun assert_valid_transfer_proof(
        sender: &signer,
        recipient_addr: address,
        asset_type: Object<fungible_asset::Metadata>,
        compressed_ek_sender: &CompressedRistretto,
        compressed_ek_recip: &CompressedRistretto,
        compressed_old_balance: &CompressedBalance<Available>,
        compressed_ek_eff_aud: &Option<CompressedRistretto>,
        proof: TransferProof
    ): (
        CompressedBalance<Available>,
        Balance<Pending>,
        CompressedAmount,
        vector<CompressedRistretto>,
    ) {

        let TransferProof::V1 {
            compressed_new_balance, compressed_amount,
            compressed_ek_volun_auds,
            zkrp_new_balance, zkrp_amount, sigma
        } = proof;

        // Note: `update_auditor` already guarantees that `compressed_ek_eff_aud` is not the identity, but the voluntary
        // auditor EKs need to be manually checked.
        compressed_ek_volun_auds.for_each_ref(|ek| {
            assert!(!ek.is_identity(), error::invalid_argument(E_EK_IS_IDENTITY));
        });

        let has_effective_auditor = compressed_ek_eff_aud.is_some();
        let num_volun_auditors = compressed_ek_volun_auds.length();

        // Auditor count checks are performed inside new_transfer_statement
        let (stmt, amount) = sigma_protocol_transfer::new_transfer_statement(
            *compressed_ek_sender, *compressed_ek_recip,
            compressed_old_balance, &compressed_new_balance,
            &compressed_amount,
            compressed_ek_eff_aud, &compressed_ek_volun_auds,
        );
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/proofs/sigma_protocol_transfer.move (L222-238)
```text
    public(friend) fun new_session(
        sender: &signer,
        recipient: address,
        asset_type: Object<Metadata>,
        has_effective_auditor: bool,
        num_volun_auditors: u64,
    ): TransferSession {
        TransferSession {
            sender: signer::address_of(sender),
            recipient,
            asset_type,
            num_avail_chunks: get_num_available_chunks(),
            num_transfer_chunks: get_num_pending_chunks(),
            has_effective_auditor,
            num_volun_auditors,
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/proofs/sigma_protocol_transfer.move (L543-559)
```text
    /// Asserts that a transfer proof verifies.
    public(friend) fun assert_verifies(
        self: &TransferSession, stmt: &Statement<Transfer>, proof: &Proof,
    ) {
        let has_eff = self.has_effective_auditor;
        let num_volun = self.num_volun_auditors;
        assert_transfer_statement_is_well_formed(stmt, has_eff, num_volun);

        let success = sigma_protocol::verify(
            new_domain_separator(@aptos_framework, chain_id::get(), PROTOCOL_ID, bcs::to_bytes(self)),
            |_X, w| psi(_X, w, has_eff, num_volun),
            |_X| f(_X, has_eff, num_volun),
            stmt,
            proof
        );

        assert!(success, error::invalid_argument(E_INVALID_TRANSFER_PROOF));
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/sigma_protocol.move (L150-209)
```text
    public(friend) inline fun verify<P>(
        dst: DomainSeparator,
        psi: Homomorphism<P>,
        f: TransformationFunction<P>,
        stmt: &Statement<P>,
        proof: &Proof,
    ): bool {
        // Step 1: Fiat-Shamir transform on `(dst, (psi, f), stmt)` to derive the random challenge `e`
        let _A = proof.get_commitment();
        let m = _A.length();
        let (e, betas) = fiat_shamir(dst, stmt, proof.get_compressed_commitment(),
            proof.get_response(), proof.get_response_length());

        // Step 2:
        let psi_sigma = psi(stmt, &proof.response_to_witness());
        let efx = f(stmt);

        assert!(m == psi_sigma.length(), error::invalid_argument(E_PROOF_COMMITMENT_WRONG_LEN));
        assert!(m == efx.length(), error::invalid_argument(E_PROOF_COMMITMENT_WRONG_LEN));

        // "Scale" all the representations in `f(stmt)` by `e`. (Implicit assumption here is that `f` is homomorphic:
        // i.e., `e f(X) = f(eX)`, which holds because our `f`'s are a `RepresentationVec`.)
        efx.scale_all(&e);

        // "Scale" the `i`th reprentation in `efx` by `\beta[i]`
        efx.scale_each(&betas);

        // "Scale" the `i`th reprentation in `\psi` by `-\beta[i]`
        // TODO(Perf): I think this could be sub-optimal: we will redo the same \beta[i] \sigma[j] multiplication several times
        //   when a `RepresentationVec`'s row reuses \sigma[j].
        psi_sigma.scale_each(&neg_scalars(&betas));

        // We start with an empty MSM: \sum_{i \in m} 0
        // ...and extend it to: \sum_{i \in [m]} A[i]^{\beta[i]}
        //                                          ^^^^^^^^^^^^^^^
        let bases = points_clone(_A);
        let scalars = betas;

        // These asserts will only fail when we have mis-implemented the cloning of `A` above
        assert!(bases.length() == m, error::internal(E_INTERNAL_INVARIANT_FAILED));
        assert!(scalars.length() == m, error::internal(E_INTERNAL_INVARIANT_FAILED));

        // Extend MSM to: be \sum_{i \in [m]} A[i]^\beta[i] + \beta[i] ( e f(stmt)[i] )
        //                                                    ^^^^^^^^^^^^^^^^^^^^^^^^^
        efx.for_each_ref(|repr| {
            bases.append(repr.to_points(stmt));
            scalars.append(*repr.get_scalars());
        });

        // Extend MSM to: be \sum_{i \in [m]} A[i]^\beta[i] + \beta[i] ( e f(stmt)[i] ) - \beta[i] (\psi(\sigma)[i])
        //                                                                                ^^^^^^^^^^^^^^^^^^^^^^^^^^
        psi_sigma.for_each_ref(|repr| {
            bases.append(repr.to_points(stmt));
            scalars.append(*repr.get_scalars());
        });

        // TODO(Perf): Could combine exponents for shared bases more aggresively? Or does the MSM code do it implicitly?

        // Do the MSM and check it equals the (zero) identity
        multi_scalar_mul(&bases, &scalars).point_equals(&point_identity())
```
