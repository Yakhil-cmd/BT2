Based on my review of `withdraw_to_raw` and the associated sigma-protocol statement/verification code:

**No vulnerability found for this question.**

Rationale:

1. **`to` is not attacker-controlled cross-account input — it's the signer's own choice.** `withdraw_to_raw` requires a `sender: &signer`, and `to` is simply an ordinary Move entry-function argument, not a value derived from someone else's approval. [1](#0-0) 

2. **The entire transaction, including `to`, is covered by the account's own signature.** Since `to` is a BCS-serialized entry-function argument, it is part of the signed `RawTransaction`; an attacker cannot swap `to` in someone else's already-signed transaction without invalidating that signature (which would require a leaked key — explicitly out of scope). If the attacker is the legitimate `sender` themselves, choosing an arbitrary `to` is the intended behavior of a withdraw-to-any-address primitive, not a binding violation.

3. **The sigma-protocol statement correctly binds what needs cryptographic protection: the sender's own encryption key and old/new balance, not the recipient address.** The withdrawal relation proves that the sender's ciphertext balance was correctly decremented by `v` given their own `ek`/`dk`; the domain separator (`WithdrawSession`) binds the proof to `sender`, `asset_type`, `num_chunks`, and `has_auditor`, but has no dependency on `to` because `to` isn't part of the zero-knowledge witness — it's a plaintext post-processing destination for the publicly-withdrawn funds. [2](#0-1) [3](#0-2) 

4. **`withdraw_to` reads the sender's own `ek` and `old_balance` from their own `ConfidentialStore`,** so a proof from one account's balance state cannot be replayed to move a *different* account's confidential balance — the statement would fail to verify against a mismatched `ek`/old balance. [4](#0-3) 

Since the attacker in this scenario is required to already be a registered `ConfidentialStore` owner acting as their own transaction's signer, and the proof/statement design deliberately excludes `to` from the witness (because `to` needs no confidentiality protection — only the sender's balance decrement does), there is no unauthorized redirection of another party's funds, no sender/signer confusion, and no admission-layer binding failure. This is the intended design of the withdraw-to-arbitrary-recipient feature, not an admission-boundary defect.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/confidential_asset.move (L494-512)
```text
    public entry fun withdraw_to_raw(
        sender: &signer,
        asset_type: Object<fungible_asset::Metadata>,
        to: address,
        amount: u64,
        new_balance_P: vector<vector<u8>>,
        new_balance_R: vector<vector<u8>>,
        new_balance_R_aud: vector<vector<u8>>,  // effective auditor R component
        zkrp_new_balance: vector<u8>,
        sigma_proto_comm: vector<vector<u8>>,
        sigma_proto_resp: vector<vector<u8>>
    ) acquires ConfidentialStore, GlobalConfig, AssetConfig {
        let compressed_new_balance = new_compressed_available_from_bytes(new_balance_P, new_balance_R, new_balance_R_aud);
        let zkrp_new_balance = bulletproofs::range_proof_from_bytes(zkrp_new_balance);
        let sigma = sigma_protocol_proof::new_proof_from_bytes(sigma_proto_comm, sigma_proto_resp);
        let proof = WithdrawalProof::V1 { compressed_new_balance, zkrp_new_balance, sigma };

        withdraw_to(sender, asset_type, to, amount, proof);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/confidential_asset.move (L528-538)
```text
        let sender_addr = signer::address_of(sender);

        // Read values before mutable borrow to avoid conflicting borrows of ConfidentialStore
        let ek = get_encryption_key(sender_addr, asset_type);
        let old_balance = get_available_balance(sender_addr, asset_type);
        let effective_auditor = get_effective_auditor_config(asset_type);

        let compressed_new_balance = assert_valid_withdrawal_proof(
            sender, asset_type,
            &ek, amount, &old_balance, &effective_auditor.config.ek, proof
        );
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/proofs/sigma_protocol_withdraw.move (L155-238)
```text
    /// Phantom marker type for withdrawal statements.
    struct Withdrawal has drop {}

    /// Used for domain separation in the Fiat-Shamir transform.
    struct WithdrawSession has drop {
        sender: address,
        asset_type: Object<Metadata>,
        num_chunks: u64,
        has_auditor: bool,
    }

    //
    // Helper functions
    //

    /// Returns the fixed number of balance chunks ℓ (= AVAILABLE_BALANCE_CHUNKS).
    inline fun get_num_chunks(): u64 {
        get_num_available_chunks()
    }

    /// Validates that the statement has the correct structure for the given auditor flag.
    fun assert_withdraw_statement_is_well_formed(stmt: &Statement<Withdrawal>, has_auditor: bool) {
        let ell = get_num_chunks();
        let expected = 3 + 4 * ell + if (has_auditor) { 1 + ell } else { 0 };
        assert!(stmt.get_points().length() == expected,e_wrong_num_points());
        // i.e., the transferred amount v
        assert!(stmt.get_scalars().length() == 1, e_wrong_num_scalars());
    }

    //
    // Public functions
    //

    public(friend) fun new_session(sender: &signer, asset_type: Object<Metadata>, has_auditor: bool): WithdrawSession {
        WithdrawSession {
            sender: signer::address_of(sender),
            asset_type,
            num_chunks: get_num_chunks(),
            has_auditor,
        }
    }

    /// Creates a withdrawal statement, optionally including auditor components.
    ///
    /// Points (auditorless): [ G, H, ek, old_P[0..ℓ-1], old_R[0..ℓ-1], new_P[0..ℓ-1], new_R[0..ℓ-1] ]
    /// Points (w/ auditor):  [ ---------------------------- as above ------------------------------, ek_aud, new_R_aud]
    /// Scalars:              [ v ]
    ///
    /// For the auditorless case, pass `option::none()` for `compressed_ek_aud`
    /// and ensure `new_balance` / `compressed_new_balance` have empty R_aud.
    public(friend) fun new_withdrawal_statement(
        compressed_ek: CompressedRistretto,
        compressed_old_balance: &CompressedBalance<Available>,
        compressed_new_balance: &CompressedBalance<Available>,
        compressed_ek_aud: &Option<CompressedRistretto>,
        v: Scalar,
    ): Statement<Withdrawal> {
        assert!(
            compressed_new_balance.get_compressed_R_aud().length() == if (compressed_ek_aud.is_some()) { get_num_chunks() } else { 0 },
            error::invalid_argument(E_AUDITOR_COUNT_MISMATCH)
        );

        let ell = get_num_chunks();
        let err = error::internal(E_STATEMENT_BUILDER_INCONSISTENCY);
        let b = new_builder();

        assert!(b.add_point(ristretto255::basepoint_compressed()) == IDX_G, err);                                  // G
        assert!(b.add_point(get_encryption_key_basepoint_compressed()) == IDX_H, err);                             // H
        assert!(b.add_point(compressed_ek) == IDX_EK, err);                                                           // ek
        assert!(b.add_points(compressed_old_balance.get_compressed_P()) == START_IDX_OLD_P, err);                  // old_P
        assert!(b.add_points(compressed_old_balance.get_compressed_R()) == START_IDX_OLD_P + ell, err);            // old_R
        assert!(b.add_points(compressed_new_balance.get_compressed_P()) == START_IDX_OLD_P + 2 * ell, err);        // new_P
        assert!(b.add_points(compressed_new_balance.get_compressed_R()) == START_IDX_OLD_P + 3 * ell, err);        // new_R

        if (compressed_ek_aud.is_some()) {
            assert!(b.add_point(*compressed_ek_aud.borrow()) == START_IDX_OLD_P + 4 * ell, err);                        // ek_aud
            assert!(b.add_points(compressed_new_balance.get_compressed_R_aud()) == START_IDX_OLD_P + 4 * ell + 1, err); // new_R_aud
        };

        assert!(b.add_scalar(v) == IDX_V, err);
        let stmt = b.build();
            assert_withdraw_statement_is_well_formed(&stmt, compressed_ek_aud.is_some());
        stmt
    }
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/proofs/sigma_protocol_withdraw.move (L384-396)
```text
    public(friend) fun assert_verifies(self: &WithdrawSession, stmt: &Statement<Withdrawal>, proof: &Proof) {
        assert_withdraw_statement_is_well_formed(stmt, self.has_auditor);

        let success = sigma_protocol::verify(
            new_domain_separator(@aptos_framework, chain_id::get(), WITHDRAWAL_PROTOCOL_ID, bcs::to_bytes(self)),
            |_X, w| psi(_X, w, self.has_auditor),
            |_X| f(_X, self.has_auditor),
            stmt,
            proof
        );

        assert!(success, error::invalid_argument(E_INVALID_PROOF));
    }
```
