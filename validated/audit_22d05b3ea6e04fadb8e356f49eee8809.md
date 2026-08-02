No vulnerability found for this question.

**Reasoning:** `StatementBuilder<phantom P>` in `sigma_protocol_statement_builder.move` is generic only at compile time, and every production call site pins `P` explicitly through the function's declared return type — e.g., `sigma_protocol_key_rotation::new_key_rotation_statement` returns `Statement<KeyRotation>` and calls `new_builder()`/`b.build()` where Move's type inference resolves `P = KeyRotation` from that return-type annotation [1](#0-0) . The builder module itself only exposes `new_builder`, `add_point(s)`, `add_scalar`, and `build` as `public(friend)`, restricted to a fixed, hardcoded friend list (`sigma_protocol_registration`, `sigma_protocol_withdraw`, `sigma_protocol_transfer`, `sigma_protocol_key_rotation`, plus test-only friends) [2](#0-1) . There is no shared helper function that accepts a generic `StatementBuilder<P>` from one proof module (e.g. withdraw) and calls `build` under a different type binding for another module (e.g. transfer) — each of `sigma_protocol_registration.move`, `sigma_protocol_withdraw.move`, `sigma_protocol_transfer.move`, and `sigma_protocol_key_rotation.move` independently constructs and builds its own dedicated `Statement<P>` type inline, with `P` fixed by that module's own return-type signature.

Because `P` is resolved entirely by the Move compiler at compile time from each module's own statically-declared function signatures — not from any transaction input, authenticator, or runtime value — there is no way for unprivileged transaction/proof input to cause `points`/`compressed_points`/`scalars` populated under one phantom type to be `build`-committed under a different phantom type. This is a compile-time type-safety property of Move generics, not a runtime check that could be bypassed by malicious input, and it does not fall within the transaction-admission boundary (mempool/vm-validator/authenticator binding) described in the review scope.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/proofs/sigma_protocol_key_rotation.move (L196-212)
```text
    public(friend) fun new_key_rotation_statement(
        compressed_ek: CompressedRistretto,
        compressed_new_ek: CompressedRistretto,
        compressed_old_R: &vector<CompressedRistretto>,
        compressed_new_R: &vector<CompressedRistretto>,
    ): Statement<KeyRotation> {
        let err = error::internal(E_STATEMENT_BUILDER_INCONSISTENCY);
        let b = new_builder();
        assert!(b.add_point(get_encryption_key_basepoint_compressed()) == IDX_H, err);                  // H
        assert!(b.add_point(compressed_ek) == IDX_EK, err);                                                // ek
        assert!(b.add_point(compressed_new_ek) == IDX_EK_NEW, err);                                        // new_ek
        assert!(b.add_points(compressed_old_R) == START_IDX_OLD_R, err);                                   // old_R
        assert!(b.add_points(compressed_new_R) == START_IDX_OLD_R + get_num_available_chunks(), err);      // new_R
        let stmt = b.build();
        assert_key_rotation_statement_is_well_formed(&stmt);
        stmt
    }
```

**File:** aptos-move/framework/aptos-framework/sources/confidential_asset/sigma_protocols/sigma_protocol_statement_builder.move (L15-25)
```text
module aptos_framework::sigma_protocol_statement_builder {
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
```
