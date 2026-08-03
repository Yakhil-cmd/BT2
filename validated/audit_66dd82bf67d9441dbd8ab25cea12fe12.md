[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** types/src/transaction/authenticator.rs (L85-90)
```rust
    /// Multi-agent transaction.
    MultiAgent {
        sender: AccountAuthenticator,
        secondary_signer_addresses: Vec<AccountAddress>,
        secondary_signers: Vec<AccountAuthenticator>,
    },
```

**File:** types/src/transaction/authenticator.rs (L2567-2570)
```rust
        let multi_agent_message =
            RawTransactionWithData::new_multi_agent(raw_txn.clone(), vec![secondary_addr]);
        let sender_sig = sender_key.sign(&multi_agent_message).unwrap();
        let secondary_sig = secondary_key.sign(&multi_agent_message).unwrap();
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L376-429)
```text
    fun multi_agent_common_prologue(
        secondary_signer_addresses: vector<address>,
        secondary_signer_public_key_hashes: vector<Option<vector<u8>>>,
        is_simulation: bool,
    ) {
        let num_secondary_signers = secondary_signer_addresses.length();
        assert!(
            secondary_signer_public_key_hashes.length() == num_secondary_signers,
            error::invalid_argument(PROLOGUE_ESECONDARY_KEYS_ADDRESSES_COUNT_MISMATCH),
        );

        let i = 0;
        while ({
            // spec {
            //     invariant i <= num_secondary_signers;
            //     invariant forall j in 0..i:
            //         account::exists_at(secondary_signer_addresses[j]);
            //     invariant forall j in 0..i:
            //         secondary_signer_public_key_hashes[j] == account::get_authentication_key(secondary_signer_addresses[j]) ||
            //             (features::spec_simulation_enhancement_enabled() && is_simulation && vector::is_empty(secondary_signer_public_key_hashes[j]));
            //         account::account_resource_exists_at(secondary_signer_addresses[j])
            //         && secondary_signer_public_key_hashes[j]
            //             == account::get_authentication_key(secondary_signer_addresses[j])
            //             || features::account_abstraction_enabled() && account_abstraction::using_native_authenticator(
            //             secondary_signer_addresses[j]
            //         ) && option::spec_some(secondary_signer_public_key_hashes[j]) == account_abstraction::native_authenticator(
            //         account::exists_at(secondary_signer_addresses[j])
            //         && secondary_signer_public_key_hashes[j]
            //             == account::spec_get_authentication_key(secondary_signer_addresses[j])
            //             || features::spec_account_abstraction_enabled() && account_abstraction::using_native_authenticator(
            //             secondary_signer_addresses[j]
            //         ) && option::spec_some(
            //             secondary_signer_public_key_hashes[j]
            //         ) == account_abstraction::spec_native_authenticator(
            //             secondary_signer_addresses[j]
            //         );
            // };
            (i < num_secondary_signers)
        }) {
            let secondary_address = secondary_signer_addresses[i];
            assert!(account::exists_at(secondary_address), error::invalid_argument(PROLOGUE_EACCOUNT_DOES_NOT_EXIST));
            let signer_public_key_hash = secondary_signer_public_key_hashes[i];
            if (!skip_auth_key_check(is_simulation, &signer_public_key_hash)) {
                if (signer_public_key_hash.is_some()) {
                    assert!(
                        signer_public_key_hash == option::some(account::get_authentication_key(secondary_address)),
                        error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                    );
                } else {
                    assert!(
                        allow_missing_txn_authentication_key(secondary_address),
                        error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                    )
                };
```

**File:** api/types/src/transaction.rs (L2416-2433)
```rust
impl VerifyInput for MultiAgentSignature {
    fn verify(&self) -> anyhow::Result<()> {
        self.sender.verify()?;

        if self.secondary_signer_addresses.is_empty() {
            bail!("MultiAgent signature has no secondary signer addresses")
        } else if self.secondary_signers.is_empty() {
            bail!("MultiAgent signature has no secondary signatures")
        } else if self.secondary_signers.len() != self.secondary_signer_addresses.len() {
            bail!("MultiAgent signatures don't match addresses length")
        }

        for signer in self.secondary_signers.iter() {
            signer.verify()?;
        }
        Ok(())
    }
}
```
