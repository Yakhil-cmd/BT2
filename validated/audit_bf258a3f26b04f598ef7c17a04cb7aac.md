### Title
Missing Validation in `set_silo_params` / `set_erc20_fallback_address` Allows Zero-Address Fallback Causing Permanent Token Freeze - (File: engine/src/contract_methods/silo/mod.rs)

---

### Summary

The `set_silo_params` and `set_erc20_fallback_address` entry points accept any `Address` value — including `Address::zero()` — as the ERC-20 fallback address without any sanity check. In Silo mode, when a NEP-141 token transfer targets a non-whitelisted EVM address, the engine redirects the minted ERC-20 tokens to the configured fallback address. If the owner accidentally configures this address as the EVM zero address (`0x0000000000000000000000000000000000000000`), all such redirected tokens are permanently burned (minted to an inaccessible address) while the corresponding NEP-141 tokens remain locked in the connector — a permanent freeze of user funds with no recovery path.

---

### Finding Description

`set_silo_params` in `engine/src/contract_methods/silo/mod.rs` writes both `fixed_gas` and `erc20_fallback_address` directly to storage with no bounds or validity checks:

```rust
pub fn set_silo_params<I: IO>(io: &mut I, args: Option<SiloParamsArgs>) {
    let (cost, address) = args.map_or((None, None), |params| {
        (Some(params.fixed_gas), Some(params.erc20_fallback_address))
    });
    set_fixed_gas(io, cost);
    set_erc20_fallback_address(io, address);   // ← no validation
}
``` [1](#0-0) 

`set_erc20_fallback_address` likewise writes whatever `Address` is supplied:

```rust
pub fn set_erc20_fallback_address<I: IO>(io: &mut I, address: Option<Address>) {
    let key = erc20_fallback_address_key();
    if let Some(address) = address {
        io.write_storage(&key, address.as_bytes());   // ← no zero-address guard
    } else {
        io.remove_storage(&key);
    }
}
``` [2](#0-1) 

The public WASM entry point `set_erc20_fallback_address` in `engine/src/lib.rs` enforces only owner access and then calls the unvalidated storage writer:

```rust
pub extern "C" fn set_erc20_fallback_address() {
    let mut io = Runtime;
    let state = state::get_state(&io).sdk_unwrap();
    require_owner_and_running(&state, &io.predecessor_account_id())
        .map_err(ContractError::msg).sdk_unwrap();
    let args: Erc20FallbackAddressArgs = io.read_input_borsh().sdk_unwrap();
    silo::set_erc20_fallback_address(&mut io, args.address);   // ← Address::zero() accepted
}
``` [3](#0-2) 

The `SiloParamsArgs` type itself imposes no constraint on `erc20_fallback_address`:

```rust
pub struct SiloParamsArgs {
    pub fixed_gas: EthGas,
    pub erc20_fallback_address: Address,   // ← any 20-byte value, including zero
}
``` [4](#0-3) 

The downstream effect is confirmed by the silo test suite: when a NEP-141 token is transferred to Aurora and the recipient EVM address is not in the `Address` whitelist, the ERC-20 tokens are minted to `erc20_fallback_address` rather than the intended recipient. [5](#0-4) 

If `erc20_fallback_address` is `Address::zero()`, the ERC-20 tokens are minted to the EVM zero address. No private key controls `0x000...000`; no NEAR account maps to it via `near_account_to_evm_address`. The NEP-141 tokens are simultaneously locked in the connector. Both sides of the bridge are frozen with no recovery path.

---

### Impact Explanation

**Impact: Critical — Permanent freezing of funds.**

Any user who sends NEP-141 tokens to Aurora via `ft_transfer_call` targeting a non-whitelisted EVM address while the fallback is `Address::zero()` will have their tokens permanently frozen:

- NEP-141 tokens are locked in the ETH connector (cannot be withdrawn without a corresponding ERC-20 burn).
- ERC-20 tokens are minted to `Address::zero()`, which is computationally inaccessible.

There is no on-chain recovery mechanism once the tokens are minted to the zero address.

---

### Likelihood Explanation

**Likelihood: Low.**

The owner must call `set_silo_params` or `set_erc20_fallback_address` with `Address::zero()`. This can happen accidentally (e.g., omitting the address field in a Borsh-encoded payload, which defaults to `[0u8; 20]`, or a scripting error). The `SiloParamsArgs` default implementation already uses `Address::zero()`:

```rust
#[derive(Debug, Default, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SiloParamsArgs {
    pub fixed_gas: EthGas,
    pub erc20_fallback_address: Address,   // Default::default() == Address::zero()
}
``` [4](#0-3) 

The test suite itself uses `Address::zero()` as the fallback address, normalizing the pattern and reducing the chance that a developer would recognize it as dangerous: [6](#0-5) 

Once set, the damage occurs silently on every subsequent non-whitelisted transfer until the owner notices and corrects the configuration.

---

### Recommendation

1. **Short term:** Add an explicit guard in `set_silo_params` and `set_erc20_fallback_address` rejecting `Address::zero()` as the fallback address:

   ```rust
   if address == Address::zero() {
       return Err(b"ERR_INVALID_FALLBACK_ADDRESS".into());
   }
   ```

2. **Short term:** Validate `fixed_gas > 0` when Silo mode is being enabled (a zero fixed-gas in Silo mode silently removes all gas revenue).

3. **Long term:** Add invariant-checking tests that assert no parameter-setting function accepts values that would cause fund loss (zero address, zero gas in Silo mode, overflow-inducing `upgrade_delay_blocks`, etc.).

---

### Proof of Concept

1. Owner calls `set_silo_params` with `SiloParamsArgs { fixed_gas: 1_000_000, erc20_fallback_address: Address::zero() }` — accepted without error.
2. Owner enables the `Address` whitelist via `set_whitelist_status`.
3. User `alice` calls `ft_transfer_call` on a NEP-141 contract, targeting Aurora with message encoding a non-whitelisted EVM address `0xDEAD...`.
4. Aurora's `ft_on_transfer` handler detects `0xDEAD...` is not whitelisted and mints the ERC-20 tokens to `Address::zero()` instead.
5. The NEP-141 tokens are now locked in the connector; the ERC-20 tokens are at `Address::zero()`.
6. Alice's funds are permanently frozen with no recovery path. [1](#0-0) [7](#0-6)

### Citations

**File:** engine/src/contract_methods/silo/mod.rs (L31-38)
```rust
pub fn set_silo_params<I: IO>(io: &mut I, args: Option<SiloParamsArgs>) {
    let (cost, address) = args.map_or((None, None), |params| {
        (Some(params.fixed_gas), Some(params.erc20_fallback_address))
    });

    set_fixed_gas(io, cost);
    set_erc20_fallback_address(io, address);
}
```

**File:** engine/src/contract_methods/silo/mod.rs (L65-73)
```rust
pub fn set_erc20_fallback_address<I: IO>(io: &mut I, address: Option<Address>) {
    let key = erc20_fallback_address_key();

    if let Some(address) = address {
        io.write_storage(&key, address.as_bytes());
    } else {
        io.remove_storage(&key);
    }
}
```

**File:** engine/src/lib.rs (L806-815)
```rust
    pub extern "C" fn set_erc20_fallback_address() {
        let mut io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: Erc20FallbackAddressArgs = io.read_input_borsh().sdk_unwrap();
        silo::set_erc20_fallback_address(&mut io, args.address);
    }
```

**File:** engine/src/lib.rs (L829-839)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn set_silo_params() {
        let mut io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: Option<SiloParamsArgs> = io.read_input_borsh().sdk_unwrap();
        silo::set_silo_params(&mut io, args);
    }
```

**File:** engine-types/src/parameters/silo.rs (L15-24)
```rust
#[derive(Debug, Default, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SiloParamsArgs {
    /// Fixed amount of gas per transaction.
    pub fixed_gas: EthGas,
    /// EVM address, which is used for withdrawing ERC-20 base tokens in case
    /// a recipient of the tokens is not in the silo white list.
    /// Note: the logic described above works only if the fallback address
    /// is set by `set_silo_params` function. In other words, in Silo mode.
    pub erc20_fallback_address: Address,
}
```

**File:** engine-tests/src/tests/silo.rs (L28-32)
```rust
const ERC20_FALLBACK_ADDRESS: Address = Address::zero();
const SILO_PARAMS_ARGS: SiloParamsArgs = SiloParamsArgs {
    fixed_gas: FIXED_GAS,
    erc20_fallback_address: ERC20_FALLBACK_ADDRESS,
};
```

**File:** engine-tests/src/tests/silo.rs (L1140-1208)
```rust
    #[tokio::test]
    async fn test_transfer_nep141_to_non_whitelisted_address_with_another_fallback_address() {
        let SiloTestContext {
            aurora,
            ft_owner,
            ft_owner_address,
            nep_141,
            erc20,
            ..
        } = init_silo().await;

        // Set another EVM fallback address
        let fallback_account = aurora
            .root()
            .create_subaccount("fallback2", NearToken::from_near(10))
            .await
            .unwrap();
        // Call storage deposit for fallback account
        let result = aurora
            .root()
            .call(&nep_141.id(), "storage_deposit")
            .args_json(serde_json::json!({
                "account_id": fallback_account.id(),
                "registration_only": None::<bool>
            }))
            .deposit(NearToken::from_near(50))
            .transact()
            .await
            .unwrap();
        assert!(result.is_success());
        let fallback_address = near_account_to_evm_address(fallback_account.id().as_bytes());
        // Setting a new fallback address.
        let result = aurora
            .set_erc20_fallback_address(Erc20FallbackAddressArgs {
                address: Some(fallback_address),
            })
            .max_gas()
            .transact()
            .await
            .unwrap();
        assert!(result.is_success());

        // Transfer tokens from `ft_owner` to non-whitelisted address `ft_owner_address`
        transfer_nep_141_to_erc_20(
            &nep_141,
            &ft_owner,
            ft_owner_address,
            FT_TRANSFER_AMOUNT,
            &aurora,
        )
        .await;

        // Verify the nep141 and erc20 tokens balances
        assert_eq!(
            nep_141_balance_of(&nep_141, &ft_owner.id()).await,
            FT_TOTAL_SUPPLY - FT_TRANSFER_AMOUNT
        );
        assert_eq!(
            nep_141_balance_of(&nep_141, &fallback_account.id()).await,
            0
        );
        assert_eq!(
            erc20_balance(&erc20, ft_owner_address, &aurora).await,
            0.into()
        );
        assert_eq!(
            erc20_balance(&erc20, fallback_address, &aurora).await,
            FT_TRANSFER_AMOUNT.into()
        );
```
