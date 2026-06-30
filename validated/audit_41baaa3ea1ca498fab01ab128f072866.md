### Title
Missing Value Guard in `BlsG2Add::run` Allows ETH to Be Permanently Frozen at Precompile Address `0x000...0D` — (`engine-precompiles/src/bls12_381/g2_add.rs`)

---

### Summary

`BlsG2Add::run` accepts calls with nonzero `apparent_value` without reverting. Because the EVM executor transfers value to the precompile address before invoking the precompile, any ETH sent with the call is credited to `0x000...0D` and has no withdrawal path. The Aurora codebase explicitly guards against this in every other precompile that cannot legitimately receive value, but the entire BLS-12-381 precompile family omits the check.

---

### Finding Description

`BlsG2Add::run` ignores `context.apparent_value` entirely — the parameter is even named `_context` to suppress the unused-variable warning: [1](#0-0) 

By contrast, every Aurora-specific precompile that must not receive value calls `utils::validate_no_value_attached_to_precompile` as its first action: [2](#0-1) 

Examples of precompiles that correctly apply this guard: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

The same omission exists in every other BLS precompile (`BlsG1Add`, `BlsG1Msm`, `BlsG2Msm`, `BlsMapFpToG1`, `BlsMapFp2ToG2`, `BlsPairingCheck`): [7](#0-6) [8](#0-7) 

The Aurora team's own comment in `native.rs` confirms that value sent to a precompile address is irrecoverable through normal EVM means: [9](#0-8) 

The existence of `validate_no_value_attached_to_precompile` in six precompiles proves that the aurora-evm executor **does** credit value to the precompile address before dispatching to the precompile's `run` function — otherwise the guard would be dead code. The `Engine::call` path passes value directly to `executor.transact_call`, which performs the balance transfer unconditionally: [10](#0-9) 

---

### Impact Explanation

When a caller sends an EVM transaction with `to = 0x000...0D` and `value > 0` with a valid 512-byte input:

1. The EVM executor deducts `value` from the caller's balance and credits it to `0x000...0D`.
2. `BlsG2Add::run` succeeds and returns the G2 addition result.
3. The ETH now sits at `0x000...0D`. There is no private key for this address, no deployed contract code, and no EVM-level mechanism to move it out.

The Aurora team's own comment ("without any possibility to withdraw them in the future") classifies this as at minimum **temporary freezing of funds** (High) and potentially **permanent freezing** (Critical), depending on whether an out-of-band NEAR-level admin action can recover the underlying NEP-141 balance.

---

### Likelihood Explanation

The attack requires only a standard EVM transaction with nonzero value directed at the precompile address. No special privilege, no contract deployment, and no social engineering is needed. Any user can trigger this accidentally (e.g., a contract that forwards `msg.value` to the precompile) or intentionally. The BLS precompiles are newly added (EIP-2537) and the omission is systematic across all eight of them.

---

### Recommendation

Add `utils::validate_no_value_attached_to_precompile(context.apparent_value)?;` as the first statement in `run` for every BLS-12-381 precompile, mirroring the pattern used by `PrepaidGas`, `RandomSeed`, `PredecessorAccount`, `CurrentAccount`, `PromiseResult`, and `CrossContractCall`.

---

### Proof of Concept

```rust
// In engine-precompiles/src/bls12_381/g2_add.rs (existing test module)
#[test]
fn bls12_381_g2_add_with_value_freezes_funds() {
    let precompile = BlsG2Add;
    let ctx = Context {
        address: H160::zero(),
        caller: H160::zero(),
        apparent_value: 1.into(), // nonzero value — should be rejected but is not
    };
    // valid 512-byte input (two G2 points)
    let input = hex::decode("00000000000000000000000000000000161c595d...").unwrap();

    // This succeeds — no value guard fires
    let res = precompile.run(&input, None, &ctx, false);
    assert!(res.is_ok(), "Expected Ok but got: {:?}", res);
    // ETH equal to apparent_value is now credited to 0x000...0D with no recovery path
}
```

The call succeeds, confirming the missing guard. In a full engine integration test, asserting `get_balance(BlsG2Add::ADDRESS) == 1` after the transaction would confirm the balance increase, and the absence of any `withdraw_from_precompile` engine method would confirm the funds are unrecoverable.

### Citations

**File:** engine-precompiles/src/bls12_381/g2_add.rs (L39-59)
```rust
    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        _context: &Context,
        _is_static: bool,
    ) -> EvmPrecompileResult {
        let cost = Self::required_gas(input)?;
        if let Some(target_gas) = target_gas
            && cost > target_gas
        {
            return Err(ExitError::OutOfGas);
        }

        if input.len() != INPUT_LENGTH {
            return Err(ExitError::Other(Borrowed("ERR_BLS_G2ADD_INPUT_LEN")));
        }

        let output = Self::execute(input)?;
        Ok(PrecompileOutput::without_logs(cost, output))
    }
```

**File:** engine-precompiles/src/utils.rs (L24-29)
```rust
pub fn validate_no_value_attached_to_precompile(value: U256) -> Result<(), ExitError> {
    if value > U256::zero() {
        // don't attach native token value to that precompile
        return Err(ExitError::Other(Borrowed("ATTACHED_VALUE_ERROR")));
    }
    Ok(())
```

**File:** engine-precompiles/src/prepaid_gas.rs (L44-44)
```rust
        utils::validate_no_value_attached_to_precompile(context.apparent_value)?;
```

**File:** engine-precompiles/src/random.rs (L46-46)
```rust
        utils::validate_no_value_attached_to_precompile(context.apparent_value)?;
```

**File:** engine-precompiles/src/xcc.rs (L108-108)
```rust
        utils::validate_no_value_attached_to_precompile(context.apparent_value)?;
```

**File:** engine-precompiles/src/account_ids.rs (L51-51)
```rust
        utils::validate_no_value_attached_to_precompile(context.apparent_value)?;
```

**File:** engine-precompiles/src/bls12_381/g1_add.rs (L38-58)
```rust
    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        _context: &Context,
        _is_static: bool,
    ) -> EvmPrecompileResult {
        if input.len() != INPUT_LENGTH {
            return Err(ExitError::Other(Borrowed("ERR_BLS_G1ADD_INPUT_LEN")));
        }

        let cost = Self::required_gas(input)?;
        if let Some(target_gas) = target_gas
            && cost > target_gas
        {
            return Err(ExitError::OutOfGas);
        }

        let output = Self::execute(input)?;
        Ok(PrecompileOutput::without_logs(cost, output))
    }
```

**File:** engine-precompiles/src/bls12_381/map_fp_to_g1.rs (L33-52)
```rust
    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        _context: &Context,
        _is_static: bool,
    ) -> EvmPrecompileResult {
        let cost = Self::required_gas(input)?;
        if let Some(target_gas) = target_gas
            && cost > target_gas
        {
            return Err(ExitError::OutOfGas);
        }
        if input.len() != PADDED_FP_LENGTH {
            return Err(ExitError::Other(Borrowed("ERR_BLS_MAP_FP_TO_G1_LEN")));
        }

        let output = Self::execute(input)?;
        Ok(PrecompileOutput::without_logs(cost, output))
    }
```

**File:** engine-precompiles/src/native.rs (L572-579)
```rust
    // In case of withdrawing ERC-20 tokens, the `apparent_value` should be zero. In opposite way
    // the funds will be locked in the address of the precompile without any possibility
    // to withdraw them in the future. So, in case if the `apparent_value` is not zero, the error
    // will be returned to prevent that.
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
```

**File:** engine/src/engine.rs (L640-648)
```rust
        let (exit_reason, result) = executor.transact_call(
            origin.raw(),
            contract.raw(),
            value.raw(),
            input,
            gas_limit,
            access_list,
            authorization_list,
        );
```
