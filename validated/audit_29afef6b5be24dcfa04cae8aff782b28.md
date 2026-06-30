### Title
`EXIT_TO_ETHEREUM` Precompile Pause Bypassed via NEAR-Level `withdraw()` - (File: `engine/src/contract_methods/connector.rs`)

---

### Summary

The Aurora Engine exposes two withdrawal paths for ETH: the EVM-level `EXIT_TO_ETHEREUM` precompile and the NEAR-level `withdraw()` contract method. The precompile pause system (`PrecompileFlags::EXIT_TO_ETHEREUM`) is only enforced inside the EVM executor path. The NEAR-level `withdraw()` function checks only `require_running` (global contract pause) and never consults the precompile pause flags. Any user can therefore call `withdraw()` directly on the NEAR contract to exit ETH to Ethereum even when the `EXIT_TO_ETHEREUM` precompile has been explicitly paused by an authorized pauser.

---

### Finding Description

Aurora Engine implements a granular pause system for its exit precompiles. `PrecompileFlags` defines two pausable flags: [1](#0-0) 

The `EnginePrecompilesPauser` stores and reads these flags from contract storage, and `is_paused_by_address` is used inside the EVM engine to block calls to a paused precompile address before execution proceeds. [2](#0-1) 

However, the NEAR-level `withdraw()` function — which is the non-EVM entry point for the same ETH-to-Ethereum bridge exit — performs no such check: [3](#0-2) 

It calls only `require_running` (global contract liveness check) and then forwards the withdrawal directly to the eth-connector contract via a NEAR promise. The precompile pause flags stored under `PAUSE_FLAGS_KEY` are never read.

This function is exposed as a public NEAR contract method: [4](#0-3) 

The `EXIT_TO_ETHEREUM` precompile itself, when invoked through the EVM, calls the connector's `withdraw` method identically: [5](#0-4) 

Both paths reach the same connector `withdraw` endpoint, but only the EVM path is gated by the pause flag.

---

### Impact Explanation

When an authorized pauser calls `pause_precompiles` with `EXIT_TO_ETHEREUM`, the intent is to halt all ETH withdrawals from Aurora to Ethereum — for example, during a bridge exploit, a connector vulnerability, or an emergency security response. Because the NEAR-level `withdraw()` bypasses the pause check entirely, any user can continue draining ETH from Aurora to Ethereum addresses throughout the pause window. The pause mechanism provides a false sense of security: operators believe withdrawals are halted, but they are not.

**Impact class:** High — temporary freezing of funds is defeated; in a live-exploit scenario this escalates to Critical (direct theft of funds in motion).

---

### Likelihood Explanation

- The `withdraw()` NEAR method is a standard, documented, publicly callable entry point requiring only 1 yoctoNEAR attached.
- No special role, key, or privilege is needed beyond being a normal Aurora user.
- The discrepancy between the two withdrawal paths is a straightforward code omission, not a complex attack chain.
- Any user monitoring the mempool for a `pause_precompiles` transaction can immediately front-run or race the pause by calling `withdraw()` directly.

---

### Recommendation

Add a precompile pause check inside `withdraw()` before forwarding the promise, mirroring the check that the EVM engine applies to the precompile address:

```rust
pub fn withdraw<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;

    // Add: enforce the EXIT_TO_ETHEREUM precompile pause
    let pauser = EnginePrecompilesPauser::from_io(io);
    if pauser.is_paused(PrecompileFlags::EXIT_TO_ETHEREUM) {
        return Err(errors::ERR_PAUSED.into());
    }

    env.assert_one_yocto()?;
    // ... rest unchanged
}
```

The same pattern should be applied to any other NEAR-level methods that duplicate paused-precompile functionality (e.g., `ft_transfer` / `ft_transfer_call` relative to `EXIT_TO_NEAR`). [6](#0-5) 

---

### Proof of Concept

1. Authorized pauser calls `pause_precompiles` with `PrecompileFlags::EXIT_TO_ETHEREUM` (bit `0b10`). The flag is written to storage under `PAUSE_FLAGS_KEY`.
2. Any EVM transaction that calls the `exit_to_ethereum` precompile address (`0xb0bd02f6...`) is now rejected by the engine's pause check.
3. Attacker calls the NEAR contract method `withdraw({"recipient_address": "<eth_addr>", "amount": N})` with 1 yoctoNEAR attached.
4. `withdraw()` in `connector.rs` reads state, calls `require_running` (passes — contract is running), and immediately creates a NEAR promise to the eth-connector's `engine_withdraw` method.
5. The eth-connector processes the withdrawal and burns the NEP-141 ETH balance, releasing ETH on Ethereum to the attacker's address.
6. The `EXIT_TO_ETHEREUM` pause flag was never consulted; the withdrawal succeeds in full. [3](#0-2) [7](#0-6)

### Citations

**File:** engine/src/pausables.rs (L9-17)
```rust
bitflags! {
    /// Wraps unsigned integer where each bit identifies a different precompile.
    #[derive(BorshSerialize, BorshDeserialize, Default)]
    #[borsh(crate = "aurora_engine_types::borsh")]
    pub struct PrecompileFlags: u32 {
        const EXIT_TO_NEAR        = 0b01;
        const EXIT_TO_ETHEREUM    = 0b10;
    }
}
```

**File:** engine/src/pausables.rs (L31-35)
```rust
    /// Checks if the precompile belonging to the `address` is marked as paused.
    #[must_use]
    pub fn is_paused_by_address(&self, address: &Address) -> bool {
        Self::from_address(address).is_some_and(|precompile_flag| self.contains(precompile_flag))
    }
```

**File:** engine/src/pausables.rs (L109-138)
```rust
impl<I: IO> EnginePrecompilesPauser<I> {
    /// Key for storing [`PrecompileFlags`].
    const PAUSE_FLAGS_KEY: &'static [u8; 11] = b"PAUSE_FLAGS";

    /// Creates new [`EnginePrecompilesPauser`] instance that reads from and writes into storage accessed using `io`.
    pub const fn from_io(io: I) -> Self {
        Self { io }
    }

    fn read_flags_from_storage(&self) -> PrecompileFlags {
        self.io
            .read_storage(&Self::storage_key())
            .map_or_else(PrecompileFlags::empty, |bytes| {
                const U32_SIZE: usize = size_of::<u32>();
                assert_eq!(bytes.len(), U32_SIZE, "PrecompileFlags value is corrupted");
                let mut buffer = [0u8; U32_SIZE];
                bytes.copy_to_slice(&mut buffer);
                PrecompileFlags::from_bits_truncate(u32::from_le_bytes(buffer))
            })
    }

    fn write_flags_into_storage(&mut self, pause_flags: PrecompileFlags) {
        self.io
            .write_storage(&Self::storage_key(), &pause_flags.bits().to_le_bytes());
    }

    fn storage_key() -> Vec<u8> {
        bytes_to_key(KeyPrefix::Config, Self::PAUSE_FLAGS_KEY)
    }
}
```

**File:** engine/src/pausables.rs (L146-154)
```rust
impl<I: IO> PausedPrecompilesChecker for EnginePrecompilesPauser<I> {
    fn is_paused(&self, precompiles: PrecompileFlags) -> bool {
        self.read_flags_from_storage().contains(precompiles)
    }

    fn paused(&self) -> PrecompileFlags {
        self.read_flags_from_storage()
    }
}
```

**File:** engine/src/contract_methods/connector.rs (L43-59)
```rust
pub fn withdraw<I: IO + Copy + PromiseHandler, E: Env>(
    io: I,
    env: &E,
) -> Result<(), ContractError> {
    require_running(&state::get_state(&io)?)?;
    env.assert_one_yocto()?;

    let args: WithdrawCallArgs = io.read_input_borsh()?;
    let args = borsh::to_vec(&EngineWithdrawCallArgs {
        sender_id: env.predecessor_account_id(),
        recipient_address: args.recipient_address,
        amount: args.amount,
    })
    .unwrap();

    return_promise(io, env, "engine_withdraw", args, ONE_YOCTO)
}
```

**File:** engine/src/lib.rs (L544-550)
```rust
    pub extern "C" fn withdraw() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::connector::withdraw(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine-precompiles/src/native.rs (L977-985)
```rust
        let withdraw_promise = PromiseCreateArgs {
            target_account_id: nep141_address,
            method: "withdraw".to_string(),
            args: serialized_args,
            attached_balance: Yocto::new(1),
            attached_gas: costs::WITHDRAWAL_GAS,
        };

        let promise = borsh::to_vec(&PromiseArgs::Create(withdraw_promise)).unwrap();
```
