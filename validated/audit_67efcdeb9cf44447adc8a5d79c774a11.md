The code evidence is conclusive. Let me trace the full path precisely.

**`PrecompileFlags` definition** — only two bits exist: [1](#0-0) 

**`from_address` / `is_paused_by_address`** — any address that is not `exit_to_near` or `exit_to_ethereum` returns `None`, which makes `is_paused_by_address` return `false`: [2](#0-1) 

**`pause_precompiles` admin call** — uses `from_bits_truncate`, which silently drops all bits beyond bit 1, so even `0xFFFFFFFF` becomes `0b11`: [3](#0-2) 

**`apply_pause_flags_to_precompiles`** — filters using `is_paused_by_address`, so only EXIT_TO_NEAR and EXIT_TO_ETHEREUM addresses ever enter `paused_precompiles`: [4](#0-3) 

**XCC, PredecessorAccount, PrepaidGas, PromiseResult are all registered** but can never be added to `paused_precompiles`: [5](#0-4) 

**`Precompiles::execute` pause gate** — only blocks execution if the address is in `paused_precompiles`, which XCC never is: [6](#0-5) 

---

### Title
Incomplete `PrecompileFlags` Bitmask Leaves XCC and Other Aurora Precompiles Permanently Unpausable — (`engine/src/pausables.rs`)

### Summary
`PrecompileFlags` defines only two bits (`EXIT_TO_NEAR`, `EXIT_TO_ETHEREUM`). The `CrossContractCall`, `PromiseResult`, `PrepaidGas`, and `PredecessorAccount` precompiles have no corresponding flag bits. As a result, `apply_pause_flags_to_precompiles` can never add their addresses to `paused_precompiles`, and `Precompiles::execute` will never return `ERR_PAUSED` for them — regardless of what mask the admin passes to `pause_precompiles`.

### Finding Description

`PrecompileFlags` in `engine/src/pausables.rs` is a `bitflags!` struct with exactly two named constants:

```rust
pub struct PrecompileFlags: u32 {
    const EXIT_TO_NEAR     = 0b01;
    const EXIT_TO_ETHEREUM = 0b10;
}
```

`PrecompileFlags::from_address` maps only those two addresses; for every other address it returns `None`. `is_paused_by_address` propagates that `None` as `false`.

When the admin calls `pause_precompiles` with any mask (including `0xFFFFFFFF`), the call path is:

```
pause_precompiles(0xFFFFFFFF)
  → PrecompileFlags::from_bits_truncate(0xFFFFFFFF)   // yields 0b11 only
  → pauser.pause_precompiles(flags)                   // stores 0b11 in storage
```

Later, when an EVM transaction targets `cross_contract_call::ADDRESS`:

```
Engine::create_precompiles(pause_flags = 0b11, ...)
  → apply_pause_flags_to_precompiles(precompiles, 0b11)
      // iterates all_precompiles.keys()
      // for XCC address: is_paused_by_address → from_address → None → false
      // XCC address is NOT inserted into paused_precompiles
  → Precompiles::execute(handle)
      // is_paused(xcc_address) → false
      // proceeds to AllPrecompiles::CrossContractCall(p) → executes normally
```

The same applies to `predecessor_account::ADDRESS`, `prepaid_gas::ADDRESS`, and `promise_result::ADDRESS`.

### Impact Explanation

The XCC precompile (`cross_contract_call::ADDRESS`) allows EVM callers to schedule arbitrary NEAR cross-contract calls, including calls to token contracts that transfer NEAR-native assets. The pause mechanism is the primary emergency circuit-breaker. If a vulnerability in XCC is being actively exploited, the admin's only recourse — calling `pause_precompiles` — has zero effect on XCC. The exploit continues unimpeded, enabling direct theft of user funds (wNEAR, NEP-141 tokens) that flow through the XCC path.

### Likelihood Explanation

The precondition is simply that the admin has called `pause_precompiles` believing it halts all Aurora-specific precompiles. Any EVM account can then invoke XCC normally. No special privilege or key compromise is required on the attacker's side. The bug is in the production code path and is unconditional.

### Recommendation

Add flag bits for every Aurora-specific precompile and extend `from_address` to cover them:

```rust
pub struct PrecompileFlags: u32 {
    const EXIT_TO_NEAR           = 0b000001;
    const EXIT_TO_ETHEREUM       = 0b000010;
    const CROSS_CONTRACT_CALL    = 0b000100;
    const PREDECESSOR_ACCOUNT    = 0b001000;
    const PREPAID_GAS            = 0b010000;
    const PROMISE_RESULT         = 0b100000;
}
```

Update `from_address` to map each new address to its flag, and add integration tests asserting that `pause_precompiles(ALL_BITS)` causes `execute` on each Aurora precompile address to return `ERR_PAUSED`.

### Proof of Concept

```rust
// In engine/src/pausables.rs tests or a new integration test:
#[test]
fn test_xcc_is_not_paused_when_all_flags_set() {
    use aurora_engine_precompiles::xcc::cross_contract_call;
    let flags = PrecompileFlags::all(); // 0b11 — does NOT include XCC
    // XCC address is not EXIT_TO_NEAR or EXIT_TO_ETHEREUM
    assert!(
        !flags.is_paused_by_address(&cross_contract_call::ADDRESS),
        "XCC must be pausable but is not — bug confirmed"
    );
}
```

This test passes on unmodified code, confirming that `PrecompileFlags::all()` (the maximum possible pause mask) does not cover the XCC precompile address, and `apply_pause_flags_to_precompiles` will therefore never insert it into `paused_precompiles`.

### Citations

**File:** engine/src/pausables.rs (L9-16)
```rust
bitflags! {
    /// Wraps unsigned integer where each bit identifies a different precompile.
    #[derive(BorshSerialize, BorshDeserialize, Default)]
    #[borsh(crate = "aurora_engine_types::borsh")]
    pub struct PrecompileFlags: u32 {
        const EXIT_TO_NEAR        = 0b01;
        const EXIT_TO_ETHEREUM    = 0b10;
    }
```

**File:** engine/src/pausables.rs (L19-35)
```rust
impl PrecompileFlags {
    #[must_use]
    pub fn from_address(address: &Address) -> Option<Self> {
        Some(if address == &exit_to_ethereum::ADDRESS {
            Self::EXIT_TO_ETHEREUM
        } else if address == &exit_to_near::ADDRESS {
            Self::EXIT_TO_NEAR
        } else {
            return None;
        })
    }

    /// Checks if the precompile belonging to the `address` is marked as paused.
    #[must_use]
    pub fn is_paused_by_address(&self, address: &Address) -> bool {
        Self::from_address(address).is_some_and(|precompile_flag| self.contains(precompile_flag))
    }
```

**File:** engine/src/contract_methods/admin.rs (L235-238)
```rust
        let args: PausePrecompilesCallArgs = io.read_input_borsh()?;
        let flags = PrecompileFlags::from_bits_truncate(args.paused_mask);
        let mut pauser = EnginePrecompilesPauser::from_io(io);
        pauser.pause_precompiles(flags);
```

**File:** engine/src/engine.rs (L938-951)
```rust
    fn apply_pause_flags_to_precompiles<H: ReadOnlyPromiseHandler>(
        precompiles: Precompiles<'env, I, E, H>,
        pause_flags: PrecompileFlags,
    ) -> Precompiles<'env, I, E, H> {
        Precompiles {
            paused_precompiles: precompiles
                .all_precompiles
                .keys()
                .filter(|address| pause_flags.is_paused_by_address(address))
                .copied()
                .collect(),
            all_precompiles: precompiles.all_precompiles,
        }
    }
```

**File:** engine-precompiles/src/lib.rs (L140-144)
```rust
        if self.is_paused(&address) {
            return Some(Err(PrecompileFailure::Fatal {
                exit_status: ExitFatal::Other(prelude::Cow::Borrowed("ERR_PAUSED")),
            }));
        }
```

**File:** engine-precompiles/src/lib.rs (L479-494)
```rust
        generic_precompiles.insert(
            cross_contract_call::ADDRESS,
            AllPrecompiles::CrossContractCall(cross_contract_call),
        );
        generic_precompiles.insert(
            predecessor_account::ADDRESS,
            AllPrecompiles::PredecessorAccount(predecessor_account_id),
        );
        generic_precompiles.insert(
            prepaid_gas::ADDRESS,
            AllPrecompiles::PrepaidGas(prepaid_gas),
        );
        generic_precompiles.insert(
            promise_result::ADDRESS,
            AllPrecompiles::PromiseResult(promise_results),
        );
```
