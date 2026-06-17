### Title
Two Divergent Base Token Minting Paths Coexist with Conflicting Accounting Semantics — (`system_hooks/src/call_hooks/mint_base_token.rs` vs `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

ZKsync OS contains two distinct mechanisms for increasing a base token balance. The bootloader's `mint_base_token` path is treasury-backed and notifies the `L2AssetTracker`. The system hook `mint_base_token_hook` at address `0x7100` directly inflates a balance with no treasury deduction and no asset tracker notification. These two paths have fundamentally different accounting semantics, creating a supply-inflation and cross-chain accounting corruption risk whenever the hook path is exercised.

---

### Finding Description

**Path 1 — Bootloader `mint_base_token` (conservation of supply):**

`process_l1_transaction.rs` calls `mint_base_token`, which:
1. Calls `notify_l2_asset_tracker` to record the deposit in `interopInfo[assetId].totalSuccessfulDepositsFromL1`.
2. Calls `transfer_from_treasury`, which **subtracts** `amount` from `BASE_TOKEN_HOLDER_ADDRESS` and **adds** it to the recipient.

Net effect: `treasury -= amount; recipient += amount`. Total circulating supply is conserved; the treasury acts as the backing reserve. [1](#0-0) [2](#0-1) 

**Path 2 — System hook `mint_base_token_hook` (true inflation):**

`mint_base_token_hook` at `0x7100`, when called by `L2_BASE_TOKEN_ADDRESS` (`0x800a`), calls `mint_nominal_token_value`, which calls `update_account_nominal_token_balance` with `subtract = false` (add to balance) **only on the beneficiary**. There is no corresponding treasury deduction and no call to `notify_l2_asset_tracker`.

Net effect: `recipient += amount`. Treasury is untouched. Total circulating supply increases without any L1-backed reserve. [3](#0-2) [4](#0-3) 

**The hook is registered unconditionally for every block**, not only during upgrades: [5](#0-4) 

The code itself acknowledges this is a temporary measure that should be removed:

```rust
// TODO(EVM-1191): temporary solution, should be removed before the release
system_hooks::add_base_token_mint(system_functions)?;
``` [5](#0-4) 

**The two paths diverge on three axes:**

| Property | Bootloader `mint_base_token` | Hook `mint_base_token_hook` |
|---|---|---|
| Treasury deducted | Yes | No |
| L2AssetTracker notified | Yes | No |
| Caller restriction | Bootloader only | `L2_BASE_TOKEN_ADDRESS` only |

---

### Impact Explanation

1. **Token supply inflation**: Every call through the hook path creates tokens that are not backed by any treasury reserve. The treasury balance does not decrease, so the sum of all user balances can exceed the treasury's initial allocation. This breaks the invariant that `sum(user_balances) + treasury_balance = constant`.

2. **L2AssetTracker accounting corruption**: `handleFinalizeBaseTokenBridgingOnL2` is never called for hook-path mints. The `totalSuccessfulDepositsFromL1` counter in the asset tracker will undercount actual circulating supply. Any cross-chain logic that relies on this counter (migration number checks, `_needToForceSetAssetMigrationOnL2`, interop accounting) will operate on stale/incorrect data.

3. **Forward/proving divergence risk**: The bootloader's `notify_l2_asset_tracker` call is explicitly designed to keep the asset tracker consistent even across reverts. The hook path skips this entirely, meaning the proving system and the forward system may disagree on the asset tracker's state after a block containing hook-path mints. [6](#0-5) 

---

### Likelihood Explanation

The hook is registered for every block and is callable by `L2_BASE_TOKEN_ADDRESS` (`0x800a`). The `L2_BASE_TOKEN_ADDRESS` is a deployed EVM system contract. Any publicly callable function on that contract that internally calls `0x7100` (the mint hook) constitutes an unprivileged entry path. The test suite confirms the hook executes successfully when called from `L2_BASE_TOKEN_ADDRESS`: [7](#0-6) 

The hook is documented as "used only for system-level mints" and "used during upgrades only," yet it is active in every block. During a migration or upgrade, the `L2_BASE_TOKEN_ADDRESS` contract will call the hook, triggering the unbacked inflation path. The TODO comment confirms the developers are aware this path should not persist.

---

### Recommendation

1. **Remove the hook before release** as the TODO comment already indicates (`EVM-1191`). All base token minting should go through the bootloader's `mint_base_token` path, which enforces treasury deduction and asset tracker notification.

2. If the hook must remain for migration purposes, it must be modified to also call `transfer_from_treasury` (deducting from `BASE_TOKEN_HOLDER_ADDRESS`) and `notify_l2_asset_tracker`, making its accounting semantics identical to the bootloader path.

3. Add an invariant check (or a prover constraint) that `sum(all_account_balances) + treasury_balance` is constant across any block that does not process L1 deposits.

---

### Proof of Concept

The divergence is directly observable by comparing the two code paths:

**Hook path** — balance increases with no treasury deduction: [8](#0-7) 

**Bootloader path** — treasury is decremented first: [9](#0-8) 

A concrete scenario:
1. Treasury is initialized with balance `T`.
2. `L2_BASE_TOKEN_ADDRESS` calls `0x7100` with calldata `abi.encode(X)` (32 bytes, amount `X`).
3. `mint_base_token_hook` executes: `L2_BASE_TOKEN_ADDRESS.balance += X`. Treasury unchanged.
4. `L2_BASE_TOKEN_ADDRESS` now holds `X` tokens backed by nothing.
5. `L2AssetTracker.totalSuccessfulDepositsFromL1` is not updated.
6. If `L2_BASE_TOKEN_ADDRESS` transfers these tokens to a user, the user holds `X` unbacked tokens.
7. The treasury still shows balance `T`, but `T + X` tokens now exist in circulation.

The addresses are defined at: [10](#0-9)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L757-768)
```rust
    notify_l2_asset_tracker::<S, Config>(
        system,
        system_functions,
        memories,
        *amount,
        l1_chain_id,
        resources,
        tracer,
        validator,
    )?;

    transfer_from_treasury::<S>(system, amount, to, resources, Config::SIMULATION)
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L793-831)
```rust
    let _ = system
        .io
        .update_account_nominal_token_balance(
            zk_ee::execution_environment_type::ExecutionEnvironmentType::EVM,
            resources,
            treasury_address,
            nominal_token_value,
            true, // true = subtract from balance
            fee_payment_in_simulation,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e {
                SubsystemError::LeafUsage(balance_error) => {
                    system_log!(system, "Treasury transfer failed: {balance_error:?}");
                    interface_error!(BootloaderInterfaceError::TreasuryTransferFailed)
                }
                _ => wrap_error!(e),
            }
        })?;

    let _ = system
        .io
        .update_account_nominal_token_balance(
            zk_ee::execution_environment_type::ExecutionEnvironmentType::EVM,
            resources,
            to,
            nominal_token_value,
            false, // false = add to balance
            fee_payment_in_simulation,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e {
                SubsystemError::LeafUsage(balance_error) => {
                    system_log!(system, "Error while minting: {balance_error:?}");
                    interface_error!(BootloaderInterfaceError::MintingBalanceOverflow)
                }
                _ => wrap_error!(e),
            }
        })?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L836-854)
```rust
/// Notify L2AssetTracker about base token bridging from L1.
///
/// Calls handleFinalizeBaseTokenBridgingOnL2(uint256 _fromChainId, uint256 _amount)
/// as L2_BASE_TOKEN_ADDRESS (0x800a) to pass the onlyBaseTokenHolderOrL2BaseToken modifier.
///
/// This is called separately for each token movement (value mint, operator
/// payment, refund) so that the asset tracker's accounting stays correct even
/// if the main transaction body reverts.
///
/// Resource usage depends on the caller — value-mint tracks native against user resources;
/// operator-fee and refund use FORMAL_INFINITE.
///
/// Failure halts block processing — if the asset tracker reverts, the
/// chain's token accounting would be inconsistent, so we treat it as
/// fatal rather than silently continuing with incorrect bookkeeping.
///
/// If no contract is deployed at L2AssetTracker, the call succeeds silently
/// (a call to an empty address returns success with no returndata in EVM).
/// However, we are certain that L2AssetTracker is available after the upgrade.
```

**File:** system_hooks/src/call_hooks/mint_base_token.rs (L139-143)
```rust
    let nominal_token_value = U256::from_be_slice(&calldata);

    mint_nominal_token_value(resources, system, &caller, &nominal_token_value)?;

    Ok(Ok(()))
```

**File:** system_hooks/src/call_hooks/mint_base_token.rs (L147-173)
```rust
fn mint_nominal_token_value<S: EthereumLikeTypes>(
    resources: &mut S::Resources,
    system: &mut System<S>,
    beneficiary: &B160,
    nominal_token_value: &U256,
) -> Result<(), SystemError>
where
    S::IO: IOSubsystemExt,
{
    // Charge EVM gas for the mint operation. This hook should be used during upgrades only, so we don't care about EVM compatibility
    match system.io.update_account_nominal_token_balance(
        ExecutionEnvironmentType::EVM,
        resources,
        beneficiary,
        &nominal_token_value,
        false, // false = add to balance, true = subtract from balance
        false, // only set to true for fee-related operations on simulation mode
    ) {
        Ok(_) => Ok(()),
        Err(SubsystemError::LeafUsage(_)) => Err(SystemError::LeafDefect(internal_error!(
            "Mint should be successful"
        ))),
        Err(SubsystemError::LeafRuntime(e)) => Err(e.into()),
        Err(SubsystemError::LeafDefect(e)) => Err(e.into()),
        Err(SubsystemError::Cascaded(e)) => match e {},
    }
}
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/post_init_op.rs (L22-24)
```rust
            // TODO(EVM-1191): temporary solution, should be removed before the release
            system_hooks::add_base_token_mint(system_functions)?;
        }
```

**File:** tests/instances/system_hooks/src/lib.rs (L1102-1153)
```rust
#[test]
fn test_mint_base_token_hook() {
    let mut tester = TestingFramework::new().with_minted_tokens_to_treasury();

    // L2 base token address is the only address allowed to call the mint hook
    let l2_base_token_address = address!("000000000000000000000000000000000000800a");
    // Mint hook address (0x7100)
    let mint_hook_address = address!("0000000000000000000000000000000000007100");
    let mint_amount = alloy::primitives::U256::from(3000000000000000000u64); // 3 ETH

    // Check initial balance of L2_BASE_TOKEN_ADDRESS is zero
    let initial_balance = tester
        .get_account_properties(&l2_base_token_address)
        .balance;

    // Prepare calldata: 32 bytes containing the mint amount as U256 big-endian
    let calldata = mint_amount.to_be_bytes::<32>().to_vec();

    // Create transaction from L2_BASE_TOKEN_ADDRESS to MINT_HOOK_ADDRESS
    let tx = L1TxBuilder::new()
        .from(l2_base_token_address)
        .to(mint_hook_address)
        .input(calldata)
        .value(alloy::primitives::U256::ZERO) // No ETH value needed for mint
        .gas_price(1000)
        .gas_limit(200_000)
        .build();

    let output = tester.execute_block(vec![tx]);

    // Assert transaction succeeded
    assert!(output.tx_results.iter().cloned().enumerate().all(|(i, r)| {
        let success = r.clone().is_ok_and(|o| o.is_success());
        if !success {
            println!("Transaction {} failed with: {:?}", i, r)
        }
        success
    }));

    // Check that the caller's (L2_BASE_TOKEN_ADDRESS) balance was increased by the mint amount
    let final_balance = tester
        .get_account_properties(&l2_base_token_address)
        .balance;

    let actually_minted_amount = final_balance
        .checked_sub(initial_balance)
        .expect("Some tokens should be minted");
    assert_eq!(
        actually_minted_amount, mint_amount,
        "Minted amount should match the requested mint amount"
    );
}
```

**File:** system_hooks/src/addresses_constants.rs (L24-52)
```rust
// L2 base token system contract
pub const L2_BASE_TOKEN_ADDRESS_LOW: u16 = 0x800a;
pub const L2_BASE_TOKEN_ADDRESS: B160 = B160::from_limbs([L2_BASE_TOKEN_ADDRESS_LOW as u64, 0, 0]);

// Base token mint system hook - allows L2 base token contract to mint tokens
// Only callable by L2_BASE_TOKEN_ADDRESS (0x800a) with 32-byte calldata containing mint amount
pub const MINT_HOOK_ADDRESS_LOW: u16 = 0x7100;
pub const MINT_HOOK_ADDRESS: B160 = B160::from_limbs([MINT_HOOK_ADDRESS_LOW as u64, 0, 0]);

// L2 message root storage contract
pub const MESSAGE_ROOT_ADDRESS: B160 = B160::from_limbs([0x10005, 0, 0]);

// L2 interop root storage system contract
pub const L2_INTEROP_ROOT_STORAGE_ADDRESS_LOW: u32 = 0x10008;
pub const L2_INTEROP_ROOT_STORAGE_ADDRESS: B160 =
    B160::from_limbs([L2_INTEROP_ROOT_STORAGE_ADDRESS_LOW as u64, 0, 0]);

// L2 interop center system contract
pub const L2_INTEROP_CENTER_ADDRESS_LOW: u32 = 0x1000d;
pub const L2_INTEROP_CENTER_ADDRESS: B160 =
    B160::from_limbs([L2_INTEROP_CENTER_ADDRESS_LOW as u64, 0, 0]);

// L2 asset tracker contract
pub const L2_ASSET_TRACKER_ADDRESS: B160 = B160::from_limbs([0x1000f, 0, 0]);

// Treasury contract used for "minting" base tokens on L2
pub const BASE_TOKEN_HOLDER_ADDRESS_LOW: u32 = 0x10011;
pub const BASE_TOKEN_HOLDER_ADDRESS: B160 =
    B160::from_limbs([BASE_TOKEN_HOLDER_ADDRESS_LOW as u64, 0, 0]);
```
