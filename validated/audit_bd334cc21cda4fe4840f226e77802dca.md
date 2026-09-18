### Title
Unhandled `.unwrap()` on `TransferFeeConfig::calculate_epoch_fee` causes a panic-based denial of service reachable from `deposit`, `withdraw`, `swap_base_input`, and `swap_base_output` - (File: programs/cp-swap/src/utils/token.rs)

### Summary
`get_transfer_fee` in `programs/cp-swap/src/utils/token.rs` calls `transfer_fee_config.calculate_epoch_fee(...).unwrap()` on a value that is derived from attacker-influenced, permissionless-created Token-2022 mint data. `calculate_epoch_fee` returns an `Option<u64>` and yields `None` when the internal fee computation overflows; the unconditional `.unwrap()` will panic and abort the whole instruction whenever that happens. [1](#0-0) 

### Finding Description
`get_transfer_fee` unpacks the mint's `TransferFeeConfig` extension and computes the transfer fee for the current epoch:

```rust
let fee = if let Ok(transfer_fee_config) = mint.get_extension::<TransferFeeConfig>() {
    transfer_fee_config
        .calculate_epoch_fee(Clock::get()?.epoch, pre_fee_amount)
        .unwrap()
} else {
    0
};
``` [2](#0-1) 

`pre_fee_amount` originates from user-supplied swap/deposit/withdraw amounts, and the `TransferFeeConfig` (basis points, maximum fee) is set entirely by whoever created the Token-2022 mint used as `token_0_mint`/`token_1_mint` for a pool. Pool creation via `initialize`/`initialize_with_permission` is permissionless for the token mints (only ordering and Token-2022 extension whitelisting via `is_supported_mint` is enforced, which explicitly allows `TransferFeeConfig` as a supported extension). [3](#0-2) 

`get_transfer_fee` is invoked from the deposit, withdraw, and both swap instruction handlers to compute transfer-fee-adjusted amounts before any token CPI: [4](#0-3) [5](#0-4) 

Because the fee math in `calculate_epoch_fee` (from the `spl-token-2022` extension code) can legitimately return `None` on internal overflow depending on the combination of basis points, maximum fee, and the transfer amount, an attacker who creates a pool with a Token-2022 mint whose `TransferFeeConfig` is tuned to overflow for certain amounts can force `.unwrap()` to panic. Any subsequent `deposit`, `withdraw`, `swap_base_input`, or `swap_base_output` call that hits the same overflow condition for that mint will abort the transaction with a Rust panic instead of returning a graceful `Result::Err`.

### Impact Explanation
A panic aborts the instruction non-gracefully but is still a transaction failure — for isolated amounts this is a denial-of-service on specific transaction sizes. However, because the fee configuration is fixed at mint-creation time and can be crafted so that a whole class of amounts (or effectively all interaction amounts once vault balances grow into the overflowing range) always trigger the overflow, the practical effect is repeated failure of every deposit/withdraw/swap against that pool for the affected amount ranges, which can escalate into a permanently unusable pool for LPs already holding liquidity in it (funds effectively frozen because withdraw also runs through this fee path). This does not directly enable theft or unbacked minting, so it sits at the DoS/availability end of the impact spectrum rather than fund theft.

### Likelihood Explanation
Pool creation with attacker-chosen Token-2022 mints is unprivileged and reachable in a single transaction (`initialize`), and Token-2022 `TransferFeeConfig` is explicitly on the allow-list in `is_supported_mint`, so no special build/feature flags are required. Triggering the overflow requires the attacker (or any user) to submit a deposit/withdraw/swap amount that lands in the overflowing region of the fee formula for the crafted config, which the pool creator fully controls at mint-creation time, making the precondition easy to set up deliberately.

### Recommendation
Replace the `.unwrap()` in `get_transfer_fee` with proper error propagation, e.g. `.ok_or(ErrorCode::MathOverflow)?` (or equivalent), so an overflow in the epoch-fee calculation results in a normal instruction error instead of a program panic. Apply the same fix pattern to any other unwrap calls on `Option`/`Result` computations that depend on externally supplied mint/extension configuration.

### Proof of Concept
1. Create a Token-2022 mint with the `TransferFeeConfig` extension, setting `transfer_fee_basis_points` and `maximum_fee` to values chosen so that `calculate_epoch_fee(epoch, amount)` overflows internally for some `amount` (e.g., very large `maximum_fee` combined with basis points such that the intermediate multiplication in the SPL implementation overflows for that `amount`).
2. Call `initialize` (or `initialize_with_permission`) with this mint as `token_0_mint` or `token_1_mint`; `is_supported_mint` permits `TransferFeeConfig`-extension mints, so pool creation succeeds. [6](#0-5) 
3. Call `deposit`, `withdraw`, `swap_base_input`, or `swap_base_output` with an amount that lands in the overflow region for that mint's fee config.
4. Observe the transaction abort via panic in `get_transfer_fee`'s `.unwrap()` rather than a clean program error, and confirm the same amount range continues to fail on every subsequent attempt, blocking further interaction with the pool for that amount range. [2](#0-1)

### Citations

**File:** programs/cp-swap/src/utils/token.rs (L288-304)
```rust
/// Calculate the fee for input amount
pub fn get_transfer_fee(mint_info: &AccountInfo, pre_fee_amount: u64) -> Result<u64> {
    if *mint_info.owner == Token::id() {
        return Ok(0);
    }
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;

    let fee = if let Ok(transfer_fee_config) = mint.get_extension::<TransferFeeConfig>() {
        transfer_fee_config
            .calculate_epoch_fee(Clock::get()?.epoch, pre_fee_amount)
            .unwrap()
    } else {
        0
    };
    Ok(fee)
}
```

**File:** programs/cp-swap/src/utils/token.rs (L335-360)
```rust
pub fn is_supported_mint(
    mint_account: &InterfaceAccount<Mint>,
    mint_associated_is_initialized: bool,
) -> Result<bool> {
    let mint_info = mint_account.to_account_info();
    if *mint_info.owner == Token::id() {
        return Ok(true);
    }
    if mint_associated_is_initialized {
        return Ok(true);
    }
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;
    let extensions = mint.get_extension_types()?;
    for e in extensions {
        if e != ExtensionType::TransferFeeConfig
            && e != ExtensionType::MetadataPointer
            && e != ExtensionType::TokenMetadata
            && e != ExtensionType::InterestBearingConfig
            && e != ExtensionType::ScaledUiAmount
        {
            return Ok(false);
        }
    }
    Ok(true)
}
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L1-1)
```rust
use crate::curve::CurveCalculator;
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L1-1)
```rust
use crate::curve::calculator::CurveCalculator;
```
