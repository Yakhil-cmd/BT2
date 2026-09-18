## Analog Found

### Title
Creator fee collection under-delivers `creator_fees_token_{0,1}` when the vault mint is a Token-2022 fee-on-transfer token - ([File: programs/cp-swap/src/instructions/collect_creator_fee.rs] / [File: programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs])

### Summary
`collect_creator_fee` and `collect_creator_fee_permissionless` transfer the full, un-adjusted `pool_state.creator_fees_token_0`/`creator_fees_token_1` amounts to the creator via `transfer_from_pool_vault_to_user`, without accounting for the Token-2022 transfer-fee extension. If the vault mint charges a transfer fee, the creator actually receives `amount - transfer_fee`, while the pool zeroes out the full recorded fee balance, matching the "fee on transfer token causes recipient to receive less than entitled" bug class from the referenced report.

### Finding Description
Every other value-moving instruction in this program (`deposit`, `withdraw`, `swap_base_input`, `swap_base_output`) explicitly calls `get_transfer_fee`/`get_transfer_inverse_fee` before transferring, computing a "receive amount" net of the mint's Token-2022 transfer fee, and uses that net amount for slippage checks and accounting: [1](#0-0) 

However, `collect_creator_fee` reads the accrued nominal fee and transfers it directly with no fee adjustment: [2](#0-1) 

The same pattern exists in the permissionless variant: [3](#0-2) 

Both call `transfer_from_pool_vault_to_user`, which is a thin wrapper around `token_2022::transfer_checked` with no balance-before/after adjustment or fee accounting: [4](#0-3) 

Since `transfer_checked` on a Token-2022 mint with `TransferFeeConfig` will withhold a fee from the transferred amount (the sender's vault balance decreases by `amount`, but the recipient's account only increases by `amount - transfer_fee`), the creator ends up receiving strictly less than the `creator_fees_token_0`/`creator_fees_token_1` value that was tracked and then reset to zero.

### Impact Explanation
The pool creator permanently loses a portion of their accrued creator fees whenever the pool's token mint is a Token-2022 fee-on-transfer token — exactly the reward-shortfall class described in the source report, but applied to the creator-fee-collection path instead of a lending-rewards path. This is a real, reachable loss of funds for the pool creator (a legitimate, unprivileged party interacting through `collect_creator_fee`/`collect_creator_fee_permissionless`), and the discrepancy is silently absorbed because `pool_state.creator_fees_token_0/1` is zeroed regardless of the fee actually withheld.

### Likelihood Explanation
This requires a pool whose `token_0_mint`/`token_1_mint` is a Token-2022 mint with the `TransferFeeConfig` extension enabled and `enable_creator_fee` set — a configuration explicitly supported elsewhere in the codebase (`get_transfer_fee`/`get_transfer_inverse_fee`, `is_supported_mint` allowing `ExtensionType::TransferFeeConfig`). Any swap that accrues creator fees on such a pool, followed by a call to `collect_creator_fee` or the permissionless variant, triggers the shortfall — no special conditions or privileged access needed.

### Recommendation
In `collect_creator_fee` and `collect_creator_fee_permissionless`, mirror the pattern used in `withdraw.rs`/`deposit.rs`/swap instructions: call `get_transfer_fee` (or measure vault/recipient balance before and after) to compute the actual amount that will land in the creator's account, and either (a) gross up the transfer so the creator receives the full recorded fee, or (b) only zero out the portion of `creator_fees_token_0/1` that was actually delivered net of the transfer fee, keeping the remainder accounted for future collection.

### Proof of Concept
1. Create a pool where `token_0_mint` (or `token_1_mint`) is a Token-2022 mint with `TransferFeeConfig` (e.g., 5% fee) and `enable_creator_fee = true` on the pool/config.
2. Perform swaps so that `pool_state.creator_fees_token_0` accrues a nonzero value (accrual logic in `update_fees`, e.g. from `swap_base_input.rs`).
3. Call `collect_creator_fee` (or `collect_creator_fee_permissionless`).
4. Observe: `transfer_from_pool_vault_to_user` is invoked with the full `creator_fees_token_0` amount; the creator's ATA balance increases by only `creator_fees_token_0 - transfer_fee`, while `pool_state.creator_fees_token_0` is reset to `0`, permanently losing the withheld fee for the creator with no path to reclaim it. [5](#0-4)

### Citations

**File:** programs/cp-swap/src/instructions/withdraw.rs (L129-147)
```rust
    let (receive_token_0_amount, token_0_transfer_fee) = {
        let transfer_fee =
            get_transfer_fee(&ctx.accounts.vault_0_mint.to_account_info(), token_0_amount)?;
        (
            token_0_amount.checked_sub(transfer_fee).unwrap(),
            transfer_fee,
        )
    };

    let token_1_amount = u64::try_from(results.token_1_amount).unwrap();
    let token_1_amount = std::cmp::min(total_token_1_amount, token_1_amount);
    let (receive_token_1_amount, token_1_transfer_fee) = {
        let transfer_fee =
            get_transfer_fee(&ctx.accounts.vault_1_mint.to_account_info(), token_1_amount)?;
        (
            token_1_amount.checked_sub(transfer_fee).unwrap(),
            transfer_fee,
        )
    };
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-122)
```rust
pub fn collect_creator_fee(ctx: Context<CollectCreatorFee>) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }

    let signer_seeds: &[&[u8]] = &[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]];

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        creator_fees_token_0,
        ctx.accounts.vault_0_mint.decimals,
        &[signer_seeds],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        creator_fees_token_1,
        ctx.accounts.vault_1_mint.decimals,
        &[signer_seeds],
    )?;

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-127)
```rust
pub fn collect_creator_fee_permissionless(
    ctx: Context<CollectCreatorFeePermissionless>,
) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }

    let signer_seeds: &[&[u8]] = &[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]];

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        creator_fees_token_0,
        ctx.accounts.vault_0_mint.decimals,
        &[signer_seeds],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        creator_fees_token_1,
        ctx.accounts.vault_1_mint.decimals,
        &[signer_seeds],
    )?;

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```

**File:** programs/cp-swap/src/utils/token.rs (L44-71)
```rust
pub fn transfer_from_pool_vault_to_user<'a>(
    authority: AccountInfo<'a>,
    from_vault: AccountInfo<'a>,
    to: AccountInfo<'a>,
    mint: AccountInfo<'a>,
    token_program: AccountInfo<'a>,
    amount: u64,
    mint_decimals: u8,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    token_2022::transfer_checked(
        CpiContext::new_with_signer(
            *token_program.key,
            token_2022::TransferChecked {
                from: from_vault,
                to,
                authority,
                mint,
            },
            signer_seeds,
        ),
        amount,
        mint_decimals,
    )
}
```
