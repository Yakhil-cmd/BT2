### Title
Creator fee funds become permanently stuck if the pool creator's fee-receiving token account is frozen - (File: `programs/cp-swap/src/instructions/collect_creator_fee.rs`, `programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs`)

### Summary
Every swap accrues a `creator_fee` into `pool_state.creator_fees_token_0`/`creator_fees_token_1`, and the only two instructions that release that accrued fee (`collect_creator_fee` and `collect_creator_fee_permissionless`) hard-code the destination account to the associated token account (ATA) owned by `pool_state.pool_creator`. Neither instruction lets anyone specify an alternate destination, and there is no admin/creator instruction to change the `pool_creator` field or redirect accrued fees. If the creator's ATA for either mint becomes frozen (e.g. the mint's `freeze_authority` freezes it), the accrued creator fees become permanently unclaimable while still sitting (as vault balance) in the pool.

### Finding Description
`CollectCreatorFee` constrains the destination accounts to ATAs owned by the fixed `creator` signer: [1](#0-0) 

`CollectCreatorFeePermissionless` is callable by any unprivileged account, but it still forces the recipient to be the ATA of the fixed `pool_creator` recorded on-chain, with `payer` only covering the ATA rent: [2](#0-1) [3](#0-2) 

Both instructions transfer the entire accrued `creator_fees_token_0`/`creator_fees_token_1` in one call, and there is no code path to withdraw to any other account or to update `pool_creator`: [4](#0-3) 

Compare this with the admin-only fee collectors (`collect_protocol_fee`, `collect_fund_fee`), whose recipient token accounts are passed in as arbitrary accounts per call rather than being pinned to a stored address, so the protocol/fund owner can always redirect fees to a working account: [5](#0-4) 

The creator fee, by contrast, has no such flexibility — the only valid recipient is derived from `pool_creator`, which is set once at pool creation and never updated. `creator_fee` is computed and accumulated on every swap via `swap_base_input`/`swap_base_output`: [6](#0-5) 

Token transfers in the program are performed with `transfer_checked` from Token-2022, which enforces the standard freeze/blacklist semantics of the underlying token program; if the destination account (the creator's ATA) is frozen by the mint's freeze authority, the CPI will fail: [7](#0-6) 

### Impact Explanation
Once the creator's ATA for `vault_0_mint` or `vault_1_mint` is frozen, `creator_fees_token_0`/`creator_fees_token_1` continue to accumulate with every swap but can never be withdrawn, since both collection entrypoints unconditionally target that single, fixed account. The tokens remain locked in `token_0_vault`/`token_1_vault` indefinitely — a permanent freeze of protocol-tracked fee funds with no admin override to redirect or recover them, analogous to the referenced Allo `treasury` blacklist issue where a hard-coded fee recipient with no alternate address causes irrecoverable fund loss.

### Likelihood Explanation
This requires the token mint (a legacy SPL Token mint with a `freeze_authority`, which the `is_supported_mint` allow-list still permits since it isn't an extension check) to have its freeze authority freeze the specific creator's ATA — or the pool_creator itself using a mint it controls, deliberately having it frozen. Reaching the accrual state itself is trivial (any unprivileged swapper triggers `creator_fee` accrual on ordinary swaps), and the permissionless collector is callable by anyone, so the funds-stuck condition is fully reachable without any privileged action once the freeze condition is met.

### Recommendation
Add an admin or creator-only instruction to update `pool_state.pool_creator` (mirroring `update_amm_config`'s ability to change `fund_owner`), or allow `collect_creator_fee`/`collect_creator_fee_permissionless` to target an explicitly supplied, verified destination account rather than only the address derived from the immutable `pool_creator` field, so that accrued creator fees can still be recovered if the original recipient account becomes frozen.

### Proof of Concept
1. Pool creator creates a pool with a legacy SPL token mint that has a `freeze_authority` (permitted by `is_supported_mint`, since freeze authority itself is not one of the checked extensions).
2. Multiple swappers call `swap_base_input`/`swap_base_output` on the pool, causing `creator_fee` to accumulate in `pool_state.creator_fees_token_0`/`creator_fees_token_1`.
3. The mint's freeze authority freezes the pool creator's ATA for that mint (a standard, permitted SPL Token operation).
4. Any caller invokes `collect_creator_fee_permissionless`; the `transfer_checked` CPI to the frozen ATA fails, and there is no alternate instruction or account path to redirect the funds — the accrued creator fee amount is permanently stuck in the pool vault.

### Citations

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L58-76)
```rust
    /// The address that receives the collected token_0 fund fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_0_mint,
        associated_token::authority = creator,
        payer = creator,
        associated_token::token_program = token_0_program,
    )]
    pub creator_token_0: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The address that receives the collected token_1 fund fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_1_mint,
        associated_token::authority = creator,
        payer = creator,
        associated_token::token_program = token_1_program,
    )]
    pub creator_token_1: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L10-20)
```rust
#[derive(Accounts)]
pub struct CollectCreatorFeePermissionless<'info> {
    /// Anyone can trigger the collection since the fee is always sent to the pool creator,
    /// the payer only funds the creation of the creator's token accounts if they don't exist yet.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L61-79)
```rust
    /// The address that receives the collected token_0 creator fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_0_mint,
        associated_token::authority = creator,
        payer = payer,
        associated_token::token_program = token_0_program,
    )]
    pub creator_token_0: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The address that receives the collected token_1 creator fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_1_mint,
        associated_token::authority = creator,
        payer = payer,
        associated_token::token_program = token_1_program,
    )]
    pub creator_token_1: Box<InterfaceAccount<'info, TokenAccount>>,
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

**File:** programs/cp-swap/src/instructions/admin/collect_protocol_fee.rs (L59-65)
```rust
    /// The address that receives the collected token_0 protocol fees
    #[account(mut)]
    pub recipient_token_0_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The address that receives the collected token_1 protocol fees
    #[account(mut)]
    pub recipient_token_1_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/cp-swap/src/curve/calculator.rs (L95-143)
```rust
    pub fn swap_base_input(
        input_amount: u128,
        input_vault_amount: u128,
        output_vault_amount: u128,
        trade_fee_rate: u64,
        creator_fee_rate: u64,
        protocol_fee_rate: u64,
        fund_fee_rate: u64,
        is_creator_fee_on_input: bool,
    ) -> Option<SwapResult> {
        let mut creator_fee = 0;
        let trade_fee: u128;

        let input_amount_less_fees = if is_creator_fee_on_input {
            let total_fee = Fees::trading_fee(input_amount, trade_fee_rate + creator_fee_rate)?;
            creator_fee = Fees::split_creator_fee(total_fee, trade_fee_rate, creator_fee_rate)?;
            trade_fee = total_fee - creator_fee;
            input_amount.checked_sub(total_fee)?
        } else {
            trade_fee = Fees::trading_fee(input_amount, trade_fee_rate)?;
            input_amount.checked_sub(trade_fee)?
        };
        let protocol_fee = Fees::protocol_fee(trade_fee, protocol_fee_rate)?;
        let fund_fee = Fees::fund_fee(trade_fee, fund_fee_rate)?;

        let output_amount_swapped = ConstantProductCurve::swap_base_input_without_fees(
            input_amount_less_fees,
            input_vault_amount,
            output_vault_amount,
        );

        let output_amount = if is_creator_fee_on_input {
            output_amount_swapped
        } else {
            creator_fee = Fees::creator_fee(output_amount_swapped, creator_fee_rate)?;
            output_amount_swapped.checked_sub(creator_fee)?
        };

        Some(SwapResult {
            new_input_vault_amount: input_vault_amount.checked_add(input_amount_less_fees)?,
            new_output_vault_amount: output_vault_amount.checked_sub(output_amount_swapped)?,
            input_amount,
            output_amount,
            trade_fee,
            protocol_fee,
            fund_fee,
            creator_fee,
        })
    }
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
