I have enough evidence to give a definitive answer.

### Title
Missing owner binding on swap token accounts lets any SPL-approved delegate drain a user's tokens with attacker-chosen slippage - (File: programs/cp-swap/src/instructions/swap_base_input.rs)

### Summary
The `Swap` accounts struct shared by `swap_base_input` and `swap_base_output` never verifies that `input_token_account`/`output_token_account` are owned (or controlled) by the transaction's `payer`. The token transfer is authorized purely by SPL Token's own delegate mechanism, so any address holding an SPL `Approve` delegation over a victim's token account can call `swap_base_input`/`swap_base_output`, name the victim's account as `input_token_account`, redirect `output_token_account` to itself, and pick worst-case `minimum_amount_out = 0` / `max_amount_in = u64::MAX`, draining the victim's approved balance through an unfavorable swap — mirroring the `PerpDepository.rebalance()` issue where a caller-controlled `account` combined with caller-controlled slippage parameters lets a griefer drain a pre-approving user.

### Finding Description
`Deposit` and `Withdraw` explicitly bind their token accounts to the signer with `token::authority = owner` constraints: [1](#0-0) 

The `Swap` context used by both `swap_base_input` and `swap_base_output`, however, has no such constraint on `input_token_account` or `output_token_account` — only `payer: Signer<'info>` is required, with the token accounts constrained solely by `mut`: [2](#0-1) 

The actual token movement authorizes the transfer using `payer` as the SPL "authority" account: [3](#0-2) 

The SPL Token program itself allows `authority` to be either the account owner or an approved delegate. Since Anchor does not additionally check `input_token_account.owner == payer.key()`, any wallet that a user has approved as a delegate (via a standard SPL `Approve` instruction — a routine action for aggregators, bots, or automation) can call `swap_base_input`/`swap_base_output` naming the victim's token account as `input_token_account`, its own account as `output_token_account`, and freely choose `minimum_amount_out` (down to 0) in `swap_base_input.rs` or `max_amount_in` (up to `u64::MAX`) in `swap_base_output.rs`: [4](#0-3) 

This is the same root cause as the referenced report: the instruction is reachable by "anyone" (any approved delegate) with caller-controlled slippage parameters and a caller-controlled destination for the swap's proceeds, letting the caller execute the swap at maximally adverse terms and capture the output for themselves.

### Impact Explanation
An attacker holding delegate approval on a victim's token account can force a swap of the victim's entire approved balance through the pool at up to 100% slippage (limited only by the AMM curve for the given amount), sending the resulting output tokens to the attacker's own account. This is a direct theft of user funds, satisfying High severity.

### Likelihood Explanation
Delegate approvals over SPL token accounts are common (used by wallets, bots, DEX aggregators, and automation services), so the precondition — a user having approved some third-party spender — is realistic and not rare. Anyone who is (or becomes) an approved delegate for a victim can execute this without any special privilege in the program itself, and the transaction is a single, straightforward instruction call.

### Recommendation
Add an explicit constraint tying `input_token_account` (and ideally `output_token_account`) to the `payer` in the `Swap` accounts struct, e.g. `token::authority = payer`, consistent with `token::authority = owner` used in `Deposit`/`Withdraw`. This prevents using someone else's token account as the swap input regardless of SPL-level delegate approvals, closing off the griefing/drain vector described above.

### Proof of Concept
1. Victim approves `Attacker` as SPL delegate for `victim_input_token_account` with some allowance (e.g., for a bot/aggregator use case).
2. `Attacker` builds a `swap_base_input` transaction with:
   - `payer` = Attacker (signer)
   - `input_token_account` = `victim_input_token_account`
   - `output_token_account` = Attacker's own ATA
   - `amount_in` = full delegated allowance
   - `minimum_amount_out` = 0
3. `transfer_from_user_to_pool_vault` in [3](#0-2)  succeeds because SPL Token accepts `Attacker` as a valid delegate authority for `victim_input_token_account`, with no Anchor-level check that `payer` owns that account, as seen in the `Swap` struct definition [5](#0-4) .
4. The swap executes at whatever price the pool offers (no floor enforced since `minimum_amount_out = 0`), and the output tokens are credited to Attacker's `output_token_account`, draining the victim's approved balance.

### Citations

**File:** programs/cp-swap/src/instructions/deposit.rs (L27-45)
```rust
    /// Owner lp token account
    #[account(mut,  token::authority = owner)]
    pub owner_lp_token: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The payer's token account for token_0
    #[account(
        mut,
        token::mint = token_0_vault.mint,
        token::authority = owner
    )]
    pub token_0_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The payer's token account for token_1
    #[account(
        mut,
        token::mint = token_1_vault.mint,
        token::authority = owner
    )]
    pub token_1_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L9-37)
```rust
#[derive(Accounts)]
pub struct Swap<'info> {
    /// The user performing the swap
    pub payer: Signer<'info>,

    /// CHECK: pool vault and lp mint authority
    #[account(
        seeds = [
            crate::AUTH_SEED.as_bytes(),
        ],
        bump,
    )]
    pub authority: UncheckedAccount<'info>,

    /// The factory state to read protocol fees
    #[account(address = pool_state.load()?.amm_config)]
    pub amm_config: Box<Account<'info, AmmConfig>>,

    /// The program account of the pool in which the swap will be performed
    #[account(mut)]
    pub pool_state: AccountLoader<'info, PoolState>,

    /// The user token account for input token
    #[account(mut)]
    pub input_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The user token account for output token
    #[account(mut)]
    pub output_token_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/cp-swap/src/utils/token.rs (L17-42)
```rust
pub fn transfer_from_user_to_pool_vault<'a>(
    authority: AccountInfo<'a>,
    from: AccountInfo<'a>,
    to_vault: AccountInfo<'a>,
    mint: AccountInfo<'a>,
    token_program: AccountInfo<'a>,
    amount: u64,
    mint_decimals: u8,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    token_2022::transfer_checked(
        CpiContext::new(
            *token_program.key,
            token_2022::TransferChecked {
                from,
                to: to_vault,
                authority,
                mint,
            },
        ),
        amount,
        mint_decimals,
    )
}
```

**File:** programs/cp-swap/src/instructions/swap_base_output.rs (L80-132)
```rust
        require_gt!(input_amount, 0);
        let transfer_fee = get_transfer_inverse_fee(
            &ctx.accounts.input_token_mint.to_account_info(),
            input_amount,
        )?;
        let input_transfer_amount = input_amount.checked_add(transfer_fee).unwrap();
        require_gte!(
            max_amount_in,
            input_transfer_amount,
            ErrorCode::ExceededSlippage
        );
        (input_transfer_amount, transfer_fee)
    };
    require_eq!(
        u64::try_from(result.output_amount).unwrap(),
        amount_out_with_transfer_fee
    );
    let (output_transfer_amount, output_transfer_fee) =
        (amount_out_with_transfer_fee, out_transfer_fee);

    pool_state.update_fees(
        u64::try_from(result.protocol_fee).unwrap(),
        u64::try_from(result.fund_fee).unwrap(),
        u64::try_from(result.creator_fee).unwrap(),
        trade_direction,
    )?;

    emit!(SwapEvent {
        pool_id,
        input_vault_before: total_input_token_amount,
        output_vault_before: total_output_token_amount,
        input_amount: u64::try_from(result.input_amount).unwrap(),
        output_amount: u64::try_from(result.output_amount).unwrap(),
        input_transfer_fee,
        output_transfer_fee,
        base_input: false,
        input_mint: ctx.accounts.input_token_mint.key(),
        output_mint: ctx.accounts.output_token_mint.key(),
        trade_fee: u64::try_from(result.trade_fee).unwrap(),
        creator_fee: u64::try_from(result.creator_fee).unwrap(),
        creator_fee_on_input: is_creator_fee_on_input,
    });
    require_gte!(constant_after, constant_before);

    transfer_from_user_to_pool_vault(
        ctx.accounts.payer.to_account_info(),
        ctx.accounts.input_token_account.to_account_info(),
        ctx.accounts.input_vault.to_account_info(),
        ctx.accounts.input_token_mint.to_account_info(),
        ctx.accounts.input_token_program.to_account_info(),
        input_transfer_amount,
        ctx.accounts.input_token_mint.decimals,
    )?;
```
