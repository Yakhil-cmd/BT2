### Title
Swap accounts omit an owner/authority check on `input_token_account`, letting a swapper drain any token account they hold delegate approval over - ([File: programs/cp-swap/src/instructions/swap_base_input.rs])

### Summary
The `Swap` account struct used by both `swap_base_input` and `swap_base_output` declares `input_token_account` and `output_token_account` with no `token::authority = payer` (or equivalent owner) constraint. The instruction signs the `transfer_checked` CPI with `payer` as the authority, but never verifies `payer` is the actual owner of `input_token_account`. This is the same bug class as the SwapNet incident: insufficient validation of a user-controlled account parameter lets the signer reuse a pre-existing SPL-Token delegate approval to move funds out of a token account that isn't theirs.

### Finding Description
`Swap` accounts are declared as: [1](#0-0) 
Neither `input_token_account` nor `output_token_account` carries a `token::authority = payer` constraint, unlike `deposit.rs`/`withdraw.rs` which explicitly enforce `token::authority = owner` on the corresponding accounts: [2](#0-1) 

The swap instruction then performs the debit using `payer` as the CPI authority: [3](#0-2) 
which calls into `transfer_from_user_to_pool_vault`, a thin wrapper around `token_2022::transfer_checked` with `authority = payer`: [4](#0-3) 

Because Anchor only validates that `input_token_account` deserializes as a valid `TokenAccount` (via `InterfaceAccount`) and never checks its `owner` field against `payer`, the only enforcement of "who can move these funds" is delegated to the SPL Token/Token-2022 program's own `transfer_checked` logic, which succeeds if `authority` is either the account owner **or** an approved delegate with sufficient `delegated_amount`. Any address that a victim has approved as a delegate for `input_token_account` (for any historical reason — a different dApp, an aggregator, a bot, etc.) can therefore submit a swap naming the victim's account as `input_token_account`, sign as `payer`, and route the resulting `output_token_account` to an account the attacker controls. `swap_base_output.rs` has the identical pattern: [5](#0-4) 

This mirrors the SwapNet root cause described in the report — insufficient input validation on a user-controlled account parameter allowing abuse of existing token approvals to execute unauthorized transfers.

### Impact Explanation
Any token account with an outstanding delegate approval to a Solana address controlled by an attacker can be drained up to the delegated amount through the Raydium CP-Swap program, with the swap proceeds redirected to the attacker's own `output_token_account`. This is a direct theft-of-user-funds path reachable from a single, unprivileged, attacker-submitted transaction (`swap_base_input`/`swap_base_output`), satisfying the "concrete theft of user funds" bar.

### Likelihood Explanation
Exploitability depends entirely on the existence of a live delegate approval on a victim's token account pointed at an address the attacker controls or can act as — a common real-world condition (many wallets/dApps set token delegations for order books, one-time approvals, bots, etc., exactly as called out in the SwapNet report). No privileged role, validator collusion, or non-default build is required; the attacker only needs to be `payer` (any signer) and to name the victim's delegated account as `input_token_account`.

### Recommendation
Add an explicit ownership constraint on `input_token_account` (and `output_token_account`) in the `Swap` accounts struct, e.g. `token::authority = payer`, mirroring the constraints already used in `deposit.rs`/`withdraw.rs`, so that only the token account's actual owner (the signing `payer`) can be used as the swap's input/output account, removing reliance on the SPL Token program's owner-or-delegate fallback.

### Proof of Concept
1. Victim `V` at some point approves delegate authority over `N` tokens on their SPL token account `V_ata` to address `A` (e.g., for an unrelated dApp/aggregator interaction), and never revokes it.
2. Attacker controls (or is) `A`. Attacker builds a `swap_base_input` transaction with:
   - `payer = A` (signer)
   - `input_token_account = V_ata`
   - `output_token_account = A`'s own token account for the output mint
   - other accounts (`input_vault`, `output_vault`, mints, pool_state, etc.) set normally for a valid pool.
3. Program executes `transfer_from_user_to_pool_vault` with `authority = A`; SPL Token's `transfer_checked` succeeds because `A` is an approved delegate on `V_ata` with sufficient `delegated_amount`, even though `A` is not the owner.
4. The corresponding swap output is transferred to `A`'s `output_token_account`. `V`'s funds are drained without `V`'s participation in the transaction, up to the previously delegated amount.

### Citations

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L31-37)
```rust
    /// The user token account for input token
    #[account(mut)]
    pub input_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The user token account for output token
    #[account(mut)]
    pub output_token_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L182-190)
```rust
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

**File:** programs/cp-swap/src/instructions/swap_base_output.rs (L124-132)
```rust
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
