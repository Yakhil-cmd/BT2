Confirmed: `transfer_from_user_to_pool_vault` in `programs/cp-swap/src/utils/token.rs` performs `token_2022::transfer_checked` using the `payer` account as the transfer `authority` [1](#0-0) , and the `Swap` accounts struct only requires `input_token_account` and `output_token_account` to be `mut`, with **no `token::authority` constraint tying them to `payer`** [2](#0-1) . This contrasts with `Deposit`, whose `token_0_account`/`token_1_account` explicitly enforce `token::authority = owner` [3](#0-2) .

### Title
Missing `token::authority` constraint on `input_token_account` in `swap_base_input`/`swap_base_output` allows draining accounts with residual delegate approval - (File: `programs/cp-swap/src/instructions/swap_base_input.rs`)

### Summary
The `Swap` account struct used by both `swap_base_input` and `swap_base_output` does not verify that `input_token_account` is owned/authorized by `payer` (the signer). The SPL `TransferChecked` CPI executed in `transfer_from_user_to_pool_vault` uses `payer` as the transfer authority, which the token program accepts as valid if `payer` is either the owner of `input_token_account` **or an approved delegate** of it.

### Finding Description
`transfer_from_user_to_pool_vault` calls `token_2022::transfer_checked` with `authority = payer` [4](#0-3) . The `Swap` struct declares `payer: Signer<'info>` and `input_token_account: Box<InterfaceAccount<'info, TokenAccount>>` with only a `mut` constraint — it never checks `input_token_account.owner == payer.key()` nor `token::authority = payer` [5](#0-4) .

The SPL Token(-2022) program's `TransferChecked` instruction succeeds as long as the supplied authority is either the account owner or a delegate with sufficient approved amount, regardless of whether that authority actually is the intended owner. Because the program does not restrict `input_token_account` to belong to (or be delegated to) `payer`, any user who has ever granted an `Approve` delegation of any token account to `payer`'s address (e.g., residual approval left over from interacting with another instance of this program, a router, or aggregator that reused the same pubkey as delegate) can have their tokens swapped by an unrelated caller supplying that victim's token account as `input_token_account`, without the victim's consent for this specific swap. The attacker additionally fully controls `output_token_account`, so the swap's proceeds can be redirected to an account of the attacker's choosing rather than the victim's — this is strictly worse than the referenced `rebalanceLite()` finding, where the swapped proceeds are at least guaranteed to go back to the impacted account.

This is the same bug class as the reported `PerpDepository.rebalanceLite()` issue: an "account/authority" parameter used in a token operation is not checked against `msg.sender`/`payer`, so anyone can trigger an action on a victim's tokens via pre-existing delegate approvals.

### Impact Explanation
An attacker with a stale/residual token delegation from a victim can force-swap the victim's tokens through the pool at any exchange rate acceptable to the pool's slippage checks, and redirect the swap output to an attacker-controlled account. This is concrete theft of user funds, matching the "Medium" bar for unauthorized use of user funds via missing signer/authority validation.

### Likelihood Explanation
Exploitability depends on the victim having previously approved a delegate whose address later becomes attacker-controlled or is reused as `payer` — this is a realistic scenario for users interacting with routers/aggregators that set delegate approvals, or for accounts where users approve a "hot wallet" for automation. Likelihood is not universal (requires an existing approval) but is a real, non-trivial precondition matching the same class accepted in the original report.

### Recommendation
Add an explicit constraint to `Swap<'info>` binding `input_token_account` (and ideally `output_token_account`, for correctness of destination) to `payer`, e.g. `#[account(mut, token::authority = payer)]` on `input_token_account`, mirroring the pattern already used in `Deposit`/`Withdraw` (`token::authority = owner`) [3](#0-2) .

### Proof of Concept
1. Victim `V` at some point calls SPL `Approve` on token account `V_input_account`, delegating `amount` to pubkey `A`.
2. `A` calls `swap_base_input` with `payer = A` (signs), `input_token_account = V_input_account`, `output_token_account = A_output_account` (owned by `A`), and pool/vault accounts for the desired pair.
3. The instruction has no constraint checking `V_input_account`'s owner/authority against `payer`, so the account is accepted as `input_token_account` [6](#0-5) .
4. `transfer_from_user_to_pool_vault` executes `TransferChecked` with `authority = A` [7](#0-6) ; the SPL token program permits this because `A` is an approved delegate on `V_input_account`, transferring `V`'s tokens into the pool vault.
5. The pool executes the swap and sends the output tokens to `A_output_account`, fully controlled by the attacker — completing an unauthorized, attacker-profitable swap of the victim's funds.

### Citations

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

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L180-190)
```rust
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

**File:** programs/cp-swap/src/instructions/deposit.rs (L31-45)
```rust
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
