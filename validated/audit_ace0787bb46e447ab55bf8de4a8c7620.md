### Title
Missing `token::authority` constraint on `input_token_account` in `Swap` lets an approved SPL-token delegate drain another user's tokens via `swap_base_input`/`swap_base_output` - (File: `programs/cp-swap/src/instructions/swap_base_input.rs`)

### Summary
The `Swap` account context used by both `swap_base_input` and `swap_base_output` does not verify that `input_token_account` (the account debited to fund the swap) is owned by `payer`. Unlike `deposit.rs` and `withdraw.rs`, which explicitly pin the user token accounts to the signer with `token::authority = owner`, the swap instructions accept `input_token_account` with only `#[account(mut)]`.

### Finding Description
`Deposit` and `Withdraw` explicitly constrain the debited/authorized token accounts to the transaction signer: [1](#0-0) [2](#0-1) 

In contrast, the `Swap` accounts struct shared by `swap_base_input` and `swap_base_output` declares `input_token_account` and `output_token_account` with no `token::authority` constraint at all: [3](#0-2) 

The instruction transfers tokens out of `input_token_account` using `payer` as the CPI authority via `transfer_from_user_to_pool_vault`, which is implemented as a plain `token_2022::transfer_checked` CPI: [4](#0-3) 

Because Anchor performs no ownership check on `input_token_account`, the only enforcement of "who may move these tokens" is delegated entirely to the SPL Token / Token-2022 program's own rule that the `authority` signer must be either the account's owner or an *approved delegate* with sufficient `delegated_amount`. This is structurally identical to the reported Solidity bug: the program lets an attacker supply an arbitrary victim-owned account (here, `input_token_account`) as long as the attacker happens to be an approved spender/delegate for it (from any unrelated prior approval), and the program will happily execute the transfer without checking that the account actually belongs to (or was intended by) `payer`.

If a victim ever approved a delegate allowance on their SPL token account to some pubkey — for any reason, in any other context — the holder of that delegate pubkey can sign as `payer` in `swap_base_input`/`swap_base_output`, submit the victim's token account as `input_token_account`, and drain the approved amount into the attacker's own `output_token_account`, with the pool mechanically executing a "swap" that is really an unauthorized transfer.

### Impact Explanation
This allows theft of tokens covered by a leftover/any-purpose SPL delegate approval, without the victim's transaction ever intending to interact with this pool. Funds land in an attacker-controlled `output_token_account`, resulting in concrete loss of user funds — matching the High severity of the original report, which stemmed from the same "attacker chooses account, program relies on stale/foreign approval instead of an ownership check" root cause.

### Likelihood Explanation
Exploitability requires only that some address created a nonzero SPL Token/Token-2022 delegate approval to a pubkey the attacker controls (a common pattern with many wallets/dApps/aggregators that request approvals). The attacker needs no privileged role; they submit a single transaction with attacker-chosen accounts (`input_token_account` = victim's account, `output_token_account` = attacker's account) and standard `swap_base_input`/`swap_base_output` instruction data. This is directly reachable by any unprivileged swapper.

### Recommendation
Add `token::authority = payer` (or an explicit `constraint = input_token_account.owner == payer.key()`) to `input_token_account` in the `Swap` accounts struct in `programs/cp-swap/src/instructions/swap_base_input.rs`, mirroring the pattern already used in `deposit.rs` and `withdraw.rs`, so that only the actual owner of the funding token account can initiate a swap from it.

### Proof of Concept
1. Victim `V` at some point approves delegate pubkey `A` for `N` tokens on their SPL token account `V_ata` (e.g., via an unrelated DEX/aggregator approval flow).
2. Attacker, controlling keypair `A`, calls `swap_base_input` with:
   - `payer` = `A` (signer)
   - `input_token_account` = `V_ata` (owned by `V`, not `A`)
   - `output_token_account` = attacker's own token account
   - other accounts (`input_vault`, `output_vault`, mints, `pool_state`, etc.) set to a real pool.
3. Anchor's account validation passes because `input_token_account` has no `token::authority` constraint (only implicit type checks in `programs/cp-swap/src/instructions/swap_base_input.rs` lines 31-37).
4. `transfer_from_user_to_pool_vault` issues `transfer_checked` with `authority = A`; the SPL token program allows it because `A` is an approved delegate on `V_ata` with `delegated_amount >= amount_in`, per `programs/cp-swap/src/utils/token.rs` lines 17-42.
5. The swap executes, debiting `V_ata` and crediting the attacker's `output_token_account`, without `V`'s consent for this specific swap.

### Citations

**File:** programs/cp-swap/src/instructions/deposit.rs (L31-37)
```rust
    /// The payer's token account for token_0
    #[account(
        mut,
        token::mint = token_0_vault.mint,
        token::authority = owner
    )]
    pub token_0_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L31-37)
```rust
    /// Owner lp token account
    #[account(
        mut, 
        token::authority = owner
    )]
    pub owner_lp_token: Box<InterfaceAccount<'info, TokenAccount>>,

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
