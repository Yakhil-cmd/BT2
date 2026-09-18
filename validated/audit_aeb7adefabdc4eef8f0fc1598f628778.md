### Title
Creator fees become permanently frozen if the pool creator's token account is frozen/blacklisted, since `collect_creator_fee`/`collect_creator_fee_permissionless` allow no alternate recipient - (File: `programs/cp-swap/src/instructions/collect_creator_fee.rs`, `programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs`)

### Summary
Both `collect_creator_fee` and its permissionless variant hard-code the destination of accumulated creator fees to the pool creator's own associated token account, and only zero out `pool_state.creator_fees_token_0/1` after the transfer succeeds. If the vault mint is a token with issuer-controlled freeze/blacklist capability (e.g. USDC/USDT-style tokens, or a Token-2022 mint whose freeze authority freezes the creator's account) and the creator's token account becomes frozen or blacklisted, both instructions permanently revert, and the accrued creator fees can never be withdrawn from the pool by anyone.

### Finding Description
`collect_creator_fee` requires the `creator` signer's own ATA as the fee destination: [1](#0-0) 

and unconditionally transfers the full accumulated fee to it before resetting the accounting: [2](#0-1) 

The permissionless variant is reachable by any signer, but is still constrained to send funds only to the `creator`'s ATA: [3](#0-2) [4](#0-3) 

Both paths call `transfer_from_pool_vault_to_user`, which performs a `transfer_checked` CPI to the token/Token-2022 program: [5](#0-4) 

If the destination `creator_token_0`/`creator_token_1` account is frozen (mint freeze authority action, or blacklist enforced by the token issuer such as USDC/USDT), the `transfer_checked` CPI fails and the whole instruction reverts. Since there is no way to designate any other recipient and `pool_state.creator_fees_token_0/1` is only zeroed after a successful transfer, the accrued fee balance is permanently unreachable — mirroring the referenced Teller finding where a hard dependency on transferring to a specific (blacklistable) address makes an otherwise-legitimate, unprivileged operation permanently revert, freezing funds tied to that operation.

### Impact Explanation
Accumulated creator fees are real economic value sitting inside the pool's token vaults, tracked only via `pool_state.creator_fees_token_0/1`. Once the creator's designated token account is frozen/blacklisted by the token issuer, this value becomes permanently frozen inside the vault with no code path to ever collect it (both the privileged and the permissionless collection paths route to the same fixed recipient). This is a permanent freezing of funds belonging to the pool creator, satisfying the Medium-severity bar for the accepted impact categories.

### Likelihood Explanation
This requires that one of the pool's mints implement issuer-side account freezing/blacklisting (common for USDC/USDT and permitted by Token-2022 extensions), and that the pool creator's account be subject to that freeze — a scenario outside the program's control but foreseeable for real stablecoin pools that this program supports (it explicitly supports Token-2022 mints and arbitrary SPL mints). No privileged action or malicious validator is needed; a normal creator using a blacklistable token as one side of the pool is naturally exposed.

### Recommendation
Allow the creator (or the permissionless caller acting on the creator's behalf) to specify/create a destination token account of their choosing (not necessarily their default ATA), or track fees purely as an accounting entry redeemable to any account the creator authorizes, so a freeze/blacklist on one specific token account cannot permanently lock the accrued fee balance.

### Proof of Concept
1. Pool `P` is initialized with `token_0` = USDC-like mint (issuer can freeze/blacklist arbitrary accounts) and creator `C`.
2. Swaps occur on `P`, accruing `pool_state.creator_fees_token_0 > 0`.
3. The USDC issuer freezes/blacklists `C`'s associated token account (`creator_token_0`), an action entirely outside the program's control.
4. `C` (or anyone, via `collect_creator_fee_permissionless`) calls the collection instruction; `transfer_from_pool_vault_to_user` issues `transfer_checked` to the frozen `creator_token_0` account, the CPI fails, and the whole instruction reverts.
5. `pool_state.creator_fees_token_0` is never reset (transfer never succeeded), and there is no alternate recipient parameter, so the fee remains permanently stuck in `token_0_vault`, unrecoverable by the creator or the protocol.

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-20)
```rust
    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-123)
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
