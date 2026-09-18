### Title
Atomic dual-token transfer in `withdraw` permanently locks LP funds if one token's recipient account is frozen/blacklisted - (File: `programs/cp-swap/src/instructions/withdraw.rs`)

### Summary
`withdraw()` burns the LP tokens and then performs two separate `transfer_from_pool_vault_to_user` CPI calls (token_0 and token_1) inside a single atomic instruction. If the mint of either token has a freeze authority (e.g. a centralized stablecoin such as USDC/USDT) and the LP's receiving token account for that side is frozen/blacklisted, the second transfer CPI fails, causing the entire instruction — including the LP burn — to revert. Because both legs of the withdrawal are mandatory and inseparable, the LP is permanently unable to redeem their liquidity position, even the portion denominated in the non-frozen token.

### Finding Description
`withdraw()` computes `receive_token_0_amount`/`receive_token_1_amount`, burns the corresponding `lp_token_amount`, and then unconditionally calls `transfer_from_pool_vault_to_user` twice — once for each vault: [1](#0-0) 

`transfer_from_pool_vault_to_user` performs a `token_2022::transfer_checked` CPI to the caller-supplied `token_0_account` / `token_1_account`: [2](#0-1) 

The `Withdraw` account struct only constrains `token_0_account`/`token_1_account` by mint, not by any "unfrozen" property: [3](#0-2) 

If the mint's freeze authority (standard SPL Token feature, e.g. Circle's USDC blacklist mechanism) has frozen the owner's token account for one side of the pool, `transfer_checked` for that leg returns an error (`AccountFrozen`), and since both transfers plus the LP burn occur in the same instruction, the whole transaction reverts atomically. There is no fallback path (e.g. skip-and-retain, or transfer only the unaffected side) — the LP cannot partially withdraw. As long as the account remains frozen, the LP's entire position (both token_0 and token_1 shares) is permanently locked, exactly analogous to the referenced report where a blacklisted recipient in a multi-transfer loop blocks the whole claim.

The same atomicity pattern also appears in `collect_creator_fee` / `collect_creator_fee_permissionless`, where both `creator_token_0` and `creator_token_1` fee transfers must succeed together or neither is collected and accrued fees remain permanently stuck: [4](#0-3) [5](#0-4) 

### Impact Explanation
An unprivileged LP who provided liquidity to a pool containing a token with a centralized freeze/blacklist authority (e.g. USDC) can have their withdrawal permanently blocked if their token account for that mint is frozen — even though the other token leg of the pool is fully redeemable. Since `withdraw` requires both transfers to succeed atomically with the LP burn, the LP's liquidity (both assets) becomes permanently frozen inside the pool with no workaround inside the protocol (they cannot burn LP for a partial redemption). This satisfies "permanent freezing of user funds." The same DoS applies to the pool creator's accrued creator fees via `collect_creator_fee`/`collect_creator_fee_permissionless`.

### Likelihood Explanation
Likelihood is realistic for pools paired against centrally-controlled/blacklistable tokens (USDC, USDT, etc.), which are common trading pairs. Freezing of specific addresses by issuers for compliance/sanctions reasons is a routine, well-documented occurrence, not a hypothetical exploit — it requires no malicious action by the pool or protocol, only a real-world blacklist event against the LP's wallet.

### Recommendation
Decouple the two token transfers in `withdraw` (and similarly in `collect_creator_fee`/`collect_creator_fee_permissionless`) so that a failure transferring one token does not block the LP's ability to redeem/collect the unaffected token, e.g., by allowing single-sided withdrawal, using a "skip on transfer failure and retain accounted balance" pattern, or making each side's transfer a separate instruction that only reverts its own leg rather than the shared LP burn / fee-reset state.

### Proof of Concept
1. Pool P has token_0 = USDC (has freeze authority) and token_1 = SOL-wrapped token.
2. LP deposits into P and receives LP tokens; LP's own USDC account is later frozen by USDC's freeze authority (blacklist) for an unrelated reason.
3. LP calls `withdraw(lp_token_amount, ...)`.
4. Execution proceeds through LP burn and the `token_0_amount` transfer to `token_0_account`; `token_2022::transfer_checked` to the frozen `token_0_account` fails with `AccountFrozen`.
5. Because the burn and both transfers are in the same instruction (`programs/cp-swap/src/instructions/withdraw.rs:178-216`), the entire instruction reverts — LP tokens are not burned, but the LP also cannot redeem the SOL-side of their liquidity, which they otherwise are entitled to.
6. As long as the freeze persists, the LP has no way to redeem any portion of their position, permanently locking both assets.

### Citations

**File:** programs/cp-swap/src/instructions/withdraw.rs (L38-50)
```rust
    /// The token account for receive token_0,
    #[account(
        mut,
        token::mint = token_0_vault.mint,
    )]
    pub token_0_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The token account for receive token_1
    #[account(
        mut,
        token::mint = token_1_vault.mint,
    )]
    pub token_1_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L178-216)
```rust
    pool_state.lp_supply = pool_state.lp_supply.checked_sub(lp_token_amount).unwrap();
    token_burn(
        ctx.accounts.owner.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.lp_mint.to_account_info(),
        ctx.accounts.owner_lp_token.to_account_info(),
        lp_token_amount,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.token_0_account.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        if ctx.accounts.vault_0_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        token_0_amount,
        ctx.accounts.vault_0_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.token_1_account.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        if ctx.accounts.vault_1_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        token_1_amount,
        ctx.accounts.vault_1_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L96-118)
```rust
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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L101-123)
```rust
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
