### Title
Permanent freeze of accumulated creator fees via a frozen/blocklisted `creator_token_0`/`creator_token_1` account - (File: programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs)

### Summary
Both `collect_creator_fee` and `collect_creator_fee_permissionless` atomically transfer accumulated `creator_fees_token_0` and `creator_fees_token_1` out of the vaults to the pool creator's associated token accounts, and only then zero the fee counters. If either destination account cannot receive tokens (e.g., a Token-2022 mint with a `DefaultAccountState = Frozen` extension, or a freeze-authority/blocklist-style mint such as USDC/USDT freezing the creator's account), the whole instruction reverts every time it is invoked, permanently trapping the accumulated creator fees inside the pool vaults with no path to recovery — the same "revert forces default/loss" pattern described in the referenced Cooler `repay()` report, where a counterparty-controlled account freeze weaponizes an atomic transfer to permanently block fund movement.

### Finding Description
`collect_creator_fee_permissionless` is explicitly permissionless — "Anyone can trigger the collection since the fee is always sent to the pool creator" [1](#0-0) . It creates the creator's ATAs via `init_if_needed` with `associated_token::authority = creator` [2](#0-1) , then transfers `creator_fees_token_0`/`creator_fees_token_1` from the vaults to those accounts, and only resets the counters to zero after both transfers succeed: [3](#0-2) 

The equivalent permissioned instruction `collect_creator_fee` has the identical atomic transfer-then-reset pattern [4](#0-3) . Both routes rely on `transfer_from_pool_vault_to_user`, which performs a plain `transfer_checked` CPI with no fallback or partial-success handling [5](#0-4) .

Because the transfer to `creator_token_0`/`creator_token_1` and the zeroing of `pool_state.creator_fees_token_0/1` happen in the same transaction, any condition that makes the transfer to the creator's account fail (frozen account, blocklisted account for USDC/USDT-style tokens, or a Token-2022 mint using the `DefaultAccountState` extension so that newly `init_if_needed`-created ATAs are frozen by default) causes the entire instruction to revert. There is no alternate path to withdraw or redirect these funds — searches of `programs/cp-swap/src` found no extension-type validation (e.g., rejecting `DefaultAccountState`, `PermanentDelegate`, or checking mint freeze authority) anywhere in `initialize.rs`/`initialize_with_permission.rs`, so a pool can legitimately be created against such a mint.

`creator_fees_token_0`/`creator_fees_token_1` are excluded from the tradable/withdrawable vault balance via `vault_amount_without_fee` [6](#0-5)  — they are tracked as a separate ledger inside `PoolState` [7](#0-6)  that accumulates every swap via `update_fees` and can only ever leave the vault through `collect_creator_fee`/`collect_creator_fee_permissionless`. Once collection is permanently blocked, these amounts remain locked inside the vault forever with no other exit instruction, which is a permanent freeze of fee-ledger funds analogous to the reported `repay()` default-forcing bug (a counterparty-controlled frozen/blocklisted account weaponizes an atomic external transfer to permanently deny access to funds).

### Impact Explanation
This is a permanent freeze of protocol/creator fee-ledger accounting: once the creator's `creator_token_0` or `creator_token_1` account is frozen/blocklisted (self-inflicted by the token issuer, not by the creator or an attacker directly), all accumulated and all future creator fees for that pool become permanently unclaimable, since both collection instructions revert atomically on every call. This matches the accepted "insolvent pool or fee-ledger accounting" impact category — funds sit in the vault forever, unreachable via any code path.

### Likelihood Explanation
This requires the creator's token account for token_0 or token_1 to become frozen or blocklisted — a realistic scenario for common tokens like USDC/USDT (blocklist) or any Token-2022 mint with the `DefaultAccountState = Frozen` extension (a mint could be configured this way from pool creation onward, guaranteeing the freshly `init_if_needed`-created ATA is frozen the moment the instruction tries to use it, i.e., deterministic and immediate, not merely probabilistic). Since `collect_creator_fee_permissionless` requires no special privilege to call and pool creation does not validate against such mint extensions, the trigger conditions are fully within reach of a single unprivileged transaction interacting with normal (if adversarially configured) SPL/Token-2022 mints.

### Recommendation
Do not couple resetting the `creator_fees_token_0`/`creator_fees_token_1` counters to a successful direct transfer to a creator-controlled account. Instead, consider a pull-based/escrow model (e.g., track a claimable balance and let the creator specify/update the destination account at claim time, or hold funds in a program-controlled account until a valid, unfrozen destination is confirmed), or handle transfer failures per-token so that a frozen `creator_token_0` account does not also block the collection of `creator_fees_token_1`.

### Proof of Concept
1. A pool creator initializes a pool where `token_1_mint` is a Token-2022 mint with the `DefaultAccountState` extension set to `Frozen` (or any mint whose issuer can later blocklist arbitrary addresses, e.g., USDC/USDT-style tokens).
2. Swaps occur normally; `pool_state.creator_fees_token_1` accumulates via `update_fees` on every swap [8](#0-7) .
3. Anyone calls `collect_creator_fee_permissionless`. The `creator_token_1` ATA is created via `init_if_needed` and is frozen by default (extension) or later frozen/blocklisted by the mint's freeze/blocklist mechanism.
4. `transfer_from_pool_vault_to_user` for `creator_fees_token_1` fails inside the CPI, reverting the whole instruction before `pool_state.creator_fees_token_0/1` are reset to zero [9](#0-8) .
5. Every subsequent call to `collect_creator_fee` or `collect_creator_fee_permissionless` reverts identically, permanently locking the growing `creator_fees_token_0`/`creator_fees_token_1` balances inside the vaults with no alternate recovery instruction in the program.

### Citations

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L11-20)
```rust
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

**File:** programs/cp-swap/src/states/pool.rs (L107-126)
```rust
    pub protocol_fees_token_0: u64,
    pub protocol_fees_token_1: u64,

    pub fund_fees_token_0: u64,
    pub fund_fees_token_1: u64,

    /// The timestamp allowed for swap in the pool.
    pub open_time: u64,
    /// recent epoch
    pub recent_epoch: u64,

    /// Creator fee collect mode
    /// 0: both token_0 and token_1 can be used as trade fees. It depends on what the input token is when swapping
    /// 1: only token_0 as trade fee
    /// 2: only token_1 as trade fee
    pub creator_fee_on: u8,
    pub enable_creator_fee: bool,
    pub padding1: [u8; 6],
    pub creator_fees_token_0: u64,
    pub creator_fees_token_1: u64,
```

**File:** programs/cp-swap/src/states/pool.rs (L200-221)
```rust
    pub fn vault_amount_without_fee(&self, vault_0: u64, vault_1: u64) -> Result<(u64, u64)> {
        let fees_token_0 = self
            .protocol_fees_token_0
            .checked_add(self.fund_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?;
        let fees_token_1 = self
            .protocol_fees_token_1
            .checked_add(self.fund_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?;
        Ok((
            vault_0
                .checked_sub(fees_token_0)
                .ok_or(ErrorCode::InsufficientVault)?,
            vault_1
                .checked_sub(fees_token_1)
                .ok_or(ErrorCode::InsufficientVault)?,
        ))
    }
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L158-163)
```rust
    pool_state.update_fees(
        u64::try_from(result.protocol_fee).unwrap(),
        u64::try_from(result.fund_fee).unwrap(),
        u64::try_from(result.creator_fee).unwrap(),
        trade_direction,
    )?;
```
