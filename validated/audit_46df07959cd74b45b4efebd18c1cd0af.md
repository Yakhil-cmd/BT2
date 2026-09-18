This is a valid analog. `is_supported_mint` in `programs/cp-swap/src/utils/token.rs` only allows Token-2022 mints whose extensions are `TransferFeeConfig`, `MetadataPointer`, `TokenMetadata`, `InterestBearingConfig`, or `ScaledUiAmount` — this excludes `PermanentDelegate`/`TransferHook`, but it does **not** exclude the plain SPL Token program's native freeze-authority mechanism, and legacy/real-world SPL tokens (owned by the classic `Token` program) are unconditionally accepted (`if *mint_info.owner == Token::id() { return Ok(true); }` at [1](#0-0) ). Any SPL token with a freeze authority (e.g. a USDC/USDT-style stablecoin) can have individual token accounts frozen, which blocks all transfers to/from them — functionally identical to Ethereum USDC's blacklist referenced in the report.

### Title
Permanent freezing of pooled creator-fee funds via non-recoverable push transfer in `collect_creator_fee`/`collect_creator_fee_permissionless` - (File: `programs/cp-swap/src/instructions/collect_creator_fee.rs`, `programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs`)

### Summary
The creator-fee collection instructions push the entire accumulated `creator_fees_token_0`/`creator_fees_token_1` balance directly to the pool creator's associated token account in a single all-or-nothing CPI transfer, and only zero out the fee counters *after* that transfer succeeds. If the creator's token account can no longer receive tokens (e.g. it is frozen by the mint's freeze authority, exactly analogous to the USDC blacklist scenario in the referenced Cooler report), the fee amount becomes permanently unrecoverable — there is no fallback claim/ledger mechanism, mirroring the root cause identified in the external report.

### Finding Description
`collect_creator_fee` and `collect_creator_fee_permissionless` both read the accrued `creator_fees_token_0`/`creator_fees_token_1` counters from `PoolState`, then call `transfer_from_pool_vault_to_user` to push tokens straight from the pool vault to `creator_token_0`/`creator_token_1` (an ATA whose authority is fixed to `pool_state.pool_creator`), and only afterward reset the counters to zero [2](#0-1) [3](#0-2) . The `creator` field is fixed forever at pool `initialize`/`initialize_with_permission` time via `pool_state.initialize(..., ctx.accounts.creator.key(), ...)` [4](#0-3) , with no rotation/claim mechanism anywhere else in the program (only 3 files reference `pool_creator`). These fees are continuously funded from every swap through `pool_state.update_fees`, which adds to `creator_fees_token_0`/`creator_fees_token_1` on each trade [5](#0-4) , and the tokens physically sit inside the shared pool vaults, accounted for via `vault_amount_without_fee` [6](#0-5) .

`is_supported_mint` unconditionally accepts any mint owned by the legacy `Token` program (`spl-token`), which supports a mint-level freeze authority capable of freezing arbitrary token accounts, and among Token-2022 mints only whitelists a specific extension list [7](#0-6) . If the creator's `creator_token_0`/`creator_token_1` account is frozen (by the mint's freeze authority — analogous to a USDC-style blacklist), every subsequent call to `collect_creator_fee`/`collect_creator_fee_permissionless` will revert at the `transfer_checked` CPI in `transfer_from_pool_vault_to_user` [8](#0-7) . Because the counters are zeroed only on success, the accrued creator-fee tokens remain permanently locked inside the pool vault with no other instruction able to move or reclaim them — exactly the "push-transfer with no internal ledger" root cause flagged in the Cooler report.

### Impact Explanation
The frozen creator-fee share is real value extracted from every swapper's trade (via `creator_fee_rate` in `swap_base_input`/`swap_base_output`) that becomes permanently and irrecoverably locked in the pool vault once the creator's receiving account is frozen, with no code path to redirect or later claim it. This constitutes a permanent freezing of funds belonging to the pool creator (and effectively removes it from ever being distributed), satisfying the "permanent freezing of user or LP funds" bar.

### Likelihood Explanation
Likelihood is moderate: it requires the mint used by the pool to have a freeze authority (true for the legacy SPL Token program's standard field, which the program unconditionally supports per `is_supported_mint`) and that authority to freeze the specific creator ATA — an external event, not something a swapper/LP can trigger unilaterally on-chain. It does not require any privileged program signer or malicious validator; it only requires the pre-existing, real-world freeze-authority capability of the underlying mint, same class of external precondition as the original USDC-blacklist report.

### Recommendation
Do not gate the fee accounting reset on a successful push transfer to a single hard-coded recipient. Track collected/pending amounts per-claim or allow the creator (or anyone permissionless) to specify an alternate destination token account at collection time, and/or maintain an internal claimable ledger so a frozen/blacklisted recipient does not permanently strand funds that were already deducted from swappers.

### Proof of Concept
1. A pool is created via `initialize` (or `initialize_with_permission`) with `creator_fee_rate > 0` and `enable_creator_fee = true`, using a mint owned by the legacy `Token` program with a freeze authority (or a Token-2022 mint with an allowed extension) as `token_0_mint`/`token_1_mint`.
2. Normal swappers call `swap_base_input`/`swap_base_output` over time; each swap increments `pool_state.creator_fees_token_0`/`creator_fees_token_1` via `update_fees`.
3. The mint's freeze authority freezes the `creator_token_0`/`creator_token_1` ATA belonging to `pool_state.pool_creator` (external event, analogous to USDC blacklisting an address).
4. Any subsequent call to `collect_creator_fee` or `collect_creator_fee_permissionless` reverts inside `transfer_from_pool_vault_to_user`'s `transfer_checked` CPI, because the destination account is frozen.
5. Since the fee counters are only zeroed after a successful transfer, the accrued `creator_fees_token_0`/`creator_fees_token_1` amounts remain permanently stuck in the vault with no alternate instruction to reclaim them, even though real swapper funds funded these fees.

### Citations

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

**File:** programs/cp-swap/src/states/pool.rs (L134-176)
```rust
    pub fn initialize(
        &mut self,
        auth_bump: u8,
        lp_supply: u64,
        open_time: u64,
        pool_creator: Pubkey,
        amm_config: Pubkey,
        token_0_vault: Pubkey,
        token_1_vault: Pubkey,
        token_0_mint: &InterfaceAccount<Mint>,
        token_1_mint: &InterfaceAccount<Mint>,
        lp_mint: Pubkey,
        lp_mint_decimals: u8,
        observation_key: Pubkey,
        creator_fee_on: CreatorFeeOn,
        enable_creator_fee: bool,
    ) {
        self.amm_config = amm_config.key();
        self.pool_creator = pool_creator.key();
        self.token_0_vault = token_0_vault;
        self.token_1_vault = token_1_vault;
        self.lp_mint = lp_mint.key();
        self.token_0_mint = token_0_mint.key();
        self.token_1_mint = token_1_mint.key();
        self.token_0_program = *token_0_mint.to_account_info().owner;
        self.token_1_program = *token_1_mint.to_account_info().owner;
        self.observation_key = observation_key;
        self.auth_bump = auth_bump;
        self.lp_mint_decimals = lp_mint_decimals;
        self.mint_0_decimals = token_0_mint.decimals;
        self.mint_1_decimals = token_1_mint.decimals;
        self.lp_supply = lp_supply;
        self.protocol_fees_token_0 = 0;
        self.protocol_fees_token_1 = 0;
        self.fund_fees_token_0 = 0;
        self.fund_fees_token_1 = 0;
        self.open_time = open_time;
        self.recent_epoch = Clock::get().unwrap().epoch;
        self.creator_fee_on = creator_fee_on.to_u8();
        self.enable_creator_fee = enable_creator_fee;
        self.padding1 = [0u8; 6];
        self.creator_fees_token_0 = 0;
        self.creator_fees_token_1 = 0;
```

**File:** programs/cp-swap/src/states/pool.rs (L200-220)
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
```

**File:** programs/cp-swap/src/states/pool.rs (L326-367)
```rust
    pub fn update_fees(
        &mut self,
        protocol_fee: u64,
        fund_fee: u64,
        creator_fee: u64,
        direction: TradeDirection,
    ) -> Result<()> {
        if !self.enable_creator_fee {
            require_eq!(creator_fee, 0)
        }
        let is_creator_fee_on_input = self.is_creator_fee_on_input(direction)?;
        match direction {
            TradeDirection::ZeroForOne => {
                self.protocol_fees_token_0 = self
                    .protocol_fees_token_0
                    .checked_add(protocol_fee)
                    .unwrap();
                self.fund_fees_token_0 = self.fund_fees_token_0.checked_add(fund_fee).unwrap();

                if is_creator_fee_on_input {
                    self.creator_fees_token_0 =
                        self.creator_fees_token_0.checked_add(creator_fee).unwrap();
                } else {
                    self.creator_fees_token_1 =
                        self.creator_fees_token_1.checked_add(creator_fee).unwrap();
                }
            }
            TradeDirection::OneForZero => {
                self.protocol_fees_token_1 = self
                    .protocol_fees_token_1
                    .checked_add(protocol_fee)
                    .unwrap();
                self.fund_fees_token_1 = self.fund_fees_token_1.checked_add(fund_fee).unwrap();
                if is_creator_fee_on_input {
                    self.creator_fees_token_1 =
                        self.creator_fees_token_1.checked_add(creator_fee).unwrap();
                } else {
                    self.creator_fees_token_0 =
                        self.creator_fees_token_0.checked_add(creator_fee).unwrap();
                }
            }
        };
```
