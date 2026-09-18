### Title
`initialize_with_permission` accepts an unchecked `creator` account and stores it as `pool_creator` without an `address(0)` check, permanently freezing future creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
The `InitializeWithPermission` account struct declares `creator` as an `UncheckedAccount<'info>` with no signer requirement, no PDA constraint, and no non-zero check [1](#0-0) . The handler stores this arbitrary attacker-supplied key directly into `pool_state.pool_creator` via `pool_state.initialize(...)`, passing `ctx.accounts.creator.key()` verbatim [2](#0-1) . This is the same class of bug as the external report: a library/instruction that assigns a privileged/identifying address without rejecting `address(0)`.

### Finding Description
`pool_state.pool_creator` is later used as the sole access-control gate for `collect_creator_fee`, which requires the `creator` account to be a `Signer` whose key equals `pool_state.pool_creator` [3](#0-2) . It is also used (without a signer requirement) by `collect_creator_fee_permissionless`, which only checks `creator.key() == pool_state.pool_creator` and creates associated token accounts owned by that `creator` to receive fees [4](#0-3) [5](#0-4) .

Unlike `initialize`, whose `creator` field is a `Signer` (and thus can never be the default/zero pubkey in practice, since no keypair exists for it), `InitializeWithPermission::creator` is a plain `UncheckedAccount` supplied entirely by the caller. Any payer holding a `Permission` PDA can call `initialize_with_permission` and pass `System Program`/`11111...1111` (the default `Pubkey`) as `creator`, with no validation anywhere in the instruction or in `PoolState::initialize` rejecting it [6](#0-5) .

### Impact Explanation
Once `pool_creator` is set to `Pubkey::default()`:
- `collect_creator_fee` becomes permanently uncallable, since it requires a `Signer` equal to the zero pubkey, and no private key exists for that address.
- `collect_creator_fee_permissionless` can still technically execute since `creator` is only an `UncheckedAccount` match, but the resulting `creator_token_0`/`creator_token_1` are associated-token accounts owned by the zero pubkey — an address nobody controls, so any tokens transferred into them are permanently unspendable.

In both cases, all `creator_fees_token_0`/`creator_fees_token_1` accrued by the pool become permanently frozen/unclaimable, a genuine loss of LP/creator funds with no recovery path, matching the report's root-cause pattern (missing zero-address validation on a privileged/identity-bearing field assigned during a state-initializing call).

### Likelihood Explanation
Any account holding a `Permission` PDA (the gate for `initialize_with_permission`) can trigger this in a single transaction by simply supplying the System Program ID (`11111111111111111111111111111111`) as the `creator` account — no special privileges beyond already being permissioned to create a pool via this path, and the call requires no cooperation from anyone else. This could happen accidentally (a client passing an uninitialized/default pubkey) or intentionally (to grief a specific pool's creator-fee stream), making it straightforward to trigger.

### Recommendation
Add an explicit check in `initialize_with_permission` (and in `PoolState::initialize` as a defense-in-depth measure) rejecting `creator.key() == Pubkey::default()`, mirroring the existing `require_keys_neq!(new_owner, Pubkey::default())` checks already present in `update_amm_config`'s `set_new_protocol_owner`/`set_new_fund_owner` [7](#0-6) .

### Proof of Concept
1. Attacker (or any account) obtains/creates a `Permission` PDA for `payer.key()` so it passes the `permission` seeds constraint on `InitializeWithPermission` [8](#0-7) .
2. Call `initialize_with_permission` with `creator = 11111111111111111111111111111111` (the default `Pubkey`), along with valid mints/vaults/amounts.
3. `pool_state.initialize(...)` stores `pool_creator = Pubkey::default()` with no rejection [2](#0-1) .
4. Perform swaps against the pool so `creator_fees_token_0`/`creator_fees_token_1` accumulate.
5. Attempt `collect_creator_fee`: fails permanently because no signer can match `Pubkey::default()` [3](#0-2) ; or call `collect_creator_fee_permissionless`, which sends fees to a zero-authority ATA that can never be withdrawn from, permanently freezing those funds.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L26-27)
```rust
    /// CHECK: creator of pool
    pub creator: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L153-161)
```rust
    /// CHECK: PDA account used for permission verification.
    #[account(
        seeds = [
            PERMISSION_SEED.as_bytes(),
            payer.key().as_ref(),
        ],
        bump,
    )]
    pub permission: Box<Account<'info, Permission>>,
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L357-372)
```rust
    pool_state.initialize(
        ctx.bumps.authority,
        liquidity,
        open_time,
        ctx.accounts.creator.key(),
        ctx.accounts.amm_config.key(),
        ctx.accounts.token_0_vault.key(),
        ctx.accounts.token_1_vault.key(),
        &ctx.accounts.token_0_mint,
        &ctx.accounts.token_1_mint,
        ctx.accounts.lp_mint.key(),
        ctx.accounts.lp_mint.decimals,
        ctx.accounts.observation_state.key(),
        creator_fee_on,
        true,
    );
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L10-13)
```rust
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-20)
```rust
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

**File:** programs/cp-swap/src/states/pool.rs (L134-152)
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
```

**File:** programs/cp-swap/src/instructions/admin/update_config.rs (L63-76)
```rust
fn set_new_protocol_owner(amm_config: &mut Account<AmmConfig>, new_owner: Pubkey) -> Result<()> {
    require_keys_neq!(new_owner, Pubkey::default());
    #[cfg(feature = "enable-log")]
    msg!(
        "amm_config, old_protocol_owner:{}, new_owner:{}",
        amm_config.protocol_owner.to_string(),
        new_owner.key().to_string()
    );
    amm_config.protocol_owner = new_owner;
    Ok(())
}

fn set_new_fund_owner(amm_config: &mut Account<AmmConfig>, new_fund_owner: Pubkey) -> Result<()> {
    require_keys_neq!(new_fund_owner, Pubkey::default());
```
