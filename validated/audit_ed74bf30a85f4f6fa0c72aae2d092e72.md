## Analysis Result

A valid analog exists in the Solana program: the `initialize_with_permission` instruction accepts an unvalidated, non-signer `creator` account that becomes `pool_state.pool_creator`, with no check against the zero/default `Pubkey`. This mirrors the reported Solidity bug class (accepting `address(0)` as an owner/founder without validation), but on Solana this translates into a permanent-freezing-of-funds bug for pool creator fees.

### Title
`initialize_with_permission` accepts an unchecked `creator` account, allowing `pool_creator` to be set to the zero `Pubkey` and permanently freezing creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`InitializeWithPermission` declares `creator` as a plain `UncheckedAccount<'info>` with no signer requirement and no constraint rejecting `Pubkey::default()`. [1](#0-0)  The value is passed straight through to `PoolState::initialize`, which stores it verbatim as `pool_creator` without validation. [2](#0-1) 

### Finding Description
Anyone holding a `Permission` PDA (a non-admin, permissioned but not protocol-owner-privileged party) can call `initialize_with_permission` and supply an arbitrary `creator` account key, including the system default/zero `Pubkey`. Unlike `Initialize`, where `creator` is a `Signer` and thus practically cannot be the zero key, `InitializeWithPermission` decouples the fee-paying `payer` (a `Signer`) from the `creator` field that is persisted as `pool_state.pool_creator`. [3](#0-2)  No constraint such as `require_keys_neq!(creator.key(), Pubkey::default())` exists on this account, in contrast to `update_config.rs`, which explicitly guards `set_new_protocol_owner`/`set_new_fund_owner` with `require_keys_neq!(new_owner, Pubkey::default())`. [4](#0-3) 

Once `pool_creator` is the zero `Pubkey`, `collect_creator_fee` (which requires `creator: Signer<'info>` constrained by `address = pool_state.load()?.pool_creator`) becomes permanently uncallable, since no keypair corresponds to the all-zero public key. [5](#0-4)  More critically, `collect_creator_fee_permissionless` does not require the creator to sign — it only checks the `creator` account key equals `pool_state.pool_creator` and lets any `payer` push the accumulated creator fees into an associated token account owned by that (zero) authority. [6](#0-5) [7](#0-6)  Any user can trigger this call, permanently sweeping the creator-fee ledger into an ATA owned by the zero address, which is unspendable by anyone.

### Impact Explanation
This results in permanent freezing (loss) of the pool creator's accrued swap fees — funds that should belong to whoever created the pool are diverted into an ATA with no controlling private key, and `collect_creator_fee_permissionless` guarantees anyone can force this transfer irrevocably. This matches the accepted impact category of permanent freezing of user/creator funds.

### Likelihood Explanation
Likelihood is bound by the requirement that the caller of `initialize_with_permission` hold a valid `Permission` PDA, which is only created by the protocol admin via `create_permission_pda`. [8](#0-7)  Any account granted permission to create pools (a normal, non-privileged operational role, not the protocol owner) can trigger this at pool-creation time with attacker-chosen `creator` value and no additional privilege, making the path realistically reachable whenever permissioned pool creation is enabled.

### Recommendation
Add an explicit validation in `InitializeWithPermission` rejecting `creator.key() == Pubkey::default()` (e.g. via a `constraint` or `require_keys_neq!` check) before persisting it as `pool_state.pool_creator`, mirroring the safeguard already present in `update_config.rs` for `protocol_owner`/`fund_owner`.

### Proof of Concept
1. Protocol admin grants a `Permission` PDA to account `P` via `create_permission_pda`.
2. `P` calls `initialize_with_permission`, setting `payer = P` (signer) but `creator = Pubkey::default()` (the all-zero system pubkey, no signature required for this field).
3. `pool_state.pool_creator` is initialized to `Pubkey::default()`. [9](#0-8) 
4. Swaps accrue `creator_fees_token_0/1` in `pool_state` as normal.
5. Any user calls `collect_creator_fee_permissionless` with `creator = Pubkey::default()` (passes the `address = pool_state.load()?.pool_creator` check) and `payer` funding creation of the ATA for that zero authority. [7](#0-6) 
6. The accumulated creator fees are transferred into an ATA owned by `Pubkey::default()`, which nobody can ever withdraw from — funds are permanently frozen.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L20-27)
```rust
#[derive(Accounts)]
pub struct InitializeWithPermission<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: creator of pool
    pub creator: UncheckedAccount<'info>,
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

**File:** programs/cp-swap/src/instructions/admin/update_config.rs (L63-72)
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

**File:** programs/cp-swap/src/instructions/admin/create_permission_pda.rs (L14-20)
```rust
#[derive(Accounts)]
pub struct CreatePermissionPda<'info> {
    #[account(
        mut,
        constraint = (owner.key() == crate::admin::ID || owner.key() == crate::create_permission_pda_owner::ID) @ ErrorCode::InvalidOwner
    )]
    pub owner: Signer<'info>,
```
