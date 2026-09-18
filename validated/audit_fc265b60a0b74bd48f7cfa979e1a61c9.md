### Title
`InitializeWithPermission` accepts an unvalidated `creator` address, permanently freezing all future creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
The external report flags a Solidity NFT constructor for accepting zero addresses and empty strings for critical parameters (`_uriSetter`, `_minter`) without validation. The reachable analog in this Solana AMM program is `initialize_with_permission`, whose `creator` account is an `UncheckedAccount` supplied directly by the transaction sender with no ownership, signer, or non-default-pubkey check, and this value is permanently baked into `PoolState.pool_creator`.

### Finding Description
In `InitializeWithPermission`, `creator` is declared as a plain, unchecked account with no signer requirement and no constraint tying it to `payer` or to any real key: [1](#0-0) 

It is written straight into the pool state during initialization with no validation that it is non-default or non-zero: [2](#0-1) 

This is the same class of bug as the reported issue: an address parameter accepted by a state-initializing entry point (constructor-equivalent) is never checked against `Pubkey::default()`/zero, so it can be permanently persisted as an unusable value.

Downstream, `collect_creator_fee_permissionless` derives the fee-recipient token accounts as associated-token accounts owned by whatever `pool_creator` was recorded, with no re-validation: [3](#0-2) [4](#0-3) 

If `creator` is set to `Pubkey::default()` (the System Program ID, which has no private key), the derived associated token accounts are technically creatable (ATA derivation only needs mint+owner keys), but no entity can ever produce a signature to move funds out of an account "owned" by that authority through any privileged spend path. Accumulated `creator_fees_token_0`/`creator_fees_token_1` recorded in `PoolState` can be transferred into these ATAs by `collect_creator_fee_permissionless` (anyone can call it, no signer check on `creator`), but the underlying assets become permanently unrecoverable once parked in an ATA whose owner cannot sign.

### Impact Explanation
Any creator fee revenue (a real economic entitlement accrued from trading fees, tracked in `PoolState.creator_fees_token_0/1`) that flows to a pool created with `creator = Pubkey::default()` is permanently and irrecoverably frozen, since collection routes funds to an ATA whose "authority" cannot ever sign a subsequent transfer. This matches the required bar of "permanent freezing of user or LP funds" via a value derived from the swap fee mechanism.

### Likelihood Explanation
`initialize_with_permission` is reachable by any account holding a valid `Permission` PDA (a pool creator, per the in-scope entity list), and requires only a single transaction with attacker/creator-chosen `creator` account data — no privileged signer beyond the permissioned payer is required. The mistake is easy to make (mis-supplying a wrong/placeholder pubkey, or the default `Pubkey`), and nothing in the account constraints or `pool_state.initialize()` call rejects it.

### Recommendation
Add an explicit constraint or `require_keys_neq!(creator.key(), Pubkey::default())` check in `InitializeWithPermission`/`initialize_with_permission` before persisting `creator` into `PoolState`, mirroring the zero-address checks already used elsewhere in the program (e.g., `set_new_protocol_owner`/`set_new_fund_owner` in `update_config.rs`, which do call `require_keys_neq!(new_owner, Pubkey::default())`): [5](#0-4) 

### Proof of Concept
1. Obtain a `Permission` PDA for `payer` (pool-creator role).
2. Call `initialize_with_permission` supplying `creator = Pubkey::default()` (or any account known to have no signing capability) along with valid mints, vaults, and `payer_token_0/1`.
3. `pool_state.initialize(...)` records `pool_creator = Pubkey::default()`.
4. Over time, trades accrue `creator_fees_token_0`/`creator_fees_token_1` in `PoolState`.
5. Call `collect_creator_fee_permissionless`; it succeeds, creating ATAs owned by `Pubkey::default()` for `vault_0_mint`/`vault_1_mint` and transferring the accumulated fees into them.
6. The transferred fee tokens are now permanently inaccessible, since no key exists to sign further transfers out of an account owned by the System Program's default pubkey.

**Note on confidence**: This is the strongest reachable analog I could find in this program to the reported "missing address/string validation" bug class. I was not able to fully trace `PoolState::initialize()`'s internal body (only found its signature location) to confirm there is no other in-code guard against `Pubkey::default()` for `creator`; based on all account-constraint and instruction-body code reviewed, no such guard exists in `initialize_with_permission.rs`, `initialize.rs`, or `pool.rs`'s referenced usages of `pool_creator`.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L26-27)
```rust
    /// CHECK: creator of pool
    pub creator: UncheckedAccount<'info>,
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

**File:** programs/cp-swap/src/instructions/admin/update_config.rs (L63-73)
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
```
