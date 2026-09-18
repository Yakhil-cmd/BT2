Based on the code I've examined, there is a valid analog to the DebtRegistry null-beneficiary bug class in this codebase, in the `pool_creator` field of `PoolState`.

### Title
Unconstrained `creator` account in `initialize_with_permission` allows setting `pool_creator` to an uncontrollable address, permanently freezing creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
The system assumes `PoolState.pool_creator` is always a valid, controllable address, since `collect_creator_fee` gates withdrawal behind `address = pool_state.load()?.pool_creator` on a `Signer`. In `initialize_with_permission`, the `creator` account is accepted as a completely unconstrained `UncheckedAccount` and is never required to sign, match the payer, or be checked against `Pubkey::default()`/other uncontrollable addresses. This mirrors the DebtRegistry report's root cause: an entity that is supposed to always be a valid, addressable party can be set to a null/uncontrollable value, silently breaking a downstream invariant that a privileged action (fee collection) relies on.

### Finding Description
In `initialize_with_permission.rs`, the account is declared with no ownership/signature constraint: [1](#0-0) 

That raw `creator.key()` is baked permanently into `pool_state.pool_creator` via `PoolState::initialize`: [2](#0-1) [3](#0-2) 

Downstream, `collect_creator_fee` assumes `pool_creator` is a real, controllable signer: [4](#0-3) 

and `collect_creator_fee_permissionless` sends the accrued fees to an ATA whose authority is that same unvalidated `pool_creator`: [5](#0-4) [6](#0-5) 

If a payer with an approved `Permission` PDA passes `Pubkey::default()` (the System Program ID, which has no corresponding private key) or any other address nobody controls as `creator`, `pool_state.pool_creator` is permanently set to that value. `collect_creator_fee` can never succeed thereafter because no one can produce a signature for that pubkey. `collect_creator_fee_permissionless` will still succeed technically (anyone can pay to create the ATA), but the resulting `creator_token_0`/`creator_token_1` accounts are owned by an address nobody controls, so the tokens transferred there (`creator_fees_token_0`/`creator_fees_token_1`, accrued from every swap through the pool) are permanently unrecoverable.

Note that by contrast, the permissionless `Initialize` instruction correctly requires `creator: Signer<'info>`, which prevents this from happening there: [7](#0-6) 

This inconsistency confirms the missing check is a bug specific to `initialize_with_permission`, not an intentional design choice.

### Impact Explanation
Every swap through an affected pool accrues `creator_fees_token_0`/`creator_fees_token_1` into `PoolState` (state used by the curve/fee-split logic). Because `pool_creator` is uncontrollable, these accrued fees are permanently locked inside the pool's vaults with no path to withdrawal — a permanent freezing of a portion of protocol/user-generated fee funds. This satisfies the "permanent freezing of user or LP funds" / "insolvent... fee-ledger accounting" acceptance criteria, since the vault's tracked balance no longer corresponds to funds any party can ever claim.

### Likelihood Explanation
The pool creation flow explicitly listed in-scope (`initialize_with_permission`) is reachable by any payer holding an approved `Permission` PDA — a normal pool-creator role, not a program-admin/privileged-signer action. The `creator` field requires no signature and no relationship to `payer`, so a pool creator can trivially pass `Pubkey::default()`, the System Program ID, or any other address whose private key is unknown/unobtainable as `creator` in a single transaction, with no additional privilege needed beyond being permitted to create a pool at all.

### Recommendation
In `InitializeWithPermission`'s account validation, require `creator` to either be a `Signer`, or explicitly constrain it to equal `payer` (or another authenticated party), and reject known-uncontrollable addresses (e.g., `Pubkey::default()` or the System Program ID) before storing it into `pool_state.pool_creator`, mirroring the signer requirement already present in the permissionless `Initialize` instruction.

### Proof of Concept
1. Attacker (or any user) obtains an approved `Permission` PDA for their `payer` key via the normal admin-approved permission flow (`create_permission_pda`).
2. Attacker calls `initialize_with_permission`, passing `creator = Pubkey::default()` (or any other address they don't control) instead of their own key. This account is only an `UncheckedAccount` with no signer/address constraint: [1](#0-0) 
3. The pool is created and `pool_state.pool_creator` is permanently set to the attacker-chosen null/uncontrollable address via `PoolState::initialize`.
4. As swaps occur, `creator_fees_token_0`/`creator_fees_token_1` accumulate in `PoolState`.
5. `collect_creator_fee` can never be called successfully since no wallet can sign as `pool_creator`: [4](#0-3) 
6. `collect_creator_fee_permissionless` may execute, but it sends the fees into an ATA owned by the uncontrollable `creator` address, permanently locking the tokens: [6](#0-5)

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

**File:** programs/cp-swap/src/states/pool.rs (L139-152)
```rust
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

**File:** programs/cp-swap/src/instructions/initialize.rs (L22-24)
```rust
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```
