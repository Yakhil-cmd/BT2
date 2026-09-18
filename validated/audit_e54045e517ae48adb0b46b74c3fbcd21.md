### Title
`initialize_with_permission` sets `pool_creator` from an unverified, unchecked account instead of binding it to a signer - ([File: programs/cp-swap/src/instructions/initialize_with_permission.rs])

### Summary
In `InitializeWithPermission`, the `creator` account that is later stored as `PoolState.pool_creator` is declared as a bare `UncheckedAccount`, not a `Signer`, and not constrained to equal the transaction's `payer`. This mirrors the reported `WrappedAvail` bug class: a privileged identity field (`bridge` there, `pool_creator` here) is populated from an attacker-suppliable account/parameter instead of being tied to the actual transaction signer (`msg.sender`).

### Finding Description
`InitializeWithPermission::creator` is only documented as `/// CHECK: creator of pool` and typed `UncheckedAccount<'info>`, with no signer check and no `constraint = creator.key() == payer.key()` (or any other binding) enforced. [1](#0-0) 

That same, unverified `creator` key is written straight into `PoolState.pool_creator` at pool initialization: [2](#0-1) 

`pool_creator` is later used as the sole authorization gate for collecting the pool's accumulated creator fees. `CollectCreatorFee` requires a `Signer` whose key equals `pool_state.pool_creator`: [3](#0-2) 

The permissionless variant sends fees to an ATA owned by whatever address is stored as `pool_creator`, again with no signature requirement on `creator` itself: [4](#0-3) [5](#0-4) 

Because `creator` is never proven to be a spendable, signer-controllable address (it can be any arbitrary pubkey, including a PDA with no known private key, or simply a typo'd/garbage key), the `pool_creator` privilege can be permanently bound to an address that can never produce a valid `Signer` for `CollectCreatorFee`, and whose ATA in `CollectCreatorFeePermissionless` can be created but never further transferred out by anyone.

For comparison, the plain `Initialize` path correctly binds `pool_creator` to a real `Signer`: [6](#0-5) [7](#0-6) 

but `InitializeWithPermission` does not apply the same safeguard.

### Impact Explanation
`enable_creator_fee` is set to `true` for pools created via `InitializeWithPermission` (unlike `Initialize`, which sets `false`), so creator fees actively accrue from every swap on such pools: [2](#0-1) 

If `pool_creator` is set (accidentally, or by a malicious/careless permissioned caller) to an address without a corresponding keypair, all accumulated `creator_fees_token_0`/`creator_fees_token_1` become permanently unclaimable through `CollectCreatorFee` (which requires a live signer match) and effectively frozen in the vault, since the `CollectCreatorFeePermissionless` ATA route only lets funds reach an account owned by that unreachable key. This is a permanent freezing of protocol/LP-adjacent trading fee funds, matching the required "permanent freezing of user or LP funds" impact class.

### Likelihood Explanation
The instruction is only callable by accounts that pass the `permission` PDA check, so this is not exploitable by a fully arbitrary unprivileged actor — it requires a permissioned caller to (mistakenly or maliciously) supply a `creator` account with no reachable signer. Given the account is entirely attacker-chosen and unchecked, this is a straightforward, single-transaction misconfiguration path with no additional constraints preventing it, making the likelihood non-trivial once a permissioned caller creates a pool.

### Recommendation
Constrain `creator` to be verifiably controllable, e.g., require it to be a `Signer` (as in `Initialize`), or add an explicit `constraint = creator.key() == payer.key()` / equivalent proof-of-control check, before storing it as `pool_state.pool_creator`.

### Proof of Concept
1. A permissioned account (holding a valid `permission` PDA) calls `initialize_with_permission`, supplying a `creator` account key that is an unowned/un-keyed pubkey (e.g., a randomly generated `Pubkey` with no corresponding keypair, or a PDA of an unrelated program).
2. The instruction succeeds; `pool_state.pool_creator` is set to this un-spendable address and `enable_creator_fee = true`. [2](#0-1) 
3. As swaps occur on the pool, `creator_fees_token_0`/`creator_fees_token_1` accrue in `PoolState`.
4. `CollectCreatorFee` can never be invoked because no one can produce a signature for the stored `pool_creator` key. [3](#0-2) 
5. `CollectCreatorFeePermissionless` can create the destination ATA (owned by the unreachable `creator` key) and move funds there, but the tokens remain permanently stuck in that ATA since its owner can never sign to move them further.

Note: full verification of downstream effects (e.g., whether any other instruction can reassign `pool_creator` after initialization) was not found in the indexed portion of the repository; based on available code, no such reassignment path exists.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L21-28)
```rust
pub struct InitializeWithPermission<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub payer: Signer<'info>,

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-25)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,

```

**File:** programs/cp-swap/src/instructions/initialize.rs (L344-349)
```rust
    pool_state.initialize(
        ctx.bumps.authority,
        liquidity,
        open_time,
        ctx.accounts.creator.key(),
        ctx.accounts.amm_config.key(),
```
