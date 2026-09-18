### Title
`initialize_with_permission` accepts an unsigned, arbitrary `creator` address, allowing pool creator fees to be permanently frozen - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` records an attacker/permission-holder-chosen `creator` pubkey into `PoolState.pool_creator` without requiring that address to sign or be verified as a controllable key. Every subsequent swap accrues `creator_fees_token_0`/`creator_fees_token_1` for that pool, but the only two ways to withdraw those fees (`collect_creator_fee` and `collect_creator_fee_permissionless`) both route the funds to an Associated Token Account owned by that same `creator` pubkey. If `creator` is set to a program-controlled PDA (e.g. `pool_state`, `authority`, `lp_mint`) or any other pubkey with no corresponding private key, the ATA that receives the fees can never be spent from, permanently locking all accumulated creator fees — the same root cause as the Cally finding: allowing the protocol's own (or otherwise unspendable) address to be embedded as an actor identity at creation time, with no later path to reclaim value credited to it.

### Finding Description
In `initialize_with_permission`, `creator` is declared as an unchecked, non-signer account: [1](#0-0) 

It is stored directly into pool state via `pool_state.initialize(...)` without any constraint tying it to a signer or to an on-curve, key-controllable address: [2](#0-1) 

By contrast, the unrestricted `initialize` instruction requires `creator` to be a `Signer`, closing off this path there: [3](#0-2) 

Once the pool is live, swaps accumulate `creator_fees_token_0`/`creator_fees_token_1` in `PoolState`, and the only withdrawal instructions constrain the payout destination to an ATA owned by `pool_state.pool_creator`: [4](#0-3) [5](#0-4) 

`collect_creator_fee_permissionless` lets anyone trigger the payout, but it still routes funds to an ATA owned by the stored `creator`, so it cannot rescue funds if that owner is unspendable: [6](#0-5) [7](#0-6) 

Because `creator` never needs to sign at pool-creation time, the permissioned `payer` can set `creator` to `pool_state`'s own key, the `authority` PDA, `lp_mint`, or any other pubkey with no known private key. No instruction in the program ever signs on behalf of these PDAs to move tokens out of an ATA they nominally "own" (the vault-moving authority is always the separate `AUTH_SEED` `authority` PDA acting on pool vaults, not on arbitrary creator-owned ATAs). The ATA created for that address is therefore permanently unspendable, and all `creator_fees_token_0`/`creator_fees_token_1` sent to it are locked forever, exactly mirroring the Cally pattern of a self-referential/unspendable identity trapping value that legitimate swappers' fees fund.

### Impact Explanation
This permanently freezes real user-derived value (the creator-fee share of every swap routed through the pool) with no recovery path via any in-scope instruction. Depending on `creator_fee_on` configuration and pool volume, this can lock a nontrivial and continuously growing amount of token_0/token_1 fees in the pool's vaults indefinitely, since the funds remain accounted for by `pool_state.creator_fees_token_0/1` but can never be transferred out (both collection instructions require an ATA under `creator`'s authority, which cannot be signed for).

### Likelihood Explanation
`initialize_with_permission` is gated by a `Permission` PDA, so this requires a permissioned `payer` — but the `creator` field itself has no signer requirement or on-curve/authority check, so a permissioned integrator can set it accidentally (e.g., passing the wrong PDA/derived address, a common integration mistake as noted in the analogous Cally finding) or deliberately to sabotage fee flows for a pool anyone can otherwise trade against. Once set, the freeze is deterministic and irreversible for every subsequent swap on that pool.

### Recommendation
Require `creator` to either be a `Signer` (as in the permissionless `initialize` path) or add an explicit check rejecting known-unspendable/program-derived addresses (the pool's own `pool_state`, `authority`, `lp_mint`, `token_0_vault`, `token_1_vault`, and the program ID itself) as the `creator` account in `initialize_with_permission`. At minimum, validate that `creator` is on the ed25519 curve (i.e., not a PDA) before storing it in `PoolState.pool_creator`.

### Proof of Concept
1. A permissioned `payer` (holding the `Permission` PDA) calls `initialize_with_permission`, passing `creator = pool_state` (the same PDA/keypair used as `pool_state` for this pool) instead of a real wallet.
2. Because `creator` is an `UncheckedAccount` with no signer requirement, this passes account validation, and `pool_state.pool_creator` is set to that unspendable address via `pool_state.initialize(...)`.
3. Users swap through the pool via `swap_base_input`/`swap_base_output`; each swap increments `pool_state.creator_fees_token_0`/`creator_fees_token_1`.
4. Anyone calls `collect_creator_fee_permissionless`; it creates ATAs owned by `creator` (the `pool_state` PDA) and transfers the accumulated creator fees into them.
5. No instruction ever signs with `pool_state`'s seeds/authority over that ATA, so the tokens sitting in `creator_token_0`/`creator_token_1` are permanently unspendable — the creator-fee share of all trading volume on this pool is locked forever.

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L21-24)
```rust
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L9-13)
```rust
#[derive(Accounts)]
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L58-66)
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
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L10-20)
```rust
#[derive(Accounts)]
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
