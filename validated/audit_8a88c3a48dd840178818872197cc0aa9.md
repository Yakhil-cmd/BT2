## Title
Unvalidated `creator` account lets anyone permanently assign (and freeze) the pool-creator fee-collection privilege - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` stores `ctx.accounts.creator.key()` as `pool_state.pool_creator`, but `creator` is declared as an `UncheckedAccount` that is never required to sign, never constrained to equal `payer`, and never checked for spendability. Any permissioned pool creator can therefore permanently bind the pool's creator-fee entitlement to an address that can never sign a transaction (e.g. the program's own `authority` PDA, a sysvar, or any other keyless account), which subsequently makes every `collect_creator_fee`/`collect_creator_fee_permissionless` call route accumulated creator fees into a token account that can never be spent from.

### Finding Description
In `InitializeWithPermission`, `creator` is declared only as: [1](#0-0) 
with no `Signer` requirement and no `constraint` tying it to `payer` or to any verified identity. This value is then persisted as the pool's permanent `pool_creator`: [2](#0-1) 

`pool_creator` is the sole authorization anchor used later to decide who receives creator fees. Both the signer-gated and "permissionless" collection paths derive the destination ATA's *authority* directly from this field with no additional sanity check that the account is a spendable wallet: [3](#0-2) [4](#0-3) 

Because `creator` can be set to any arbitrary pubkey (including the pool's own `authority` PDA, seeded only by `AUTH_SEED`, or any other account with no known private key), the resulting `creator_token_0`/`creator_token_1` ATAs are owned by an address that can never produce a valid signature and that the program itself never signs on behalf of for arbitrary/generic token transfers (the `AUTH_SEED` PDA only ever signs for the specific, hard-coded vault/lp-mint operations checked against `pool_state` fields, not for a freely-chosen "creator" ATA). This is a straightforward incorrect-privilege-assignment bug (CWE-266, analogous to the Nomad advisory): a role that carries real economic entitlement (accrued creator fees) is granted based on an unauthenticated, uncontrolled identifier instead of a proven signer.

### Impact Explanation
Every swap through the pool accrues `creator_fees_token_0/1` in `pool_state`: [5](#0-4) 
Once `collect_creator_fee_permissionless` is invoked, these fees are unconditionally moved out of the pool vaults into the attacker-chosen, non-spendable `creator_token_0/1` accounts: [6](#0-5) 
Since no instruction in the program ever signs on behalf of an arbitrary account owner to move funds back out of these ATAs, and the chosen `creator` may have no corresponding keypair at all, the transferred fee tokens become permanently unrecoverable — a concrete, permanent freezing of funds belonging to whoever the pool's fee revenue was intended for.

### Likelihood Explanation
`initialize_with_permission` is directly reachable by any account holding a valid `Permission` PDA (an explicitly in-scope, non-privileged-signer flow per the pool-creator use case), and requires no cooperation from the eventual `pool_creator` — the attacker fully controls the `creator` field in a single transaction with no additional preconditions beyond normal pool creation inputs.

### Recommendation
Require `creator` to be a `Signer` (as is already done in the permissionless `Initialize` instruction) or, if delegated creation is desired, constrain it with an explicit ownership/signature proof (e.g., require `creator` to sign, or validate it is a legitimate SPL token account owner capable of receiving/spending funds) before persisting it into `pool_state.pool_creator`.

### Proof of Concept
1. Obtain a `Permission` PDA via `create_permission_pda` (admin-granted, but reachable to any allow-listed creator).
2. Call `initialize_with_permission` with `payer` as your funded signer, but set the `creator` account to the pool's own `authority` PDA (`seeds = [AUTH_SEED]`) or any other keyless account (e.g., a sysvar address).
3. `pool_state.pool_creator` is now permanently set to that keyless address (`initialize_with_permission.rs:357-372`).
4. Perform swaps against the pool to accrue `creator_fees_token_0/1`.
5. Call `collect_creator_fee_permissionless`; the fee tokens are transferred into `creator_token_0/1` ATAs owned by the keyless `creator` address (`collect_creator_fee_permissionless.rs:101-127`).
6. No instruction exists to move tokens out of that ATA — the funds are permanently locked, and `collect_creator_fee` (the signer-gated path) can never succeed either since `creator` can never sign.

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L10-22)
```rust
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,

    /// CHECK: pool vault and lp mint authority
    #[account(
        seeds = [
            crate::AUTH_SEED.as_bytes(),
        ],
        bump,
    )]
    pub authority: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-29)
```rust
    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,

    /// CHECK: pool vault and lp mint authority
    #[account(
        seeds = [
            crate::AUTH_SEED.as_bytes(),
        ],
        bump,
    )]
    pub authority: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L101-127)
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

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```

**File:** programs/cp-swap/src/states/pool.rs (L166-176)
```rust
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
