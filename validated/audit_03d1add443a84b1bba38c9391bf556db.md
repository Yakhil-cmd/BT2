### Title
Permissionless `initialize` allows front-running of the deterministic pool PDA, causing pool-creation DoS and hijacking the "creator" role - (File: `programs/cp-swap/src/instructions/initialize.rs`)

### Summary
The `initialize` instruction can be called by *anyone* to create a new AMM pool. The `pool_state` PDA address is fully deterministic, derived only from `amm_config`, `token_0_mint`, and `token_1_mint` [1](#0-0) . Because none of these inputs include any caller-specific value, an attacker who observes a pending pool-creation transaction (or simply predicts a popular token pair) can submit their own `initialize` call for the same `(amm_config, token_0_mint, token_1_mint)` first, permanently taking the deterministic address before the intended creator's transaction lands — exactly the front-running/address-squatting bug class described in the external `FundFactory.createFund` report, where an unauthorized caller could consume a deterministic `CREATE2` address to DoS the intended creator.

### Finding Description
`Initialize<'info>` explicitly documents that `creator` "can be anyone" and applies no access control beyond a signer check [2](#0-1) . The pool account is created inside `create_pool`, which computes the expected PDA from `amm_config`/`token_0_mint`/`token_1_mint` and only requires an explicit signer if the caller supplies a non-PDA "random" address; for the canonical PDA path, no additional authorization is required [3](#0-2) . The account is then created/allocated via `create_or_allocate_account`, using system `CreateAccount`/`Allocate`/`Assign` signed with the PDA seeds [4](#0-3) .

Because the salt for this deterministic address (`amm_config`, `token_0_mint`, `token_1_mint`) is public and reusable, an attacker can:
1. Observe a legitimate creator's intended `initialize` transaction for a given token pair (via the public mempool/RPC), or simply preemptively initialize a pair they expect to be valuable.
2. Submit their own `initialize` transaction with the same `(amm_config, token_0_mint, token_1_mint)`, but with attacker-chosen `init_amount_0`/`init_amount_1` (setting an arbitrary/skewed initial price) and `open_time`.
3. Because `pool_account_info.owner` is checked to be the system program only before creation [5](#0-4) , the attacker's transaction succeeds first, and the PDA becomes owned by the program with the attacker recorded as `creator`.
4. The legitimate creator's later transaction for the exact same token pair now targets an account that is no longer owned by the system program, so their `create_pool` call reverts (`ErrorCode::NotApproved`), permanently blocking them from creating the intended pool for that pair under that `amm_config`.

This directly mirrors the report's root cause: a deterministic, publicly-computable creation address with no restriction on which caller may consume it, enabling front-running DoS of the intended, authorized party.

### Impact Explanation
- **Denial of Service on pool creation:** The legitimate project/team that wanted to create the canonical pool for a given token pair under a given `amm_config` is permanently prevented from doing so, since the deterministic PDA is already initialized. They cannot pick a different pair/config without changing their intended integration.
- **Hijacking of "creator" role and economic parameters:** The attacker, not the intended party, becomes the pool's `creator` recorded in `PoolState`, which is later used for creator-fee entitlement in `collect_creator_fee` and `collect_creator_fee_permissionless`. The attacker also fully controls `init_amount_0`/`init_amount_1`, letting them set an adversarial initial price ratio for the pool that legitimate users/LPs will subsequently interact with, and controls `open_time`.
- This satisfies the "unauthorized privileged effect" criterion: the "creator" designation and its economic rights are a privileged role that should belong to the intended/authorized party but can be stolen via front-running.

### Likelihood Explanation
High. The attack requires only observing a pending `initialize` transaction (or predicting a desirable token pair/config combination) and submitting a competing transaction with a higher priority fee — a standard, well-known front-running technique on Solana. No special privileges, validator collusion, or non-default features are required; a single attacker-controlled signer with generic token accounts is sufficient.

### Recommendation
Add a mechanism to bind pool creation to the intended creator or make competing initialization non-damaging, e.g.:
- Require an explicit allow-list/authorization check (similar to `initialize_with_permission`) for canonical, non-random pool PDAs, or
- Include a creator-specific or application-specific component (e.g., a `creator`-derived seed or a pre-registered "reservation" step) in the pool PDA derivation so an attacker cannot squat the exact address intended for a specific party, or
- At minimum, allow the legitimate creator to specify a unique, unpredictable identifier (similar to the `random_pool_id` signed-account path) rather than relying purely on the deterministic `(amm_config, token_0_mint, token_1_mint)` PDA when creator identity/economic terms matter.

### Proof of Concept
1. Attacker monitors the network (or independently decides) for pool creation of a valuable pair `(token_0_mint, token_1_mint)` under `amm_config` index `0`.
2. Attacker computes the same PDA: `Pubkey::find_program_address([POOL_SEED, amm_config, token_0_mint, token_1_mint], program_id)` as in `client/src/instructions/amm_instructions.rs` lines 49-58 [6](#0-5) .
3. Attacker submits `initialize` with their own token accounts, arbitrary `init_amount_0`, `init_amount_1`, and `open_time` before the legitimate creator's transaction is confirmed.
4. `create_pool` succeeds for the attacker because `pool_account_info.owner == system_program::ID` still holds at that point [7](#0-6) , and the PDA is initialized with the attacker as `creator` and attacker-chosen initial price.
5. The legitimate creator's subsequent `initialize` transaction for the same `(amm_config, token_0_mint, token_1_mint)` now fails at the `pool_account_info.owner != &system_program::ID` check, permanently reverting with `ErrorCode::NotApproved` [5](#0-4) .

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L372-388)
```rust
    if pool_account_info.owner != &system_program::ID {
        return err!(ErrorCode::NotApproved);
    }

    let (expect_pda_address, bump) = Pubkey::find_program_address(
        &[
            POOL_SEED.as_bytes(),
            amm_config.key().as_ref(),
            token_0_mint.key().as_ref(),
            token_1_mint.key().as_ref(),
        ],
        &crate::id(),
    );

    if pool_account_info.key() != expect_pda_address {
        require_eq!(pool_account_info.is_signer, true);
    }
```

**File:** programs/cp-swap/src/utils/token.rs (L405-456)
```rust
pub fn create_or_allocate_account<'a>(
    program_id: &Pubkey,
    payer: AccountInfo<'a>,
    system_program: AccountInfo<'a>,
    target_account: AccountInfo<'a>,
    siger_seed: &[&[u8]],
    space: usize,
) -> Result<()> {
    let rent = Rent::get()?;
    let current_lamports = target_account.lamports();

    if current_lamports == 0 {
        let lamports = rent.minimum_balance(space);
        let cpi_accounts = system_program::CreateAccount {
            from: payer,
            to: target_account.clone(),
        };
        let cpi_context = CpiContext::new(*system_program.key, cpi_accounts);
        system_program::create_account(
            cpi_context.with_signer(&[siger_seed]),
            lamports,
            u64::try_from(space).unwrap(),
            program_id,
        )?;
    } else {
        let required_lamports = rent
            .minimum_balance(space)
            .max(1)
            .saturating_sub(current_lamports);
        if required_lamports > 0 {
            let cpi_accounts = system_program::Transfer {
                from: payer.to_account_info(),
                to: target_account.clone(),
            };
            let cpi_context = CpiContext::new(*system_program.key, cpi_accounts);
            system_program::transfer(cpi_context, required_lamports)?;
        }
        let cpi_accounts = system_program::Allocate {
            account_to_allocate: target_account.clone(),
        };
        let cpi_context = CpiContext::new(*system_program.key, cpi_accounts);
        system_program::allocate(
            cpi_context.with_signer(&[siger_seed]),
            u64::try_from(space).unwrap(),
        )?;

        let cpi_accounts = system_program::Assign {
            account_to_assign: target_account.clone(),
        };
        let cpi_context = CpiContext::new(*system_program.key, cpi_accounts);
        system_program::assign(cpi_context.with_signer(&[siger_seed]), program_id)?;
    }
```

**File:** client/src/instructions/amm_instructions.rs (L46-59)
```rust
    let pool_account_key = if random_pool_id.is_some() {
        random_pool_id.unwrap()
    } else {
        Pubkey::find_program_address(
            &[
                POOL_SEED.as_bytes(),
                amm_config_key.to_bytes().as_ref(),
                token_0_mint.to_bytes().as_ref(),
                token_1_mint.to_bytes().as_ref(),
            ],
            &program.id(),
        )
        .0
    };
```
