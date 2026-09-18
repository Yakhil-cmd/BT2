### Title
Pool Initialization Does Not Reject Token Mints with a Freeze Authority, Enabling Permanent Freeze of Pool Vaults - ([File: programs/cp-swap/src/instructions/initialize.rs])

### Summary
`initialize` and `initialize_with_permission` accept any SPL/Token-2022 mint whose only validation is `mint::token_program` and the `is_supported_mint` extension allow-list; neither checks the mint's `freeze_authority` field, so a pool can be created for a token whose issuer (or attacker acting as mint/freeze authority) can freeze the pool's vault token accounts at will.

### Finding Description
`Initialize`/`InitializeWithPermission` constrain `token_0_mint`/`token_1_mint` only via `mint::token_program = token_X_program` [1](#0-0) . The only additional gate is `is_supported_mint`, called in `initialize()` before pool creation [2](#0-1) . That function only inspects the mint's *extension types* (`TransferFeeConfig`, `MetadataPointer`, `TokenMetadata`, `InterestBearingConfig`, `ScaledUiAmount`) and rejects any other extension [3](#0-2) . `freeze_authority` is a base `Mint` field present in both legacy SPL Token and Token-2022 accounts — it is not an `ExtensionType` at all, so `is_supported_mint` never inspects it, and no other constraint in `Initialize`/`InitializeWithPermission` does either.

Because pool creation is permissionless (`creator: Signer<'info>`, no admin gating) [4](#0-3) , any user can initialize a pool with a self-issued mint that retains a freeze authority, then have that freeze authority freeze `token_0_vault`/`token_1_vault` (created as ordinary associated/derived token accounts of that mint) [5](#0-4) . The same unguarded mint acceptance is repeated for `deposit`, `withdraw`, and `swap_base_input`/`swap_base_output`, which all validate only `token::mint = vault.mint` / `address = vault.mint` relationships, never freeze authority [6](#0-5) [7](#0-6) .

### Impact Explanation
Once a vault token account is frozen by the mint's freeze authority, the SPL/Token-2022 program refuses any transfer/burn/close involving that account, so `deposit`, `withdraw`, and `swap_base_input`/`swap_base_output` CPIs for that pool permanently fail. Any liquidity already deposited by other, unaware LPs before or after the freeze becomes permanently locked in the vault — a genuine permanent loss of user funds, not merely a compute/DoS nuisance.

### Likelihood Explanation
The path is fully reachable by an unprivileged actor in a single flow: mint a token with `freeze_authority = Some(attacker)`, call `initialize` (or `initialize_with_permission`) to create a pool for it, wait for unsuspecting LPs to deposit, then freeze the vault. No privileged signer, off-chain component, or non-default build is required, and the check that exists (`is_supported_mint`) provably does not cover this field.

### Recommendation
Add an explicit constraint (or manual check in `initialize`/`initialize_with_permission`) that both `token_0_mint.freeze_authority` and `token_1_mint.freeze_authority` are `COption::None`, or otherwise require the pool/allowlist mechanism (`SupportMintAssociated`) to certify a mint before allowing pool creation, consistent with the extension allow-list already implemented in `is_supported_mint`.

### Proof of Concept
1. Create a Token-2022 mint with `freeze_authority = Some(attacker_key)` (no other unsupported extensions so `is_supported_mint` passes).
2. Call `initialize` with this mint as `token_0_mint`, pairing it with any other valid mint; the instruction succeeds because only `mint::token_program` and `is_supported_mint` are checked [1](#0-0) .
3. Wait for other users to `deposit` into the pool.
4. `attacker_key` invokes `spl_token_2022::instruction::freeze_account` on `token_0_vault`.
5. Subsequent `withdraw`/`swap` calls referencing this vault fail permanently, freezing all deposited liquidity for token_0 in that pool.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L52-63)
```rust
    /// Token_0 mint, the key must smaller than token_1 mint.
    #[account(
        constraint = token_0_mint.key() < token_1_mint.key(),
        mint::token_program = token_0_program,
    )]
    pub token_0_mint: Box<InterfaceAccount<'info, Mint>>,

    /// Token_1 mint, the key must grater then token_0 mint.
    #[account(
        mint::token_program = token_1_program,
    )]
    pub token_1_mint: Box<InterfaceAccount<'info, Mint>>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L106-128)
```rust
    /// CHECK: Token_0 vault for the pool, created by contract
    #[account(
        mut,
        seeds = [
            POOL_VAULT_SEED.as_bytes(),
            pool_state.key().as_ref(),
            token_0_mint.key().as_ref()
        ],
        bump,
    )]
    pub token_0_vault: UncheckedAccount<'info>,

    /// CHECK: Token_1 vault for the pool, created by contract
    #[account(
        mut,
        seeds = [
            POOL_VAULT_SEED.as_bytes(),
            pool_state.key().as_ref(),
            token_1_mint.key().as_ref()
        ],
        bump,
    )]
    pub token_1_vault: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L196-200)
```rust
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
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

**File:** programs/cp-swap/src/instructions/deposit.rs (L68-77)
```rust
    #[account(
        address = token_0_vault.mint
    )]
    pub vault_0_mint: Box<InterfaceAccount<'info, Mint>>,

    /// The mint of token_1 vault
    #[account(
        address = token_1_vault.mint
    )]
    pub vault_1_mint: Box<InterfaceAccount<'info, Mint>>,
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L59-69)
```rust
    /// The mint of input token
    #[account(
        address = input_vault.mint
    )]
    pub input_token_mint: Box<InterfaceAccount<'info, Mint>>,

    /// The mint of output token
    #[account(
        address = output_vault.mint
    )]
    pub output_token_mint: Box<InterfaceAccount<'info, Mint>>,
```
