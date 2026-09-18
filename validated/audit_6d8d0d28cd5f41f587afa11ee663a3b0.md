## Analysis

The reported bug class — an unconditional native transfer that reverts when the recipient cannot accept it, with no fallback mechanism to recover the funds — has a direct analog in the Raydium CP-Swap program's creator-fee collection path.

### Root cause

`collect_creator_fee` and `collect_creator_fee_permissionless` unconditionally push the pool's accumulated `creator_fees_token_0` / `creator_fees_token_1` to a hardcoded ATA derived from the immutable `pool_creator` field, via `transfer_from_pool_vault_to_user`, which is a plain `transfer_checked` CPI with no fallback path: [1](#0-0) 

The recipient account is fixed by the account constraints (`associated_token::authority = creator`) in both instructions: [2](#0-1) [3](#0-2) 

`pool_creator` is written once at `initialize`/`initialize_with_permission` time and there is no instruction anywhere in the program to update it: [4](#0-3) 

`is_supported_mint` only restricts a narrow set of Token-2022 *extensions* (`TransferFeeConfig`, `MetadataPointer`, `TokenMetadata`, `InterestBearingConfig`, `ScaledUiAmount`) and unconditionally allows any legacy SPL-Token mint: [5](#0-4) 

Critically, this check never inspects the mint's base `freeze_authority` field (a normal field on both legacy SPL-Token and Token-2022 mints, not an "extension"). If the creator's `creator_token_0`/`creator_token_1` ATA is ever frozen by the mint's freeze authority (which can be the pool creator's own choice of a malicious/careless mint, or a third party who was granted/retains freeze authority on a mint used to seed the pool), every future `transfer_checked` to that account reverts, permanently failing `collect_creator_fee`/`collect_creator_fee_permissionless`. Because `vault_amount_without_fee` subtracts `creator_fees_token_0/1` out of the swappable reserve indefinitely, this fee amount becomes a stuck, unrecoverable liability with no alternate withdrawal path — the same "no way to sweep the funds out" failure mode as the reported `Sweepable.sol` issue: [6](#0-5) 

### Title
Permanent lock of accumulated creator fees when the creator's fee-receiving token account is frozen - (File: programs/cp-swap/src/instructions/collect_creator_fee.rs, programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs)

### Summary
`collect_creator_fee` / `collect_creator_fee_permissionless` transfer accumulated creator fees to a single, immutable ATA owned by `pool_state.pool_creator`. If that account is or becomes frozen (via the underlying mint's `freeze_authority`, which the program never validates or forbids), the transfer permanently reverts and the accrued `creator_fees_token_0/1` can never be collected, with no alternate recipient or recovery instruction available.

### Finding Description
Both instructions hardcode the destination account via Anchor's `associated_token::authority = creator` constraint, and rely on `transfer_from_pool_vault_to_user` → `transfer_checked`, which has no fallback if the recipient rejects the transfer (e.g. a frozen token account). `pool_creator` is fixed at pool creation with no update path in the program. `is_supported_mint` filters some Token-2022 extensions but does not check or forbid a mint's base `freeze_authority`, so a pool can be created with mints whose creator ATA can later be frozen.

### Impact Explanation
Once the creator's ATA for either vault mint is frozen, the corresponding `creator_fees_token_0`/`creator_fees_token_1` balance accumulates forever but can never be withdrawn — `collect_creator_fee`/`collect_creator_fee_permissionless` will always revert for that side. This is a permanent freezing of creator (LP-participant) funds with no recovery mechanism, matching the impact bar of concrete fund lock.

### Likelihood Explanation
Reachable without any privileged action: a pool creator can choose (or be tricked into using) a mint whose freeze authority is retained by themselves or a third party, then anyone (via the permissionless variant) or the creator triggers the fee-collection path once fees accrue and the account is frozen, at which point the instruction permanently fails.

### Recommendation
Validate that mints used for pool creation have no active `freeze_authority`, or add an owner-gated instruction to redirect/rotate the creator's fee-recipient account (and/or the `pool_creator` field) so fees are not tied to a single account that can be frozen without recourse.

### Proof of Concept
1. Create a mint (legacy SPL-Token or Token-2022) with `freeze_authority` set to an address the "creator" or a colluding party controls.
2. Use it as `token_0_mint` in `initialize`/`initialize_with_permission` (passes `is_supported_mint` since freeze authority isn't checked).
3. Perform swaps to accrue `creator_fees_token_0`.
4. Freeze the `creator_token_0` ATA using the mint's `FreezeAccount` instruction.
5. Call `collect_creator_fee` or `collect_creator_fee_permissionless`: the `transfer_checked` CPI reverts every time, and `creator_fees_token_0` remains stuck in the vault permanently.

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L58-76)
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

    /// The address that receives the collected token_1 fund fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_1_mint,
        associated_token::authority = creator,
        payer = creator,
        associated_token::token_program = token_1_program,
    )]
    pub creator_token_1: Box<InterfaceAccount<'info, TokenAccount>>,
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

**File:** programs/cp-swap/src/states/pool.rs (L134-177)
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
        self.padding = [0u64; 28];
```

**File:** programs/cp-swap/src/states/pool.rs (L200-221)
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
    }
```
