### Title
Authorized Precompile-Pauser Accounts Cannot Resume Precompiles They Paused — Asymmetric Access Control Causes Temporary Fund Freeze - (File: `engine/src/contract_methods/admin.rs`)

---

### Summary

`pause_precompiles` uses an ACL-based `EngineAuthorizer` to allow a set of explicitly authorized accounts to pause exit precompiles. `resume_precompiles` uses a stricter `require_owner_only` check, meaning only the contract owner can resume. Authorized (non-owner) accounts that legitimately pause a precompile cannot undo their own action. If the owner is slow to respond, the EXIT_TO_NEAR and EXIT_TO_ETHEREUM precompiles remain paused and user funds are temporarily frozen inside Aurora.

---

### Finding Description

`pause_precompiles` and `resume_precompiles` use two different, incompatible authorization schemes:

**`pause_precompiles`** — ACL-based (`EngineAuthorizer`):

```rust
// engine/src/contract_methods/admin.rs  lines 225-241
pub fn pause_precompiles<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        require_running(&state::get_state(&io)?)?;
        let authorizer: EngineAuthorizer = engine::get_authorizer(&io);
        if !authorizer.is_authorized(&env.predecessor_account_id()) {
            return Err(b"ERR_UNAUTHORIZED".into());
        }
        ...
        pauser.pause_precompiles(flags);
        Ok(())
    })
}
```

**`resume_precompiles`** — owner-only (`require_owner_only`):

```rust
// engine/src/contract_methods/admin.rs  lines 208-223
pub fn resume_precompiles<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        ...
        pauser.resume_precompiles(flags);
        Ok(())
    })
}
```

`EngineAuthorizer` is a separate ACL (`BTreeSet<AccountId>`) stored independently from `EngineState::owner_id`. [1](#0-0)  An account in the ACL is not necessarily the owner, and the owner is not necessarily in the ACL.

`require_owner_only` performs a strict equality check against `state.owner_id`: [2](#0-1) 

The result: any ACL member that is not the owner can call `pause_precompiles` successfully but will be rejected by `resume_precompiles` with `ERR_NOT_ALLOWED`. [3](#0-2) 

---

### Impact Explanation

The `EXIT_TO_NEAR` and `EXIT_TO_ETHEREUM` precompiles are the only on-chain paths for users to exit ETH and ERC-20 tokens from Aurora back to NEAR or Ethereum. When these precompiles are paused, all exit transactions revert. [4](#0-3) 

If an ACL-authorized account pauses one or both exit precompiles — even for a legitimate reason such as a security incident — it cannot resume them. Only the owner can call `resume_precompiles`. Until the owner acts, every user attempting to exit funds receives a failure. This is a **temporary freezing of funds** (High impact).

---

### Likelihood Explanation

The `EngineAuthorizer` ACL is a production feature explicitly designed to delegate pause authority to non-owner accounts. [5](#0-4)  The asymmetry is reachable in normal operational use: an ACL member pauses a precompile in response to an incident, the incident resolves, and the ACL member attempts to resume — only to be blocked. The owner must then be contacted out-of-band. Any delay in owner response directly extends the fund-freeze window. No key compromise or governance capture is required; the ACL member is acting within their granted permissions.

---

### Recommendation

`resume_precompiles` should accept calls from any account that is either the owner **or** in the `EngineAuthorizer` ACL, mirroring the authorization model of `pause_precompiles`:

```rust
pub fn resume_precompiles<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let predecessor = env.predecessor_account_id();
        let authorizer: EngineAuthorizer = engine::get_authorizer(&io);
        if &state.owner_id != &predecessor && !authorizer.is_authorized(&predecessor) {
            return Err(errors::ERR_NOT_ALLOWED.into());
        }
        ...
    })
}
```

---

### Proof of Concept

1. Owner deploys Aurora Engine and adds account `pauser.near` to the `EngineAuthorizer` ACL.
2. `pauser.near` calls `pause_precompiles` with `EXIT_TO_NEAR` flag — succeeds.
3. All user calls to the `exitToNear` precompile now revert.
4. `pauser.near` calls `resume_precompiles` with the same flag — **fails with `ERR_NOT_ALLOWED`** because `pauser.near != owner_id`.
5. Users cannot exit funds until the owner separately calls `resume_precompiles`.

Relevant entry points in `engine/src/lib.rs`: [6](#0-5)

### Citations

**File:** engine/src/pausables.rs (L38-84)
```rust
/// Can check if given account has a permission to pause precompiles.
pub trait Authorizer {
    /// Checks if the `account` has the permission to pause precompiles.
    fn is_authorized(&self, account: &AccountId) -> bool;
}

/// Can check if a subset of precompiles is currently paused or not.
pub trait PausedPrecompilesChecker {
    /// Checks if all the `precompiles` are paused.
    ///
    /// The `precompiles` mask can be a subset and every 1 bit is meant to be checked and every 0 bit is ignored.
    fn is_paused(&self, precompiles: PrecompileFlags) -> bool;

    /// Returns a set of all paused precompiles in a bitmask, where every 1 bit means paused and every 0 bit means
    /// the opposite.
    ///
    /// To determine which bit belongs to what precompile, you have to match it with appropriate constant, for example
    /// [`PrecompileFlags::EXIT_TO_NEAR`].
    ///
    /// # Example
    /// ```
    /// # use aurora_engine::pausables::{PausedPrecompilesChecker, PrecompileFlags};
    /// # fn check(checker: impl PausedPrecompilesChecker) {
    /// let flags = checker.paused();
    ///
    /// if flags.contains(PrecompileFlags::EXIT_TO_NEAR) {
    ///     println!("EXIT_TO_NEAR is paused!");
    /// }
    /// # }
    /// ```
    fn paused(&self) -> PrecompileFlags;
}

/// Responsible for resuming and pausing of precompiles.
pub trait PausedPrecompilesManager {
    /// Resumes all the given `precompiles_to_resume`.
    ///
    /// The `precompiles_to_resume` mask can be a subset and every 1 bit is meant to be resumed and every 0 bit is
    /// ignored.
    fn resume_precompiles(&mut self, precompiles_to_resume: PrecompileFlags);

    /// Pauses all the given precompiles.
    ///
    /// The `precompiles_to_pause` mask can be a subset and every 1 bit is meant to be paused and every 0 bit is
    /// ignored.
    fn pause_precompiles(&mut self, precompiles_to_pause: PrecompileFlags);
}
```

**File:** engine/src/pausables.rs (L86-99)
```rust
#[derive(BorshSerialize, BorshDeserialize, Debug, Default, Clone)]
#[borsh(crate = "aurora_engine_types::borsh")]
pub struct EngineAuthorizer {
    /// List of [`AccountId`]s with the permission to pause precompiles.
    pub acl: BTreeSet<AccountId>,
}

impl EngineAuthorizer {
    /// Creates new [`EngineAuthorizer`] and grants permission to pause precompiles for all given `accounts`.
    pub fn from_accounts(accounts: impl Iterator<Item = AccountId>) -> Self {
        Self {
            acl: accounts.collect(),
        }
    }
```

**File:** engine/src/contract_methods/mod.rs (L79-87)
```rust
pub fn require_owner_only(
    state: &state::EngineState,
    predecessor_account_id: &AccountId,
) -> Result<(), ContractError> {
    if &state.owner_id != predecessor_account_id {
        return Err(errors::ERR_NOT_ALLOWED.into());
    }
    Ok(())
}
```

**File:** engine/src/contract_methods/admin.rs (L208-241)
```rust
#[named]
pub fn resume_precompiles<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let predecessor_account_id = env.predecessor_account_id();

        require_owner_only(&state, &predecessor_account_id)?;

        let args: PausePrecompilesCallArgs = io.read_input_borsh()?;
        let flags = PrecompileFlags::from_bits_truncate(args.paused_mask);
        let mut pauser = EnginePrecompilesPauser::from_io(io);
        pauser.resume_precompiles(flags);
        Ok(())
    })
}

#[named]
pub fn pause_precompiles<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        require_running(&state::get_state(&io)?)?;
        let authorizer: EngineAuthorizer = engine::get_authorizer(&io);

        if !authorizer.is_authorized(&env.predecessor_account_id()) {
            return Err(b"ERR_UNAUTHORIZED".into());
        }

        let args: PausePrecompilesCallArgs = io.read_input_borsh()?;
        let flags = PrecompileFlags::from_bits_truncate(args.paused_mask);
        let mut pauser = EnginePrecompilesPauser::from_io(io);
        pauser.pause_precompiles(flags);
        Ok(())
    })
}
```

**File:** engine/src/lib.rs (L197-216)
```rust
    ///
    /// [`paused`]: pause_precompiles
    #[unsafe(no_mangle)]
    pub extern "C" fn resume_precompiles() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::resume_precompiles(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Pauses a precompile.
    #[unsafe(no_mangle)]
    pub extern "C" fn pause_precompiles() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::pause_precompiles(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```
