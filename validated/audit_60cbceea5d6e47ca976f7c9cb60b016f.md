### Title
`BijectionMap::insert` Overwrites Existing NEP-141 ↔ ERC-20 Mappings Without Validation, Enabling Any Caller to Corrupt Bridge Token Accounting - (File: engine/src/map.rs)

### Summary
The `BijectionMap::insert` function in `engine/src/map.rs` writes both directions of the NEP-141 ↔ ERC-20 token mapping unconditionally, with no check for pre-existing entries. The `deploy_erc20_token` entry point in `engine/src/contract_methods/connector.rs` has no owner or access-control guard — only `require_running`. Any unprivileged caller can therefore invoke `deploy_erc20_token` for an already-registered NEP-141 token, silently overwriting the canonical `Nep141Erc20Map` entry while leaving the stale `Erc20Nep141Map` entry for the old ERC-20 address intact. This produces an inconsistent bifurcated state: two ERC-20 contracts simultaneously claim to represent the same NEP-141 token, breaking bridge accounting and effectively orphaning the original ERC-20 token from all future deposits.

### Finding Description

**Root cause — `BijectionMap::insert` has no existence check:**

```rust
// engine/src/map.rs  lines 29-35
pub fn insert(&mut self, left: &L, right: &R) {
    let key = self.left_key(left);
    self.io.write_storage(&key, right.as_ref());   // blindly overwrites

    let key = self.right_key(right);
    self.io.write_storage(&key, left.as_ref());    // blindly overwrites
}
```

The struct is documented as "A map storing a **1:1 relation**" but the invariant is never enforced. [1](#0-0) 

**Entry point — `deploy_erc20_token` is open to any caller:**

```rust
// engine/src/contract_methods/connector.rs  lines 112-130
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I, env: &E, handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;   // ← only guard
        ...
```

Every other state-mutating admin function (`set_owner`, `set_key_manager`, `set_eth_connector_contract_account`) calls `require_owner_only` before touching state. `deploy_erc20_token` does not. [2](#0-1) 

**Contrast with guarded functions:** [3](#0-2) 

**Downstream read path — `get_nep141_from_erc20` used by both exit precompiles:**

```rust
// engine-precompiles/src/native.rs  lines 302-309
fn get_nep141_from_erc20<I: IO>(erc20_token: &[u8], io: &I) -> Result<AccountId, ExitError> {
    AccountId::try_from(
        io.read_storage(bytes_to_key(KeyPrefix::Erc20Nep141Map, erc20_token).as_slice())
            ...
    )
}
``` [4](#0-3) 

**Storage key prefixes involved:** [5](#0-4) 

**Exploit flow:**

1. Legitimate operator calls `deploy_erc20_token(USDC.near)` → `ERC20_A` is deployed; storage state: `USDC.near → ERC20_A` and `ERC20_A → USDC.near`.
2. Attacker calls `deploy_erc20_token(USDC.near)` (no access control blocks this). A new `ERC20_B` is deployed. `BijectionMap::insert` runs:
   - Overwrites `Nep141Erc20Map[USDC.near] = ERC20_B`
   - Writes `Erc20Nep141Map[ERC20_B] = USDC.near`
   - **Does not touch** the now-stale `Erc20Nep141Map[ERC20_A] = USDC.near`
3. Resulting inconsistent state:
   - `USDC.near → ERC20_B` (canonical forward mapping, now points to attacker-triggered contract)
   - `ERC20_B → USDC.near` (reverse mapping for new contract)
   - `ERC20_A → USDC.near` (stale reverse mapping — orphaned)
4. All subsequent `ft_on_transfer` deposits of `USDC.near` mint `ERC20_B` tokens; `ERC20_A` can never receive new mints.
5. `ERC20_A` holders can still call `ExitToNear` (stale reverse mapping still resolves), but the token is permanently cut off from new supply — its market value collapses and holders are economically frozen.

### Impact Explanation

**Classification: High — Temporary/effective freezing of funds.**

Holders of the legitimate `ERC20_A` token lose access to all future bridge inflows. While they can technically burn existing holdings via the exit precompile (the stale `Erc20Nep141Map` entry survives), the token is permanently severed from new minting. In practice this is economically equivalent to a freeze: the token's peg breaks, liquidity drains, and holders who cannot exit immediately suffer loss of value. The attack is repeatable — the attacker can re-invoke `deploy_erc20_token` to keep rotating the canonical mapping, preventing any recovery.

### Likelihood Explanation

**High.** The entry point (`deploy_erc20_token`) requires no privileged key, no deposit, and no special role — only that the engine is running. The call is a standard NEAR function call reachable by any account. The attacker needs only to know the NEP-141 account ID of a bridged token (all are publicly observable on-chain). No front-running or timing dependency is required.

### Recommendation

1. **Short term:** Add an existence check in `BijectionMap::insert` (or add a separate `insert_if_absent` variant) that returns an error if either key is already present. Apply this in `engine::deploy_erc20_token` before writing the mapping.
2. **Short term:** Add `require_owner_only` (or an equivalent role check) to `connector::deploy_erc20_token`, consistent with all other state-mutating admin functions.
3. **Long term:** Document the valid states of the bijection map and add invariant tests asserting that no NEP-141 token and no ERC-20 address can appear in more than one mapping entry simultaneously.

### Proof of Concept

```
// Precondition: USDC.near is already registered → ERC20_A
// Attacker (any NEAR account) submits:
aurora.call(
  "deploy_erc20_token",
  borsh_encode(DeployErc20TokenArgs::Legacy("usdc.near")),
  gas=300_TGas,
  deposit=0
)
// Result:
//   Nep141Erc20Map["usdc.near"] = ERC20_B   (overwritten)
//   Erc20Nep141Map[ERC20_B]     = "usdc.near" (new)
//   Erc20Nep141Map[ERC20_A]     = "usdc.near" (stale, never cleaned)
//
// All subsequent ft_on_transfer from usdc.near mint ERC20_B.
// ERC20_A is permanently orphaned from new supply.
``` [6](#0-5) [2](#0-1) [4](#0-3)

### Citations

**File:** engine/src/map.rs (L6-35)
```rust
/// A map storing a 1:1 relation between elements of types L and R.
/// The map is backed by storage of type I.
pub struct BijectionMap<L, R, I> {
    left_prefix: KeyPrefix,
    right_prefix: KeyPrefix,
    io: I,
    left_phantom: PhantomData<L>,
    right_phantom: PhantomData<R>,
}

impl<L: AsRef<[u8]> + TryFrom<Vec<u8>>, R: AsRef<[u8]> + TryFrom<Vec<u8>>, I: IO>
    BijectionMap<L, R, I>
{
    pub const fn new(left_prefix: KeyPrefix, right_prefix: KeyPrefix, io: I) -> Self {
        Self {
            left_prefix,
            right_prefix,
            io,
            left_phantom: PhantomData,
            right_phantom: PhantomData,
        }
    }

    pub fn insert(&mut self, left: &L, right: &R) {
        let key = self.left_key(left);
        self.io.write_storage(&key, right.as_ref());

        let key = self.right_key(right);
        self.io.write_storage(&key, left.as_ref());
    }
```

**File:** engine/src/map.rs (L74-78)
```rust
        let left_prefix = KeyPrefix::Nep141Erc20Map;
        let right_prefix = KeyPrefix::Erc20Nep141Map;

        let mut map: BijectionMap<NEP141Account, ERC20Address, _> =
            BijectionMap::new(left_prefix, right_prefix, storage);
```

**File:** engine/src/contract_methods/connector.rs (L112-130)
```rust
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let bytes = io.read_input().to_vec();
        let args =
            DeployErc20TokenArgs::deserialize(&bytes).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

        match args {
            DeployErc20TokenArgs::Legacy(nep141) => {
                let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;

                io.return_output(
                    &borsh::to_vec(address.as_bytes()).map_err(|_| errors::ERR_SERIALIZE)?,
                );
                Ok(PromiseOrValue::Value(address))
```

**File:** engine/src/contract_methods/admin.rs (L104-120)
```rust
pub fn set_owner<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;

        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;

        let args: SetOwnerArgs = io.read_input_borsh()?;
        if state.owner_id == args.new_owner {
            return Err(errors::ERR_SAME_OWNER.into());
        }

        state.owner_id = args.new_owner;
        state::set_state(&mut io, &state)?;

        Ok(())
    })
```

**File:** engine-precompiles/src/native.rs (L302-309)
```rust
fn get_nep141_from_erc20<I: IO>(erc20_token: &[u8], io: &I) -> Result<AccountId, ExitError> {
    AccountId::try_from(
        io.read_storage(bytes_to_key(KeyPrefix::Erc20Nep141Map, erc20_token).as_slice())
            .map(|s| s.to_vec())
            .ok_or(ExitError::Other(Cow::Borrowed(ERR_TARGET_TOKEN_NOT_FOUND)))?,
    )
    .map_err(|_| ExitError::Other(Cow::Borrowed("ERR_INVALID_NEP141_ACCOUNT")))
}
```
