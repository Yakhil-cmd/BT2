### Title
Tokens sent to the governance contract are permanently frozen — no `AdminOperation` can move token balances out - ([File: contracts/governance/src/op.rs])

### Summary
The governance contract can hold SAC token balances (including native XLM), but its entire operation surface — the `AdminOperation` enum resolved in `resolve_op` and applied in `apply_self_op`/`execute_self` — contains no operation that transfers tokens out or performs a generic external call. Any tokens transferred to the governance contract address are locked forever.

### Finding Description
On Soroban/Stellar, any address can hold a balance of any Stellar Asset Contract token; a `token::transfer` to a contract address requires no receiver consent or hook. The governance contract is therefore freely fundable by anyone.

Unlike the referenced `UXDGovernor` (which at least had `approveERC20`/`transferERC20` but lacked `transferETH`), this governance contract has **no** token-movement capability at all:

- `resolve_op` in `contracts/governance/src/op.rs:124-431` enumerates every schedulable `AdminOperation`. Every variant resolves either to a fixed-function call on the controller or price aggregator (e.g. `create_liquidity_pool`, `set_oracle`, `upgrade_pool`), or to a self-operation (`upgrade`, `update_delay`, `grant_role`, `revoke_role`, `transfer_ownership`, `set_price_aggregator`). There is no `TransferToken`/`Sweep`/`GenericCall` variant, and no way to specify an arbitrary target contract + function + args.
- `apply_self_op` (op.rs:439-488) handles only the self-targeting variants and panics with `InternalError` for everything else, confirming self-operations are a closed set.
- The `sweep_balance`/`claim_admin_fees` rescue endpoints exist only on the **out-of-scope** swap aggregator (`docs/reference/endpoints.md:278-290`); nothing equivalent exists in the in-scope governance API (`contracts/governance/src/api.rs`, endpoint table `docs/reference/endpoints.md:211-228`).

The only theoretical escape is `AdminOperation::UpgradeGov` installing new code with a rescue function — but that requires the current owner to be the proposer (privileged path) and a code change, i.e. the deployed code as-is cannot release the funds.

### Impact Explanation
Permanent freezing of funds: any token amount (XLM or any other SAC asset) held by the governance contract address — whether sent accidentally by a user, sent as a donation, or received through any future integration — can never be moved. The accepted impact class "permanent freezing of funds" applies directly.

### Likelihood Explanation
Medium/low likelihood but nonzero: Stellar tooling and users routinely send SAC payments to addresses without checking whether the recipient is a contract; governance addresses are published and attract donations/misdirected payments. There is no mechanism discouraging inbound transfers, and once received, no unprivileged or even routine privileged flow can recover them.

### Recommendation
Add an `AdminOperation::SweepToken { token: Address, to: Address, amount: i128 }` variant that resolves to `token.transfer(governance, to, amount)` on the `Sensitive` delay tier (or an `execute_self`-applied self-op calling `token::Client::transfer` with `env.current_contract_address()` as `from`), validated with `require_contract_address` for `to`. Optionally extend the same capability to the position-NFT and price-aggregator contracts, which share the same stuck-funds exposure.

### Proof of Concept
```rust
// Any unprivileged address freezes tokens on the governance contract:
let token = token::Client::new(&env, &xlm_sac_address);
token.transfer(&attacker, &governance_address, &1_000_000_000);

// There is no recovery path:
// - governance client API exposes only propose/pause/set_*_flags/
//   execute_self/accept_ownership-style endpoints (api.rs, endpoints.md L211-228)
// - every AdminOperation variant in resolve_op (op.rs:124-431) targets a fixed
//   controller/price-aggregator/self function — none invokes token.transfer
// - the governance address's XLM balance is now spendable by nobody
assert_eq!(token.balance(&governance_address), 1_000_000_000);
// Any call attempting to move it reverts with InternalError/NotGovernance
// because no operation variant exists for it.
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/governance/src/op.rs (L124-135)
```rust
pub(crate) fn resolve_op(env: &Env, op: &AdminOperation) -> ResolvedOperation {
    match op {
        AdminOperation::UpgradeGov(hash) => {
            validate::require_nonzero_wasm_hash(env, hash);
            self_operation(
                env,
                "upgrade",
                vec![env, hash.clone().into_val(env)],
                DelayTier::Sensitive,
            )
        }
        AdminOperation::UpdateGovDelay(new_delay) => {
```

**File:** contracts/governance/src/op.rs (L439-457)
```rust
pub(crate) fn apply_self_op(env: &Env, op: &AdminOperation) {
    match op {
        AdminOperation::UpgradeGov(hash) => access::apply_upgrade(env, hash),
        AdminOperation::UpdateGovDelay(new_delay) => apply_update_delay(env, *new_delay),
        AdminOperation::GrantGovRole(args) => {
            access::apply_grant_role(env, &args.account, &args.role)
        }
        AdminOperation::RevokeGovRole(args) => {
            access::apply_revoke_role(env, &args.account, &args.role)
        }
        AdminOperation::TransferGovOwnership(args) => {
            access::apply_transfer_ownership(env, &args.new_owner, args.live_until_ledger)
        }
        AdminOperation::SetPriceAggregator(addr) => {
            validate::require_contract_address(env, addr, OracleError::InvalidAggregator);
            storage::set_price_aggregator(env, addr);
            ControllerAdminClient::new(env, &storage::get_controller(env))
                .set_price_aggregator(addr);
        }
```

**File:** docs/reference/endpoints.md (L211-228)
```markdown
| `get_operation_ledger(operation_id: BytesN<32>) -> u32` | Open view / resolver |
| `hash_operation(target: Address, function: Symbol, args: Vec<Val>, predecessor: BytesN<32>, salt: BytesN<32>) -> BytesN<32>` | Open view / resolver |
| `resolve_oracle_tolerance(tolerance: u32) -> OracleTolerance` | Open view / resolver |
| `resolve_asset_oracle(key: PriceKey, oracle: AssetOracle) -> AssetOracle` | Open view / resolver |
| `propose(proposer: Address, op: AdminOperation, salt: BytesN<32>) -> BytesN<32>` | PROPOSER_ROLE; the proposer must also be the current owner for ownership transfers, code upgrades (`UpgradeGov`, `UpgradeController`, `UpgradePool`, `UpgradePositionNft`, `UpgradePriceAggregator`, `MigrateController`), the timelock minimum delay (`UpdateGovDelay`), price and swap sources (`SetPriceAggregator`, `ConfigureAssetOracle`, `EditOracleTolerance`, `SetSwapAggregator`), `ApproveBlendPool`, `SetAccumulator` and `GrantGovRole`; `RevokeGovRole` cannot target the proposer or the owner |
| `pause(caller: Address)` | GUARDIAN_ROLE; immediate |
| `set_spoke_asset_flags(caller: Address, spoke_id: u32, hub_asset: HubAssetKey, paused: bool, frozen: bool, no_seize: bool)` | GUARDIAN_ROLE; immediate tightening only |
| `set_sanity_band(caller: Address, key: PriceKey, min_wad: i128, max_wad: i128)` | ORACLE_ROLE; immediate tightening only |
| `create_hub(caller: Address) -> u32` | GUARDIAN_ROLE; immediate |
| `add_spoke(caller: Address) -> u32` | GUARDIAN_ROLE; immediate |
| `revoke_role_immediate(account: Address, role: Symbol)` | Owner; only guardian/oracle roles |
| `execute_self(executor: Option<Address>, op: AdminOperation, salt: BytesN<32>)` | Ready scheduled self-operation; optional executor |
| `propose_canceller_reset(new_cancellers: Vec<Address>, salt: BytesN<32>) -> BytesN<32>` | Owner; schedule uncancellable recovery |
| `execute_canceller_reset(executor: Option<Address>, new_cancellers: Vec<Address>, salt: BytesN<32>)` | Ready recovery; optional executor |
| `accept_ownership()` | Pending owner; synchronizes access-control admin and roles |
| `has_role(account: Address, role: Symbol) -> bool` | Open view / resolver |

Governance exports no generic `grant_role`, `revoke_role`, `renounce_ownership`, `get_owner`, `schedule`, or `update_delay` endpoint. Role, owner, delay and upgrade changes go through `AdminOperation` handlers. The exceptions are `revoke_role_immediate`, the canceller reset and `accept_ownership`.
```
