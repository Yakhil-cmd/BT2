### Title
NonTransfer proxy can self-escalate to `Auction`/`SudoBalances` proxy via unconditional `is_superset` rule - ([File: substrate/frame/staking-async/runtimes/rc/src/lib.rs])

### Summary
In the `staking-async` relay-chain runtime, `ProxyType::is_superset` declares that `NonTransfer` is a superset of **every** other `ProxyType` variant unconditionally, without checking that its own `filter` actually admits every call the target type admits. `pallet_proxy` authorizes `add_proxy`/`remove_proxy` solely through `is_superset`, so a delegate holding only a `NonTransfer` proxy can grant itself an `Auction` or `SudoBalances` proxy and thereby reach calls (`Registrar::swap`, `Sudo::sudo{Balances(..)}`) that `NonTransfer`'s own filter explicitly excludes. This is the exact bug class already identified and fixed for `asset-hub-westend` (paritytech/polkadot-sdk#12724 / `prdoc/pr_12769.prdoc`), but it remains present in this runtime.

### Finding Description
`pallet_proxy::do_proxy` gates nested `add_proxy`/`remove_proxy` calls purely on `is_superset`: [1](#0-0) 

In `substrate/frame/staking-async/runtimes/rc/src/lib.rs`, `ProxyType::filter` is an **allow-list** where `NonTransfer` explicitly omits sensitive calls:
- Only `Registrar(register|deregister|reserve)` — `swap` is explicitly commented as omitted.
- The entire `Sudo` pallet is explicitly commented as omitted. [2](#0-1) 

But `Auction` admits the **entire** `Registrar` call family (including `swap`): [3](#0-2) 

And `SudoBalances` admits `Sudo::sudo{call: Balances(..)}`: [4](#0-3) 

Despite these mismatches, `is_superset` blanket-claims `NonTransfer` as superset of any other type: [5](#0-4) 

`paras_registrar::Call::swap` exists as a real dispatchable in `polkadot/runtime/common/src/paras_registrar/mod.rs`, confirming the mismatch is not vacuous.

This mirrors CVE-2023-50713 precisely: the "requesting token" (`NonTransfer` proxy relationship) is checked for a broad capability flag (`is_superset`/"token write") but the system never verifies the *actual* granted privileges of the newly minted credential (`Auction`/`SudoBalances` proxy) don't exceed what the requester's own filter allows.

### Impact Explanation
A delegate holding only a routine, low-trust `NonTransfer` proxy relationship can:
1. Self-grant an `Auction` proxy, then invoke `Registrar::swap` — a call `NonTransfer` was deliberately designed to forbid (parachain-registration identity swap, a sensitive/irreversible operation).
2. Self-grant a `SudoBalances` proxy, then (if the delegator account happens to hold the chain's `Sudo` key) invoke `Sudo::sudo{Balances::force_set_balance/force_transfer}` — a class of call `NonTransfer` explicitly excludes to prevent an automation/low-trust delegate from moving or fabricating funds.

This breaks the confinement guarantee that proxy types are supposed to provide and lets a restricted delegate reach dispatches its grant was explicitly scoped to deny — the same "privilege escalation via unauthorized new-credential minting" class as the reference CVE, rated Medium there for the same reason (the escalation is bounded by the underlying account's real privileges, but it defeats the intended restriction of the specific delegated credential).

### Likelihood Explanation
High reachability: `pallet_proxy::add_proxy` and `pallet_proxy::proxy` are ordinary signed, fee-paying extrinsics available to any account that has been granted a `NonTransfer` proxy — a common, low-trust delegation pattern (e.g., automation bots, session-key rotators) — with no governance or validator privilege required. The flaw is a static configuration defect (not conditional on external state), so it is deterministically triggerable whenever such a delegation exists.

### Recommendation
Mirror the fix already applied to `asset-hub-westend` (`prdoc/pr_12769.prdoc`): remove the blanket `(ProxyType::NonTransfer, _) => true` rule and enumerate only the subset relations where `NonTransfer`'s filter is verifiably a superset of the target type's filter (e.g., `Staking`, `NominationPools`, `Governance`, `IdentityJudgement`, `CancelProxy`, `ParaRegistration` appear consistent, but `Auction` and `SudoBalances` must be excluded). Add a lattice regression test analogous to `proxy_type_superset_relation_matches_call_filters` in `cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs` for this runtime to prevent recurrence.

### Proof of Concept
Not executed against a live network (per constraints); reasoning is based on static code inspection of the cited files, which is sufficient to demonstrate the logical flaw deterministically:

1. Delegator `A` (holder of `Sudo` key, for the `SudoBalances` scenario) grants delegate `D` a `NonTransfer` proxy via `Proxy::add_proxy(origin=A, delegate=D, proxy_type=NonTransfer, delay=0)`.
2. `D` calls `Proxy::proxy(origin=D, real=A, force_proxy_type=None, call=Proxy::add_proxy{delegate: D, proxy_type: Auction, delay: 0})`.
   - Inside `do_proxy`, the origin filter evaluates `Call::add_proxy{proxy_type: Auction, ..}` against `def.proxy_type.is_superset(&Auction)` where `def.proxy_type == NonTransfer` → returns `true` (line 1415), so the nested call is **not** filtered and `add_proxy` succeeds — `D` now also holds an `Auction` proxy for `A`.
3. `D` calls `Proxy::proxy(origin=D, real=A, force_proxy_type=Some(Auction), call=Registrar::swap{..})`.
   - `Auction::filter` matches `RuntimeCall::Registrar(..)` (line 1396) → call dispatches successfully, even though `NonTransfer::filter` (the delegate's originally granted scope) explicitly excludes `Registrar::swap` (comment at line 1358).
4. Analogous flow using `SudoBalances` in place of `Auction` reaches `Sudo::sudo{Balances(..)}`, a call family `NonTransfer` explicitly omits entirely (comment at line 1353).

No privileged role, governance action, or stolen key is required beyond the routine grant of a `NonTransfer` proxy — the escalation path is enabled purely by the static, overly-permissive `is_superset` table.

### Citations

**File:** substrate/frame/proxy/src/lib.rs (L1005-1013)
```rust
			match c.is_sub_type() {
				// Proxy call cannot add or remove a proxy with more permissions than it already
				// has.
				Some(Call::add_proxy { ref proxy_type, .. }) |
				Some(Call::remove_proxy { ref proxy_type, .. })
					if !def.proxy_type.is_superset(proxy_type) =>
				{
					false
				},
```

**File:** substrate/frame/staking-async/runtimes/rc/src/lib.rs (L1352-1363)
```rust
				RuntimeCall::Scheduler(..) |
				// Specifically omitting Sudo pallet
				RuntimeCall::Proxy(..) |
				RuntimeCall::Multisig(..) |
				RuntimeCall::Registrar(paras_registrar::Call::register{..}) |
				RuntimeCall::Registrar(paras_registrar::Call::deregister{..}) |
				// Specifically omitting Registrar `swap`
				RuntimeCall::Registrar(paras_registrar::Call::reserve{..}) |
				RuntimeCall::Crowdloan(..) |
				RuntimeCall::Slots(..) |
				RuntimeCall::Auctions(..)
			),
```

**File:** substrate/frame/staking-async/runtimes/rc/src/lib.rs (L1370-1376)
```rust
			ProxyType::SudoBalances => match c {
				RuntimeCall::Sudo(pallet_sudo::Call::sudo { call: ref x }) => {
					matches!(x.as_ref(), &RuntimeCall::Balances(..))
				},
				RuntimeCall::Utility(..) => true,
				_ => false,
			},
```

**File:** substrate/frame/staking-async/runtimes/rc/src/lib.rs (L1392-1398)
```rust
			ProxyType::Auction => matches!(
				c,
				RuntimeCall::Auctions(..) |
					RuntimeCall::Crowdloan(..) |
					RuntimeCall::Registrar(..) |
					RuntimeCall::Slots(..)
			),
```

**File:** substrate/frame/staking-async/runtimes/rc/src/lib.rs (L1410-1418)
```rust
	fn is_superset(&self, o: &Self) -> bool {
		match (self, o) {
			(x, y) if x == y => true,
			(ProxyType::Any, _) => true,
			(_, ProxyType::Any) => false,
			(ProxyType::NonTransfer, _) => true,
			_ => false,
		}
	}
```
