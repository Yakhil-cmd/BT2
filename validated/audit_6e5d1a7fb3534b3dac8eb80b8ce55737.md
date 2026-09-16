### Title
AMM-style AA swap logic computes settlement price from AA balance at trigger-processing time with no slippage bound, enabling a front-run/sandwich of a victim's swap trigger - (File: test/samples/uniswap_like_market_maker.oscript)

### Summary
The Certik finding describes a race between a user's unconditional `repay(uint(-1))` and an attacker's `borrow()`, where the amount actually charged is computed from mutable on-chain state (`compoundedBorrowBalance`) at *settlement* time rather than the state the user observed when signing. The ocore analog is an Autonomous Agent (AA) whose payout for a trigger is computed from the AA's live `balance[...]` at the moment the trigger is *processed* (which happens only after the triggering unit becomes stable and its position among other triggers is fixed), not from the state the trigger author observed when broadcasting. Any user who sends a swap/exchange trigger to such an AA with no min-output/slippage guard can have their expected outcome degraded by another trigger that lands earlier in trigger-processing order.

### Finding Description
AA triggers are executed strictly in the deterministic order in which their containing units are ordered by `(mci, level, unit, address)`, computed only once the relevant MCI stabilizes: [1](#0-0) [2](#0-1) 

Because ordering is keyed on `level`/`unit` hash and MCI stabilization point (not on broadcast time or the content the two trigger authors could see of each other at signing time), a second trigger that reaches the network shortly after a victim's trigger — but is included in the same or an earlier processing slot — is executed against the AA's state *before* the victim's trigger, even though the victim never intended that ordering.

Inside `handleTrigger`, formulas such as `balance[asset]` are evaluated against the AA's *live* balance at the moment of processing, e.g., in `formula/evaluation.js`'s `readBalance()`: [3](#0-2) 

The shipped `uniswap_like_market_maker.oscript` example computes swap outputs purely from `balance[$asset]` / `balance[base]` measured at the time of execution, with no user-supplied minimum-output or maximum-slippage bound: [4](#0-3) [5](#0-4) 

This is structurally the same root cause as the audited bug: the amount actually delivered/charged is derived from state read at *execution* time, and the party who submitted the request has no way to bound or revert if that state has moved unfavorably due to another party's action landing first. In the reported bug, front-running a `repay(uint(-1))` with a `borrow()` inflates the amount pulled from the victim; here, front-running (or "sandwiching") a swap trigger by shifting `balance[base]`/`balance[$asset]` first causes the victim's trigger to execute at a worse implied price than what they expected when they composed and signed their unit, with no bounds check to reject the unfavorable outcome. Note that the "invest" branch of the same sample *does* guard against this (it recomputes `$expected_asset_amount` and bounces on mismatch), which itself illustrates that the "exchange bytes to asset" / "exchange asset to bytes" branches are missing the equivalent protection.

### Impact Explanation
A trigger sender who swaps through such an AA can be forced to receive materially less than what the observed reserves implied at broadcast time, i.e. a form of AA fund loss for the victim and value extraction by whoever inserts a trigger ahead of it in the deterministic MCI/level ordering. Because this is a general pattern intrinsic to how AA formulas read `balance[...]` at execution time rather than at signing time, it affects any AA (not just this sample) that settles a payout formula from live balances without an author-specified bound, which is a documented reference pattern in the codebase's own AA examples.

### Likelihood Explanation
Exploitation requires only the capability already granted to any unprivileged AA trigger sender: observe a pending/broadcast unit destined for the AA, and get a competing unit into the DAG so that it is ordered ahead of the victim's trigger at MCI-stabilization time. This does not require any privileged network, hub, or node role — it is achievable by an ordinary user racing to get their own trigger unit witnessed/stabilized first, which is a realistic and previously discussed class of behavior for economically-incentivized AAs (AMMs, order books, price-dependent AAs) on Obyte.

### Recommendation
- AA authors should require an explicit, caller-specified bound (e.g., `trigger.data.min_amount_out` / `trigger.data.max_slippage`) in any payout formula that depends on `balance[...]` measured at trigger-processing time, and `bounce()` if the computed amount violates that bound — mirroring the existing bounce-based guard already used in the "invest in MM" branch of the same sample.
- Document this hazard prominently in the AA-authoring guidance/example scripts (`test/samples/uniswap_like_market_maker.oscript` and similar), since these ship as reference implementations that developers copy.
- Consider providing a first-class oscript primitive/helper for "minimum acceptable output" checks so AA authors are nudged toward safe patterns by default.

### Proof of Concept
1. AA `M` holds a `base`/`asset` pool per `uniswap_like_market_maker.oscript`.
2. Victim `V` observes `balance[base]` and `balance[asset]`, computes an expected `$amount` for an "exchange bytes to asset" swap, and broadcasts a trigger unit `U_v` sending bytes to `M` with no min-output constraint (matching the sample's actual logic).
3. Attacker `A` observes `U_v` before it stabilizes, and broadcasts their own trigger `U_a` (e.g., a large swap in the same direction) chosen so that `U_a` is ordered ahead of `U_v` per the `(mci, level, unit, address)` ordering used in `handleAATriggers` (`aa_composer.js:59-68`, `main_chain.js:1691-1706`).
4. When the MCI stabilizes, `U_a` executes first, shifting `balance[base]`/`balance[asset]` (per `test/samples/uniswap_like_market_maker.oscript:124-145`).
5. `U_v` then executes against the new, worse ratio, computing `$amount` via `readBalance()` (`formula/evaluation.js:1510-1528`) using the post-`U_a` balances — `V` receives less asset than what was true at the time `V` composed and signed `U_v`, with no on-chain check to reject the unfavorable fill.

### Citations

**File:** main_chain.js (L1691-1706)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
```

**File:** aa_composer.js (L59-68)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
```

**File:** formula/evaluation.js (L1510-1528)
```javascript
				function readBalance(param_address, bal_asset, cb2) {
					if (bal_asset !== 'base' && !ValidationUtils.isValidBase64(bal_asset, constants.HASH_LENGTH))
						return setFatalError('bad asset ' + bal_asset, { arr }, false, cb);

					if (!objValidationState.assocBalances[param_address])
						objValidationState.assocBalances[param_address] = {};
					var balance = objValidationState.assocBalances[param_address][bal_asset];
					if (balance !== undefined)
						return cb2(new Decimal(balance));
					conn.query(
						"SELECT balance FROM aa_balances WHERE address=? AND asset=? ",
						[param_address, bal_asset],
						function (rows) {
							balance = rows.length ? rows[0].balance : 0;
							objValidationState.assocBalances[param_address][bal_asset] = balance;
							cb2(new Decimal(balance));
						}
					);
				}
```

**File:** test/samples/uniswap_like_market_maker.oscript (L102-123)
```text
			{ // exchange bytes to asset
				if: `{trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] == 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_asset_balance = round($p / balance[base]);
					$amount = $asset_balance - $new_asset_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
```

**File:** test/samples/uniswap_like_market_maker.oscript (L124-145)
```text
			{ // exchange asset to bytes
				if: `{trigger.output[[asset=$asset]] > 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]]; // 10Kb fee
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_bytes_balance = round($p / balance[$asset]);
					$amount = $bytes_balance - $new_bytes_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
```
