### Title
Front-running of AA state used in payout formulas due to missing slippage protection - ([File: aa_composer.js])

### Summary
The Sherlock finding describes an admin function (`setTopupFee`) that can be changed to front-run a user's pending transaction, and because the contract lacks a minimum-received / slippage check on some code paths, the user ends up receiving far less than expected. The analogous root cause exists in how Obyte AAs (Autonomous Agents) are triggered and ordered: AA trigger processing order is deterministic based on DAG level/MCI at execution time, not on when a user composed their trigger, so any shared AA state (an exchange rate, ratio, or fee-like variable) that is used in a payout formula can be changed by another trigger that gets sequenced first — and if the AA logic (as commonly written, see the shipped `uniswap_like_market_maker.oscript` sample) contains no minimum-output/slippage guard, the victim's trigger is processed against the new, less-favorable state.

### Finding Description
AA triggers are queued and executed strictly in `mci, level, unit, address` order, not in the order a user intended or composed their trigger: [1](#0-0) 

`handleAATriggers` in `aa_composer.js` then processes all queued triggers for that MCI sequentially, applying each response (including state var updates) before the next trigger is evaluated: [2](#0-1) [3](#0-2) 

Because this ordering depends only on DAG structure (parents/level) and not on the "logical" time the trigger was authored, any other trigger sender (not just a privileged admin) can get their own trigger included and processed before a victim's already-broadcast trigger, mutating shared AA state (e.g. balances, a price ratio, or an explicit "fee" state var) that the victim's payout formula subsequently reads. This is architecturally identical to the reported bug: a value used in an output-amount calculation is mutated between when the user "locks in" their expectation and when their transaction is actually processed.

Whether this results in fund loss depends entirely on whether the AA author included a slippage check, but ocore's own bundled AA example intentionally omits one and documents the missing protection inline: [4](#0-3) 
The comment `// we can deduct exchange fees here` and the absence of any `trigger.data.min_amount`/expected-output check show that the payout `$amount` is computed purely from the current `balance[$asset]`/`balance[base]` ratio at execution time — exactly the "no slippage control" pattern flagged in the original report — with no protocol-level mechanism in `aa_composer.js` to protect a trigger sender against this state having moved due to another trigger processed first.

### Impact Explanation
An unprivileged AA trigger sender (any Obyte wallet user interacting with an AA that performs a state-dependent payout, e.g., a bonding-curve/AMM-style AA) can receive materially less than they expected, since:
- The order of trigger execution is controlled by DAG placement (which any user influences by choosing parents/fees), not by original submission intent.
- Nothing in `aa_composer.js`/`handleTrigger` enforces a minimum-output guarantee; that responsibility is left entirely to the oscript author, and the officially bundled reference implementation does not include it.
This can cause direct fund loss for the trigger sender (receiving less of an asset/base currency than the state at composition time implied), which maps to "AA fund loss" per the accepted impact categories.

### Likelihood Explanation
Medium. Exploitation requires an attacker to observe a pending, unstable trigger unit in the DAG and get their own competing trigger unit to a state-mutating AA processed at an earlier or same MCI/level — a capability any network participant already has when composing units, and does not require any privileged role (no admin, oracle, or hub access needed). This mirrors the ease of front-running described in the original report, translated to Obyte's deterministic-but-attacker-influenceable trigger ordering.

### Recommendation
- At the oscript/AA-authoring level, document and strongly recommend that any AA computing payouts from mutable state (balances, ratios, externally-set fee/rate variables) require callers to supply an expected minimum output (e.g. `trigger.data.min_amount`) and `bounce()` if the actual computed amount is less, closing the gap illustrated by the bundled `uniswap_like_market_maker.oscript` sample.
- Consider updating the reference sample AAs shipped with ocore (`test/samples/*.oscript`) to include slippage protection, since they are used as canonical patterns for third-party AA developers and currently propagate the same missing-slippage-check pattern flagged in the original report.

### Proof of Concept
1. Deploy an AA similar to `uniswap_like_market_maker.oscript` with balances `asset_balance` and `bytes_balance`.
2. Victim composes trigger T1 sending `base` to receive `asset` at the current ratio, expecting amount `A`.
3. Before T1 stabilizes, attacker observes T1 in the unstable DAG and posts trigger T2 (e.g., a large swap in the same AA) chosen so it is ordered before T1 by `mci, level, unit` per the trigger-selection query in `main_chain.js` (`handleAATriggers`).
4. T2 is processed first via `aa_composer.handleAATriggers`, changing `balance[$asset]`/`balance[base]`.
5. T1 is then processed against the new balances; since the AA's `if`/`init` blocks perform no minimum-output check (as shown in the sample), the victim receives significantly less `asset` than implied when T1 was composed.

### Citations

**File:** main_chain.js (L1695-1706)
```javascript
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

**File:** aa_composer.js (L59-88)
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
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
```

**File:** aa_composer.js (L1472-1503)
```javascript
	function fixStateVars() {
		if (bBouncing)
			return;
		for (var address in stateVars) {
			var addressVars = stateVars[address];
			for (var var_name in addressVars) {
				var state = addressVars[var_name];
				if (!state.updated)
					continue;
				if (state.value === true)
					state.value = 1; // affects secondary triggers that execute after ours
			}
		}
	}

	function saveStateVars() {
		if (bSecondary || bBouncing || trigger_opts.bAir)
			return;
		for (var address in stateVars) {
			var addressVars = stateVars[address];
			for (var var_name in addressVars) {
				var state = addressVars[var_name];
				if (!state.updated)
					continue;
				var key = "st\n" + address + "\n" + var_name;
				if (state.value === false) // false value signals that the var should be deleted
					batch.del(key);
				else
					batch.put(key, getTypeAndValue(state.value)); // Decimal converted to string, object to json
			}
		}
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
