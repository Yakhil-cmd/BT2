## Analysis

The Sherlock report describes an attacker front‑running a state‑dependent critical operation (`rebalance`) by manipulating shared state (minting max supply) right before it executes, causing the operation to break/behave incorrectly and inflict loss.

In `ocore`, the equivalent trust boundary is the **deterministic-but-attacker-influenceable ordering of AA trigger execution within a single stabilized MCI**, combined with balance/ratio-dependent AA logic (e.g., an AMM/market-maker style AA). Any unprivileged unit poster can craft a unit whose `level` places it earlier in the execution queue for the same MCI, letting them execute their own trigger against an AA *before* another already-broadcast trigger is processed — manipulating the AA's `balance[...]` state that the second trigger's formula depends on.

### Root cause

`markMcIndexStable` collects **all** units with outputs to AA addresses for the just-stabilized MCI and queues them for execution in a fixed, but attacker-affectable, order: [1](#0-0) 

The sort key is `units.level, units.unit, address` — determined purely by unit-graph properties (`level`, hash) that the unit's author chooses when composing the unit (by picking parents), not by arrival time or any anti-front-running mechanism: [2](#0-1) 

`handleAATriggers` then executes these triggers strictly in that order, each one reading/writing the AA's persisted `aa_balances` before the next trigger runs: [3](#0-2) [4](#0-3) 

A template/sample AA that is bundled with ocore and used as the canonical AMM pattern computes its trade output purely from the *current* on-chain `balance[...]` at trigger time: [5](#0-4) [6](#0-5) 

and the "initial deposit" branch is gated only on the *current* balances being exactly zero: [7](#0-6) 

### Title
Front-running of AA trigger execution order within a single MCI enables sandwich/initial‑deposit manipulation of balance‑dependent AAs - (File: `main_chain.js`, `aa_composer.js`, `test/samples/uniswap_like_market_maker.oscript`)

### Summary
Unlike EVM mempools, ocore orders AA trigger execution deterministically by `(level, unit, address)` for all triggers that land in the same stabilized MCI. Because `level` is chosen by the unit's author (via parent selection) rather than by network arrival order, any unprivileged user who observes a pending unit destined for a balance-sensitive AA can compose and broadcast their own trigger with a lower `level` so it is queued and executed first in the same MCI, mutating the AA's `aa_balances` state before the victim's trigger runs — directly analogous to the reported "front-run a critical, state-dependent function via an unrestricted mutation" bug class.

### Finding Description
`handleAATriggers` in `main_chain.js` selects every unit with an output to an AA address for the newly stabilized MCI and inserts them into the `aa_triggers` queue ordered by `level, unit, address` [8](#0-7) . This queue is drained sequentially by `handleAATriggers` in `aa_composer.js`, and each trigger's execution reads/updates the AA's balance in `aa_balances` synchronously before the next queued trigger for that MCI is processed [9](#0-8) .

Since a unit's `level` is simply `max(parent levels) + 1` and is fully controlled by which parents the author chooses at compose time, an attacker who sees a victim's unit broadcast to the AA (but not yet stable) can build their own competing unit on lower-level parents so that, once both land in the same MCI, the attacker's trigger is executed first. Balance-dependent AA logic — such as the bundled market-maker template's ratio/price computation from `balance[$asset]`/`balance[base]` [10](#0-9)  and its swap formulas [11](#0-10)  — has no protection against this reordering, so the attacker's earlier-executed trigger changes `balance[...]` that the victim's trigger (queued right after, same MCI) then uses to compute its own output.

This mirrors the reported bug class: an unprivileged actor mutates shared, critical state ("mint the max supply" / here "shift the pool balances") immediately ahead of a state-dependent operation, corrupting its result.

### Impact Explanation
- **Sandwich/MEV extraction**: attacker front-runs a legitimate swap in the market-maker AA, extracting value from the victim's trade and leaving the AA/victim worse off (fund loss).
- **First-depositor donation attack**: because the "initial deposit" branch checks `balance == 0` exactly, an attacker can front-run the genuine first depositor with a dust deposit/donation so the real depositor's investment is priced against a corrupted initial ratio, allowing the attacker to extract a disproportionate share on divestment (classic vault-inflation-style fund loss), analogous to disabling/skewing the intended "rebalance" computation in the original report.
- More generally, any bundled/derivative AA that computes state transitions from `balance[...]` at trigger time is exposed to this ordering-manipulation primitive, since ocore's engine provides no reordering protection for triggers landing in the same MCI.

### Likelihood Explanation
High for an attacker who monitors the DAG for units targeting a specific AA (this data is public before stabilization) and composes a competing unit with favorable parent selection to obtain a lower `level`. No special privilege, witness cooperation, or protocol violation is required — only standard unit composition capability available to any unprivileged unit poster.

### Recommendation
- AA authors should not assume single-mci trigger ordering is unpredictable/fair; document and, where possible, add explicit anti-front-running guards in security-sensitive templates (e.g., commit-reveal patterns, minimum liquidity locks, slippage/price bounds enforced against `trigger` data rather than `balance[...]` computed pre-vs-post trade).
- Consider hardening the bundled example templates (e.g. `uniswap_like_market_maker.oscript`) to require a minimum locked initial liquidity or a price-bound parameter supplied by the trader, closing the "balance == 0" donation/front-run window.
- At the engine level, consider whether trigger ordering within an MCI should incorporate a less author-controllable tie-breaker to reduce the practical ease of intentionally winning execution order.

### Proof of Concept
1. Attacker watches the DAG for an unstable unit `U_victim` whose output targets AA `M` (the market-maker) with a large "exchange bytes to asset" trigger.
2. Before `U_victim` stabilizes, attacker composes `U_attacker` also targeting `M`, choosing parents that yield `level(U_attacker) < level(U_victim)`.
3. Both units end up confirmed within the same MCI. `markMcIndexStable`/`handleAATriggers` order execution by `(level, unit, address)` [2](#0-1) , so `U_attacker`'s trigger executes first, updating `balance[base]`/`balance[$asset]` in `aa_balances`.
4. `U_victim`'s trigger then executes using the now-shifted `balance[...]`, computing a worse exchange amount (per the formula in the sample AA) than the trader intended, transferring value to the attacker who can immediately reverse their own position with a follow-up trigger.

### Citations

**File:** main_chain.js (L1691-1723)
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
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
			}
		);
	}
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

**File:** aa_composer.js (L463-541)
```javascript
	var bWithKeys = (mci >= constants.includeKeySizesUpgradeMci);
	var FULL_TRANSFER_INPUT_SIZE = TRANSFER_INPUT_SIZE + (bWithKeys ? TRANSFER_INPUT_KEYS_SIZE : 0);
	var byte_balance;
	var storage_size;
	var objStateUpdate;
	var count = 0;
	var originalStateVars = _.cloneDeep(stateVars);
	var originalBalances;
	if (bSecondary)
		updateOriginalOldValues();

	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
		objValidationState.assocBalances[address] = {};
		var arrAssets = Object.keys(trigger.outputs);
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
					if (!trigger.outputs[row.asset]) {
						objValidationState.assocBalances[address][row.asset] = row.balance;
						return;
					}
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
				});
				// 2. insert balances of new assets
				var arrExistingAssets = rows.map(function (row) { return row.asset; });
				var arrNewAssets = _.difference(arrAssets, arrExistingAssets);
				if (arrNewAssets.length > 0) {
					var arrValues = arrNewAssets.map(function (asset) {
						objValidationState.assocBalances[address][asset] = trigger.outputs[asset];
						return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", " + trigger.outputs[asset] + ")"
					});
					conn.addQuery(arrQueries, "INSERT INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
				}
				byte_balance = objValidationState.assocBalances[address].base;
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
				if (!bSecondary)
					conn.addQuery(arrQueries, "SAVEPOINT initial_balances");
				async.series(arrQueries, function () {
					conn.query("SELECT storage_size FROM aa_addresses WHERE address=?", [address], function (rows) {
						if (rows.length === 0)
							throw Error("AA not found? " + address);
						storage_size = rows[0].storage_size;
						objValidationState.storage_size = storage_size;
						cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
					});
				});
			}
		);
	}
```

**File:** test/samples/uniswap_like_market_maker.oscript (L33-48)
```text
			{ // invest in MM
				if: `{$mm_asset AND trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] > 0}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
						$issue_amount = balance[base];
						return;
					}
					$current_ratio = $asset_balance / $bytes_balance;
					$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
					if ($expected_asset_amount != trigger.output[[asset=$asset]])
						bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
					$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
					$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
				}`,
```

**File:** test/samples/uniswap_like_market_maker.oscript (L102-145)
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
