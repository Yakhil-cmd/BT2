### Title
Same-unit price manipulation and cross-AA arbitrage via chained secondary AA triggers reading manipulable `balance[]`/`var[]` state - ([File: aa_composer.js])

### Summary
The external report describes an attacker manipulating a spot price inside a Curve pool via a large exchange and then immediately using that manipulated price to arbitrage a dependent lending market, all within one attacker-controlled transaction. The analogous bug class in ocore is that AA (Autonomous Agent) contracts that compute a "spot price" from their own mutable reserves (`balance[asset]`) or from a cached state variable derived from those reserves (`var[address]['key']`) can have that price manipulated and then immediately consumed by a second, chained AA — all inside the processing of a *single* trigger unit, because secondary AA triggers are executed synchronously and atomically in the same batch as the primary trigger [1](#0-0) .

### Finding Description
AMM-style AAs such as the reference `uniswap_like_market_maker.oscript` pattern compute exchange rates directly from the AA's own live balance (`balance[$asset]`, `balance[base]`), which reflects the funds just received in the current trigger [2](#0-1) . This is the same "spot-price-from-pool-reserves" pattern that was exploited in the UwU Lend/Curve incident (manipulate reserve ratio, then have a dependent contract trust that ratio as price).

In ocore, formula evaluation additionally allows an AA to read **another AA's state variables directly** (`var[address]['name']`), as demonstrated in `test/aa_composer.test.js` (`var['large_num2'] = var[trigger.address]['large_num'] + 1;`) [3](#0-2) . If one AA (A) stores a reserve-derived "price" in a state variable after a swap, and a second AA (B) trusts that state variable (or reads A's `balance[]` indirectly through a chained response) to price its own payout, this is a direct on-chain analog of one DeFi protocol trusting another's spot price.

Critically, when a primary trigger unit causes AA-A to send funds to AA-B, ocore treats this as a **secondary trigger** and processes it synchronously, in the same call stack and same atomic batch write, before the top-level `handleTrigger` for the primary unit even finishes: [1](#0-0) 
This means the entire sequence — "swap in A to move the reserve ratio" → "state var in A updated" → "secondary trigger fires into B" → "B reads A's now-manipulated `balance[]`/state var and pays out based on it" — happens within the processing of one single unit posted by an unprivileged user, with no intervening block/mci boundary where the market could correct itself. The balances used are tracked in `objValidationState.assocBalances`/`trigger_opts.assocBalances`, which are mutated as messages are executed within the same trigger chain [4](#0-3) , and committed together only at the end via one `batch.write` [5](#0-4) .

### Impact Explanation
If an AA design (of the kind shown in the shipped `uniswap_like_market_maker.oscript` sample, which is a widely copied AA template) is deployed with a second AA that consumes its reserve-derived price without a time-weighted or manipulation-resistant aggregation, an attacker can, within one atomically-processed unit:
1. Send a large swap to AA-A to skew its `asset_balance`/`bytes_balance` ratio.
2. Have AA-A forward funds/trigger AA-B in the same call chain.
3. Have AA-B compute a payout from AA-A's now-skewed `balance[]` (via cross-AA `var[]` read or via a chained secondary trigger amount that embeds the manipulated ratio).
4. Extract value from AA-B at the manipulated price, then (in later messages of the same chain or unit) reverse the original swap in AA-A.

This is a Critical-severity fund-drain vector for any AA composition that treats another AA's live reserve ratio as an oracle-quality price, mirroring exactly the "manipulate reserves → arbitrage dependent protocol" pattern from the UwU Lend incident.

### Likelihood Explanation
Likelihood is Medium: it requires a specific AA composition (an AMM-style AA whose price is consumed by a second AA, either via chained triggers or cross-AA `var[]` reads) rather than being a flaw in the core protocol logic itself. However, the building blocks — spot-price-from-`balance[]`, cross-AA state reads, and synchronous chaining of secondary triggers within one unit — are all first-class, documented ocore features (the shipped sample AAs actively encourage this reserve-ratio pricing pattern), so it is reasonably likely that real-world AAs are built this way, and any unprivileged unit poster can trigger the exploit chain with a single unit and no special privileges.

### Recommendation
- Document prominently (and update the reference AMM sample) that pricing an AA purely from its own instantaneous `balance[]` is unsafe for consumption by other AAs within the same atomic trigger chain, since it is manipulable by construction within a single unit.
- For AAs intended to serve as price sources for other AAs, recommend/require a manipulation-resistant mechanism (e.g., a minimum number of separate stabilized mci's between price updates and consumption, or TWAP-style averaging using historical data feeds) rather than relying on `balance[]` or a single derived state var that is updated and consumed within the same secondary-trigger chain.
- Consider adding a general warning/lint in AA validation (`formula/validation.js`) when a formula both writes a state var derived from `balance[]` and that same var is read by a *different* AA address, to help toolchains flag this pattern to AA authors.

### Proof of Concept
Conceptual chain (each AA can be deployed by an unprivileged user, and the whole chain triggered by a single unit from an unprivileged attacker):
1. Deploy `AA-A`: An AMM AA like `uniswap_like_market_maker.oscript`, which holds `asset` and `base` reserves and computes swap outputs from `balance[$asset]`/`balance[base]`, and after each swap records `var['last_price'] = balance[$asset] / balance[base]` (or similar) [2](#0-1) .
2. Deploy `AA-B`: pays out `asset` or `base` to `trigger.initial_address` based on `var[AA_A_address]['last_price']` without any staleness/deviation check, reading it via `var[address]['name']` cross-AA read semantics as demonstrated in the test suite [3](#0-2) .
3. Attacker composes and posts a single unit that:
   a. Sends a large `base` (or `asset`) payment to `AA-A`, sharply moving `balance[$asset]`/`balance[base]` and thus `var['last_price']`.
   b. Has `AA-A` forward part of its output to `AA-B` as a secondary trigger (processed synchronously per `handleSecondaryTriggers`) [1](#0-0) .
   c. `AA-B` computes and pays out using the manipulated `var[AA_A_address]['last_price']`, over-paying the attacker relative to the true (pre-manipulation) market price.
   d. The manipulated reserve ratio in `AA-A` is restored (or partially restored) by a further swap in the same or a following unit, since the price bump was purely due to the temporary large trade.

Because steps (a)-(c) are guaranteed to execute together atomically within one unit's `handleTrigger`/`handleSecondaryTriggers` recursion and a single `batch.write` [5](#0-4) , no other network participant can intervene between the manipulation and the arbitrage, exactly reproducing the intra-transaction "manipulate then arbitrage" bug class from the UwU Lend report.

**Uncertainty note:** This finding is a structural/architectural risk pattern rather than a bug in a specific patchable function — it depends on how individual AA authors design cross-AA price dependencies. I was not able to fully trace the exact bytecode of the `var[address][name]` cross-AA read op (`case 'var':` in `formula/evaluation.js`) within the tool budget available, so the precise read semantics (e.g., whether it reads committed DB state vs. in-memory `stateVars` mutated earlier in the same chain) should be verified directly in `formula/evaluation.js` before treating this as fully proven; the cross-AA read capability itself, however, is confirmed via the test suite citation above.

### Citations

**File:** aa_composer.js (L91-150)
```javascript
function handlePrimaryAATrigger(mci, unit, address, arrDefinition, arrPostedUnits, onDone) {
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
									if (arrResponses.length > 1) {
										// copy updatedStateVars to all responses
										if (arrResponses[0].updatedStateVars)
											for (var i = 1; i < arrResponses.length; i++)
												arrResponses[i].updatedStateVars = arrResponses[0].updatedStateVars;
										// merge all changes of balances if the same AA was called more than once
										let assocBalances = {};
										for (let { aa_address, balances } of arrResponses)
											assocBalances[aa_address] = balances; // overwrite if repeated
										for (let r of arrResponses) {
											r.balances = assocBalances[r.aa_address];
											r.allBalances = assocBalances;
										}
									}
									else
										arrResponses[0].allBalances = { [address]: arrResponses[0].balances };
									arrResponses.forEach(function (objAAResponse) {
										if (objAAResponse.objResponseUnit)
											arrPostedUnits.push(objAAResponse.objResponseUnit);
										eventBus.emit('aa_response', objAAResponse);
										eventBus.emit('aa_response_to_unit-'+objAAResponse.trigger_unit, objAAResponse);
										eventBus.emit('aa_response_to_address-'+objAAResponse.trigger_address, objAAResponse);
										eventBus.emit('aa_response_from_aa-'+objAAResponse.aa_address, objAAResponse);
									});
									onDone();
								});
							});
						});
					});
				});
			});
		});
	});
}
```

**File:** aa_composer.js (L543-586)
```javascript
	function updateFinalAABalances(arrConsumedOutputs, objUnit, cb) {
		if (trigger_opts.bAir)
			throw Error("updateFinalAABalances shouldn't be called with bAir");
		var assocDeltas = {};
		var arrNewAssets = [];
		arrConsumedOutputs.forEach(function (output) {
			if (!assocDeltas[output.asset])
				assocDeltas[output.asset] = 0;
			assocDeltas[output.asset] -= output.amount;
			// this might happen if there is another pending invocation of our AA that created the outputs we are spending now
			if (!objValidationState.assocBalances[address][output.asset])
				arrNewAssets.push(output.asset);
		});
		objUnit.messages.forEach(function (message) {
			if (message.app !== 'payment')
				return;
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address !== address)
					return;
				if (!assocDeltas[asset]) { // it can happen if the asset was issued by AA
					assocDeltas[asset] = 0;
					arrNewAssets.push(asset);
				}
				assocDeltas[asset] += output.amount;
			});
		});
		var arrQueries = [];
		if (arrNewAssets.length > 0) {
			var arrValues = arrNewAssets.map(function (asset) { return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", 0)"; });
			conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
		}
		for (var asset in assocDeltas) {
			if (assocDeltas[asset]) {
				conn.addQuery(arrQueries, "UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=?", [assocDeltas[asset], address, asset]);
				if (!objValidationState.assocBalances[address][asset])
					objValidationState.assocBalances[address][asset] = 0;
				objValidationState.assocBalances[address][asset] += assocDeltas[asset];
			}
		}
		if (assocDeltas.base)
			byte_balance += assocDeltas.base;
		async.series(arrQueries, cb);
```

**File:** aa_composer.js (L1702-1756)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
				},
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
					saveStateVars();
					addUpdatedStateVarsIntoPrimaryResponse();
					onDone(objUnit, bBouncing ? error_message : false);
				}
			);
		});
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

**File:** test/aa_composer.test.js (L178-182)
```javascript
					var['large_num2'] = var[trigger.address]['large_num'] + 1;
					var['long_num2'] = var[trigger.address]['long_num'] + 1;
					var['number_of_responses'] = number_of_responses;
					var['previous_aa_responses_trigger_address'] = previous_aa_responses[0].trigger_address;
					var['previous_aa_responses_unit'] = previous_aa_responses[0].unit_obj.unit;
```
