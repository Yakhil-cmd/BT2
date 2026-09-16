### Title
AA triggers that require an exact payment amount computed from live `balance[]`/`var[]` state bounce (and lose funds/bounce fee) if the AA's state changes between trigger signing and trigger stabilization/execution - (File: `formula/evaluation.js`, `aa_composer.js`)

### Summary
Just as InitCore's `repay()`/`liquidate()` take a pre-computed value (`shares`) that is checked against a live, time-varying debt figure and revert if the two diverge between approval and settlement, Obyte AA triggers that pre-compute a payment amount (e.g. via `round($ratio * trigger.output[[...]])`) and require it to exactly match a value derived from the AA's *live* `balance[]`/`var[]` state will bounce if that live state changes between when the trigger unit is signed/broadcast and when it is actually evaluated at stabilization.

### Finding Description
`balance[...]` and `var[...]` in oscript formulas are always evaluated against the AA's *current* state at the moment `handleTrigger()` runs — i.e. after the triggering unit reaches DAG stability, not at the moment the trigger's author signed and broadcast the unit. This is implemented in `formula/evaluation.js`'s `readBalance`/`readVar` handlers, which read from `objValidationState.assocBalances`/state vars populated by `updateInitialAABalances()` in `aa_composer.js` right when `handleTrigger` executes for that specific trigger: [1](#0-0) [2](#0-1) 

Trigger execution only happens after the unit has passed through DAG consensus and MCI stabilization: `handlePrimaryAATrigger` / `handleAATriggers` are invoked from `stabilizeMci`/`writer.js` only once the unit's MCI becomes stable, an event that is not synchronous with signing and can be delayed by an arbitrary number of blocks/units depending on network conditions, parent selection, witnessing, etc.: [3](#0-2) [4](#0-3) 

Meanwhile the *content* of the trigger unit — specifically the payment `outputs` amounts — is fixed and immutable the moment it is signed (`trigger.output[[asset=...]]` is read straight from the signed unit's payment message via `getTrigger()`): [5](#0-4) 

Many published AA patterns rely on the requirement that the pre-signed trigger amount matches a value computed from live state exactly, e.g. the Uniswap-like AA sample explicitly bounces when the exact match fails: [6](#0-5) 

If any other trigger to the same AA is processed and changes `balance[]`/`var[]` (e.g. another trader's swap, another investor's deposit/withdrawal) between the time a user's own trigger unit is signed/broadcast and the time it is actually stabilized and executed, the previously-signed exact amount no longer matches the freshly recomputed `$expected_asset_amount`/ratio, and the trigger unavoidably bounces via `bounce(...)` in `aa_composer.js`'s `handleTrigger`.

### Impact Explanation
Unlike an EVM `revert` that fully reverses the transaction and refunds gas to the sender's wallet, an Obyte AA bounce is not free: the AA still consumes the received coins to cover `bounce_fees` (by default `constants.MIN_BYTES_BOUNCE_FEE`, and any additional asset bounce fees defined in the AA), enforced right at the start of `handleTrigger`: [7](#0-6) 

So every ordinary, honest user (an "AA trigger sender") who composes a payment amount based on the AA's state at signing time is exposed to unrecoverable fund loss (the bounce fee, plus loss of intended trade execution) purely because of the unavoidable delay between signing a unit and its stabilization — a race condition inherent to the "exact-match-against-live-state" pattern that the ocore AA/oscript execution model encourages and that official sample AAs (shipped as part of the "Sample Autonomous Agents" documentation) implement without a tolerance window or resubmission mechanism.

### Likelihood Explanation
This is highly likely to be triggered in any AA with concurrent user activity (market makers, ICOs, games, fundraising proxies) because: (1) DAG stabilization is not instantaneous and can take multiple units/blocks depending on witnessing and MC advancement; (2) any concurrent trigger to the same AA processed in between will move `balance[]`/`var[]`; and (3) AA authors are actively encouraged (via the shipped sample AAs) to build exact-match checks against `balance[]`-derived ratios, which is the exact anti-pattern flagged in the original report.

### Recommendation
- In oscript/AA design guidance and sample AAs, avoid checking for an *exact* match between a pre-signed trigger amount and a value computed from live `balance[]`/`var[]` state; instead accept a tolerance/slippage parameter supplied by the trigger (analogous to receiving "amount" with slippage bounds rather than a fixed pre-computed value), similar to the fix recommended for InitCore (take the raw amount/parameters as input and compute expected shares/ratios inside the contract using bounded tolerance, not a strict equality check against a caller-precomputed value).
- Consider providing/encouraging an oscript primitive or documented pattern that lets AA authors specify acceptable slippage ranges instead of exact-amount checks, and update the shipped sample AAs (e.g. `uniswap_like_market_maker.oscript`) to demonstrate this safer pattern.

### Proof of Concept
1. AA `M` implements the "invest in MM" case from `test/samples/uniswap_like_market_maker.oscript` (lines 33-47), which requires the payment amount to equal `round($current_ratio * trigger.output[[asset=base]])`, where `$current_ratio = balance[$asset]/balance[base]` computed from live state at trigger-execution time.
2. User A reads the current AA balance, computes the required asset payment `X`, and signs+broadcasts a trigger unit `U_A` sending `base` and asset amount `X`.
3. Before `U_A` becomes MC-stable (this can take multiple units/witness confirmations), User B's earlier-signed but later-stabilized trigger `U_B` is stabilized first and changes the AA's `balance[]` (e.g. another swap/investment).
4. When `U_A` is finally stabilized and `handleTrigger()` runs (`aa_composer.js`), `balance[$asset]`/`balance[base]` are re-read live (`formula/evaluation.js` `readBalance`), producing a different `$current_ratio` than User A calculated, so `$expected_asset_amount != trigger.output[[asset=$asset]]` and the AA calls `bounce('wrong ratio of amounts...')`.
5. User A's funds are consumed for the `bounce_fees` (`aa_composer.js` lines 1850-1863) and the intended payment/investment does not occur — an unrecoverable fund loss caused purely by the unavoidable gap between signing and stabilization, exactly mirroring the InitCore `repay()`/`liquidate()` revert-on-stale-approval bug class.

### Citations

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

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** aa_composer.js (L474-541)
```javascript
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

**File:** aa_composer.js (L1850-1863)
```javascript
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
		}
```

**File:** main_chain.js (L1262-1286)
```javascript
// marks the MCI stable, executes triggers, and updates tps fees
async function stabilizeMci(mci) {
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	const batch = kvstore.batch();
	const count_aa_triggers = await markMcIndexStable(conn, batch, mci);
	await util.promisify(batch.write.bind(batch))({ sync: true });
	await conn.query("COMMIT");
	conn.release();
	if (count_aa_triggers > 0) {
		console.log(`executing ${count_aa_triggers} AA triggers after stabilizing MCI ${mci}`);
		// every trigger takes its own db connection
		const aa_composer = require("./aa_composer.js");
		await aa_composer.handleAATriggers();
	}
	if (mci >= constants.v4UpgradeMci) {
		console.log(`updating tps fees after stabilizing MCI ${mci}`);
		// get a new connection to write tps fees
		const conn = await db.takeConnectionFromPool();
		await conn.query("BEGIN");
		await storage.updateTpsFees(conn, [mci]);
		await conn.query("COMMIT");
		conn.release();
	}
}
```

**File:** test/samples/uniswap_like_market_maker.oscript (L33-47)
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
```
