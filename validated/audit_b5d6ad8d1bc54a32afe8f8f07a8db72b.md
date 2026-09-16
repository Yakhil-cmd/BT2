### Title
Officially shipped market-maker AA template computes swap outputs from live `balance[]` state with no slippage/minimum-output protection - ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
Obyte's autonomous agent (AA) execution model processes primary triggers strictly in main-chain (MC) order, and the `balance[asset]` value an AA formula reads reflects the AA's balance *after* all previously-ordered triggers/payments have been applied but *before* the current trigger's exchange is executed. The reference/example market-maker AA shipped in the repo computes the amount of asset or bytes to pay out purely from this live balance ratio, with no way for a trigger sender to specify an acceptable minimum output. Exactly like the reported `buyToken` issue, any other trigger that lands earlier in MC order shifts the exchange rate, so a user's swap can settle for materially less than what they expected when they broadcast their unit.

### Finding Description
The AMM exchange logic in `test/samples/uniswap_like_market_maker.oscript` computes: [1](#0-0) 

for "exchange bytes to asset" and [2](#0-1) 

for "exchange asset to bytes". In both cases `$amount` is derived solely from `balance[$asset]`/`balance[base]` at the moment the trigger executes, with no `$min_amount`/`$max_slippage` parameter read from `trigger.data` and no post-computation check that the actual `$amount` still satisfies the sender's expectations.

This mirrors how AA triggers are processed deterministically in `aa_composer.js`: `handleTrigger` reads the current on-chain balances via `updateInitialAABalances` and `objValidationState.assocBalances` before evaluating the AA's `messages`/formulas [3](#0-2) , and each trigger unit is handled according to its position in the DAG/MC order (`handlePrimaryAATrigger` / `validateAATrigger`) [4](#0-3) [5](#0-4) . The `balance[...]` formula keyword itself returns whatever the current on-disk (or trigger-adjusted) balance is at evaluation time, without any concept of a price the sender locked in [6](#0-5) .

Because unit composition happens client-side (the sender computes an expected `$amount` off-chain using the balance they observed when composing the unit) and unit inclusion order in the DAG is not something the sender controls, any other unit paying into the same AA (or exchanging in the opposite direction) that gets included/stabilized ahead of the sender's trigger shifts `balance[$asset]`/`balance[base]`, and thus the payout the sender actually receives — identical in nature to the VRGDAC price drift described in the report, just implemented via a constant-product formula instead of a VRGDA curve.

### Impact Explanation
A trigger sender computing an expected swap output from the balances visible when they compose their transaction can receive a payout that is silently and arbitrarily worse than expected once other triggers (including deliberately front-run ones) land ahead of theirs in MC order, resulting in direct unauthorized-value loss to the swapper with no on-chain enforcement of a minimum acceptable output. This is a fund-loss condition for any AA author who deploys this officially documented pattern verbatim (which is exactly the intended use of this bundled sample), and it is reachable by any unprivileged AA trigger sender.

### Likelihood Explanation
Any address can send a payment into a deployed instance of this AA (or a similar AMM AA copied from this template) at any time; ordinary transaction volume/mempool timing (not even malicious front-running) is sufficient to move the balance ratio between the time the sender observes the price and the time their trigger executes, so the condition is trivially and frequently reachable, not merely theoretical.

### Recommendation
Add an optional slippage-protection parameter to the exchange cases, e.g. let the trigger include `trigger.data.min_amount` (or `max_amount` for the receiving side) and `bounce()` if the computed `$amount` does not meet the sender's requested bound, mirroring the mitigation recommended for `buyToken`. Update the documentation/sample so that any AA author copying this pattern is guided to add such a check rather than shipping the unprotected formula as the reference implementation.

### Proof of Concept
1. AA holds `$bytes_balance` and `$asset_balance` in a 1:1-ish ratio (constant product `$p`).
2. Alice observes current balances and computes expected `$amount` for exchanging `X` bytes to asset off-chain, then composes and broadcasts her unit sending `X` bytes to the AA.
3. Before Alice's unit is included as a primary trigger, Bob broadcasts a large opposite-direction (or same-direction) exchange into the same AA that gets included first, changing `balance[$asset]`/`balance[base]`.
4. When Alice's trigger executes, `$asset_balance`/`$bytes_balance` reflect Bob's trade, so `$new_asset_balance` (and hence `$amount` in `test/samples/uniswap_like_market_maker.oscript` lines 105-110/127-132) is computed from the shifted ratio, and Alice receives less than the `$amount` she expected — with nothing in the AA to bounce the trade or protect her, exactly as in the referenced `buyToken` finding.

### Citations

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

**File:** validation.js (L986-1038)
```javascript
async function validateAATrigger(conn, objUnit, objValidationState, callback) {
	if (objValidationState.last_ball_mci < constants.v4UpgradeMci || objValidationState.bAA || !objValidationState.last_ball_mci) {
		if ("max_aa_responses" in objUnit)
			return callback(`max_aa_responses should not be there`);
		if (objValidationState.bAA || !objValidationState.last_ball_mci)
			return callback();
	}
	if ("content_hash" in objUnit) { // messages already stripped off
		objValidationState.count_primary_aa_triggers = 0;
		return callback();
	}
	if (objUnit.max_aa_responses === 0 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback(`max_aa_responses=0 is not allowed`);
	let outputCounts = {};
	for (let m of objUnit.messages) {
		if (m.app === 'payment' && m.payload) {
			const asset = m.payload.asset || 'base';
			for (let o of m.payload.outputs) {
				if (!outputCounts[o.address])
					outputCounts[o.address] = {};
				if (!outputCounts[o.address][asset])
					outputCounts[o.address][asset] = 0;
				outputCounts[o.address][asset]++;
			}
		}
	}
	const arrOutputAddresses = Object.keys(outputCounts);
	if (arrOutputAddresses.length === 0)
		return callback("no output addresses found in payment messages");

	// Look for AA triggers
	// There might be actually more triggers due to AAs defined between last_ball_mci and our unit, so our validation of tps fee might require a smaller fee than the fee actually charged when the trigger executes
	const rows = await conn.query("SELECT address FROM aa_addresses WHERE address IN (?) AND mci<=?", [arrOutputAddresses, objValidationState.last_ball_mci]);
	if (rows.length === 0) {
		if ("max_aa_responses" in objUnit)
			return callback(`no outputs to AAs, max_aa_responses should not be there`);
		return callback();
	}
	objValidationState.count_primary_aa_triggers = rows.length;
	if (objValidationState.count_primary_aa_triggers > 1) {
		if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci)
			return callback(`more than 1 primary AA trigger (${objValidationState.count_primary_aa_triggers})`);
		if (storage.getMinRetrievableMci() > constants.pemCurvesFixMci)
			return callback(createTransientError(`more than 1 primary AA trigger (${objValidationState.count_primary_aa_triggers})`));
	}
	if ((objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) && objValidationState.count_primary_aa_triggers === 1) {
		const address = rows[0].address;
		for (let asset in outputCounts[address]) {
			if (outputCounts[address][asset] > 1)
				return callback(`more than 1 output to the same AA ${address} for asset ${asset}`);
		}
	}
	callback();
```

**File:** formula/evaluation.js (L1480-1528)
```javascript
			case 'var':
			case 'balance':
				var param1 = arr[1];
				var param2 = arr[2];
				evaluate(param1, function (evaluated_param1) {
					if (fatal_error)
						return cb(false);
					if (typeof evaluated_param1 !== 'string')
						return setFatalError("1st var name is not a string: " + evaluated_param1, { arr }, false, cb);
					if (op === 'var' && !evaluated_param1.isWellFormed())
						return setFatalError("state var name not well formed: " + evaluated_param1, { arr }, false, cb);
					if (param2 === null)
						return ((op === 'var') ? readVar(address, evaluated_param1, cb) : readBalance(address, evaluated_param1, cb));
					// then, the 1st param is the address of an AA whose state or balance we are going to query
					var param_address = evaluated_param1;
					if (!ValidationUtils.isValidAddress(param_address))
						return setFatalError("var address is invalid: " + param_address, { arr }, false, cb);
					evaluate(param2, function (evaluated_param2) {
						if (fatal_error)
							return cb(false);
						if (typeof evaluated_param2 !== 'string')
							return setFatalError("2nd var name is not a string: " + evaluated_param2, { arr }, false, cb);
						if (op === 'var' && !evaluated_param2.isWellFormed())
							return setFatalError("state var name not well formed: " + evaluated_param2, { arr }, false, cb);
						(op === 'var')
							? readVar(param_address, evaluated_param2, cb)
							: readBalance(param_address, evaluated_param2, cb);
					});
				});

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
