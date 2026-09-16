### Title
Cost-free previewing of AA pseudo-randomness via `light/dry_run_aa` lets a trigger sender cherry-pick favorable outcomes before ever broadcasting a unit - (File: `network.js`, `aa_composer.js`, `formula/evaluation.js`)

### Summary
The AI Arena report describes a bug class where an attribute that is supposed to be randomly assigned is instead computed in the very same transaction that a user submits, so a user who controls the calling contract can simply revert and retry until the outcome is favorable, at negligible cost. Obyte's AA (Autonomous Agent) platform has a functionally equivalent weakness: the `light/dry_run_aa` network command lets any client fully simulate an AA trigger — including any oscript-computed "randomness" such as `number_from_seed()` — without spending anything or committing a unit to the DAG. Because the simulation uses attacker-supplied `trigger.data`/`trigger.outputs` and reads real, already-stable AA state, a trigger sender can iterate offline/via RPC over candidate trigger payloads until the simulated response produces the desired result (e.g. rare NFT-like asset issuance, favorable lottery payout, favorable price/rate), and only then broadcast the real unit with that exact payload. This reproduces the "mint with desired attributes by reverting" pattern without needing any special contract-wallet trick, because the whole "transaction" can be rehearsed for free before it is ever posted.

### Finding Description
`light/dry_run_aa` is handled in `network.js` and simply validates the trigger object and forwards it to `aa_composer.dryRunPrimaryAATrigger`: [1](#0-0) 

`dryRunPrimaryAATrigger` executes the AA's real bytecode/oscript against the current on-chain state (real state vars, real balances) inside a DB transaction that is always rolled back, and reports the exact `arrResponses` (bounced or not, response vars, outputs, updated state vars) that a real execution would produce: [2](#0-1) 

This is exercised by the test suite, which shows the dry run returning full, deterministic response details including response vars and outputs identical to what a live trigger would produce: [3](#0-2) 

Many AAs implement pseudo-randomness for things like loot boxes, lotteries, or randomly-weighted issuance using the `number_from_seed` oscript function, which deterministically derives a number in `[min,max]` from a caller-suppliable seed via `sha256`: [4](#0-3) 

Because `trigger.data` (and other trigger contents) are entirely chosen by the sender before the trigger is ever posted, and because `number_from_seed` (or any other seed built from `trigger.data`, current `mci`, state vars, etc.) is fully deterministic given those inputs, an unprivileged AA trigger sender can:
1. Freely call `light/dry_run_aa` with many candidate `trigger.data`/`trigger.outputs` payloads (or vary an off-chain seed value included in the trigger),
2. Inspect the simulated `response`, `updatedStateVars`, and output messages for each candidate, and
3. Only broadcast the one real unit whose trigger content is known, in advance and with certainty, to yield the desired "random" attribute/output.

This mirrors the AI Arena root cause exactly: the "random" value is fixed within the same call/trigger that also produces the final effect, so anyone able to inspect the result before committing to it can force the outcome. In Obyte's case the inspection channel is not a revert-catching wrapper contract, but the built-in `light/dry_run_aa`/`dryRunPrimaryAATrigger` simulation path, which is even cheaper (no gas, no unit ever created) than the EVM revert-retry trick.

### Impact Explanation
Any AA that assigns value-bearing, pseudo-random outcomes (rarity tiers of an issued asset, lottery/loot-box payouts, randomly-weighted distribution of bonus tokens, price-impacting randomness, etc.) using a seed derived from attacker-controlled trigger content combined with public, readable state is vulnerable to full outcome selection with zero cost and zero on-chain footprint for failed attempts. This lets an attacker systematically win the best-case outcome every time, draining funds/assets meant to be fairly distributed among many participants — a direct AA fund-loss/inflation-of-favorable-outcomes impact, matching the Medium severity of the referenced finding.

### Likelihood Explanation
`light/dry_run_aa` is a documented, always-available RPC exposed to any peer (light or full) with no rate limiting beyond generic node throughput, and `number_from_seed` is a commonly recommended primitive for implementing on-chain randomness in AAs. Any AA author who feeds `number_from_seed` (or similar sha256-based derivations) with data available to/chosen by the trigger sender (trigger.data, trigger outputs, or public state) is directly exposed. This is a systemic risk to the AA ecosystem rather than a one-off implementation bug, so likelihood is high wherever such a pattern is used.

### Recommendation
- Document prominently (and enforce via linting/best-practice guides) that any randomness seed used inside an AA must incorporate data that is *not* known or fully controllable by the trigger sender at trigger-composition time and cannot be freely iterated via `light/dry_run_aa` — e.g., derive it from the eventual `response_unit` hash, from a future stable MC unit not yet known when the trigger is composed, or from an oracle/data feed value not yet published.
- Consider having `dryRunPrimaryAATrigger`/`light/dry_run_aa` explicitly flag or restrict simulation of AAs that use `number_from_seed` with sender-controlled seeds, or watermark dry-run results so state-changing "lottery" AAs cannot be trivially rehearsed this way.
- Encourage a two-step commit/reveal design for AAs that need on-chain randomness: request in one trigger, resolve the random outcome in a later trigger/response once inputs unknown to the sender (e.g., future block/unit hash) are available.

### Proof of Concept
Given an AA such as:
```
{
  messages: [{
    app: 'state',
    state: `{
      $r = number_from_seed(trigger.data.seed, 1, 100);
      var['prize'] = $r;
    }`
  }]
}
```
An attacker can:
1. Call `light/dry_run_aa` repeatedly with `trigger.data = {seed: "attempt1"}`, `{seed: "attempt2"}`, ... (using `aa_composer.dryRunPrimaryAATrigger`, reachable through the `light/dry_run_aa` network command at [1](#0-0)  and [2](#0-1) ), observing `arrResponses[0].updatedStateVars[address].prize.value` for each candidate seed, at no cost since every dry run is rolled back.
2. Once a seed yielding `prize == 100` (best case) is found, broadcast the real trigger unit with `trigger.data = {seed: "attemptN"}`, guaranteeing the top prize deterministically instead of the intended 1/100 chance.

### Citations

**File:** network.js (L3939-3963)
```javascript
		case 'light/dry_run_aa':
			if (!params)
				return sendErrorResponse(ws, tag, "no params in light/dry_run_aa");
			if (!ValidationUtils.isValidAddress(params.address))
				return sendErrorResponse(ws, tag, "address not valid");
		
			storage.readAADefinition(db, params.address, null, function (arrDefinition) {
				if (!arrDefinition)
					return sendErrorResponse(ws, tag, "not an AA");
				aa_composer.validateAATriggerObject(params.trigger, function(error){
					if (error)
						return sendErrorResponse(ws, tag, error);
					aa_composer.dryRunPrimaryAATrigger(params.trigger, params.address, arrDefinition, function (arrResponses) {
						if (constants.COUNT_WITNESSES === 1) { // the temp unit might have rebuilt the MC
							db.executeInTransaction(function (conn, onDone) {
								storage.resetMemory(conn, onDone);
							});
						}
						if (ws.library_version === '0.4.2' && arrResponses.length === 1 && arrResponses[0].bounced && typeof arrResponses[0].response.error === 'object')
							arrResponses[0].response.error = arrResponses[0].response.error.message;
						sendResponse(ws, tag, arrResponses);
					});
				})
			});
			break;
```

**File:** aa_composer.js (L272-306)
```javascript
function dryRunPrimaryAATrigger(trigger, address, arrDefinition, onDone) {
	if (!onDone)
		return new Promise(resolve => dryRunPrimaryAATrigger(trigger, address, arrDefinition, resolve));
	console.log('dry run', address, trigger);
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = conf.bLight ? lightBatch : kvstore.batch();
			readLastStableMcUnit(conn, function (mci, objMcUnit) {
				trigger.unit = constants.GENESIS_UNIT; // objMcUnit.unit; // might cause duplicate trigger_unit in aa_triggers if objMcUnit is already a real trigger
				if (!trigger.address)
					trigger.address = objMcUnit.authors[0].address;
				trigger.initial_address = trigger.address;
				trigger.initial_unit = trigger.unit;
				var fPrepare = function (cb) {
					insertFakeOutputsIntoMcUnit(conn, objMcUnit, trigger.outputs, address, cb);
				};
				fPrepare(function () {
					var arrResponses = [];
					handleTrigger({
						bDryRun: true, // suppress events for a unit that will be rolled back
						conn, batch, trigger, params: {}, stateVars: {}, arrDefinition, address, mci, objMcUnit, bSecondary: false, arrResponses,
						onDone: function () {
							revertResponsesInCaches(arrResponses);
							batch.clear();
							conn.query("ROLLBACK", function () {
								conn.release();
								onDone(arrResponses);
							});
						},
					});
				});
			});
		});
	});
}
```

**File:** test/aa_composer.test.js (L79-118)
```javascript
test.cb.serial('AA with response vars', t => {
	var trigger = { outputs: { base: 40000 }, data: { x: 333 } };
	var aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		doc_url: 'https://myapp.com/description.json',
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					init: "{response['received_amount'] = trigger.output[[asset=base]];}",
					outputs: [
						{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 2000}"}
					]
				}
			}
		]
	}];

	validateAA(aa, async err => {
		t.deepEqual(err, null);

		var address = objectHash.getChash160(aa);
		await addAA(aa);
		
		aa_composer.dryRunPrimaryAATrigger(trigger, address, aa, (arrResponses) => {
			t.deepEqual(arrResponses.length, 1);
			t.deepEqual(arrResponses[0].bounced, false);
			t.deepEqual(arrResponses[0].response.responseVars.received_amount, 40000);
			t.deepEqual(arrResponses[0].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === trigger.address); }).amount, 38000);
			fixCache();
			t.deepEqual(storage.assocUnstableUnits, old_cache.assocUnstableUnits);
			t.deepEqual(storage.assocStableUnits, old_cache.assocStableUnits);
			t.deepEqual(storage.assocUnstableMessages, old_cache.assocUnstableMessages);
			t.deepEqual(storage.assocBestChildren, old_cache.assocBestChildren);
			t.deepEqual(storage.assocStableUnitsByMci, old_cache.assocStableUnitsByMci);
			t.end();
		});
	});
});
```

**File:** formula/evaluation.js (L1872-1919)
```javascript
			case 'number_from_seed':
				var evaluated_params = [];
				async.eachSeries(
					arr[1],
					function (param, cb2) {
						evaluate(param, function (res) {
							if (fatal_error)
								return cb2(fatal_error);
							if (res instanceof wrappedObject)
								res = true;
							if (!isValidValue(res))
								return setFatalError("invalid value in sha256: " + res, { arr }, undefined, cb2);
							if (isFiniteDecimal(res))
								res = toDoubleRange(res);
							evaluated_params.push(res);
							cb2();
						});
					},
					function (err) {
						if (err)
							return cb(false);
						var seed = evaluated_params[0];
						var hash = crypto.createHash("sha256").update(seed.toString(), "utf8").digest("hex");
						var head = hash.substr(0, 16);
						var nominator = new Decimal("0x" + head);
						var denominator = new Decimal("0x1" + "0".repeat(16));
						var num = nominator.div(denominator); // float from 0 to 1
						if (evaluated_params.length === 1)
							return cb(num);
						var min = dec0;
						var max;
						if (evaluated_params.length === 2)
							max = evaluated_params[1];
						else {
							min = evaluated_params[1];
							max = evaluated_params[2];
						}
						if (!isFiniteDecimal(min) || !isFiniteDecimal(max))
							return setFatalError("min and max must be numbers", { arr }, false, cb);
						if (!min.isInteger() || !max.isInteger())
							return setFatalError("min and max must be integers", { arr }, false, cb);
						if (!max.gt(min))
							return setFatalError("max must be greater than min", { arr }, false, cb);
						var len = max.minus(min).plus(1);
						num = num.times(len).floor().plus(min);
						cb(num);
					}
				);
```
