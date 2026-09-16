### Title
Deterministic, sender-known randomness in oscript (`number_from_seed`/`trigger.unit`) lets an AA trigger sender freely simulate outcomes off-chain before posting, enabling guaranteed wins in randomness-dependent AAs - (File: `formula/evaluation.js`, `aa_composer.js`)

### Summary
The report's bug class is "unmitigated, retryable pseudo-randomness that lets the caller pick a favorable outcome" (mint-and-revert via `onERC721Received`, `msg.sender`/length-seeded DNA, best-of-rerolls). The ocore analog is stronger: an unprivileged AA trigger sender can compute the exact hash of a not-yet-broadcast unit (`trigger.unit`) and other trigger fields, feed them to `number_from_seed()` inside an AA's oscript, and use the platform's own trigger-simulation tooling (`estimatePrimaryAATrigger`/`dryRunPrimaryAATrigger`) to preview the AA's deterministic response *before* paying any fee or committing to the DAG at all. If the outcome is unfavorable, the sender simply discards the composed unit (never signs/broadcasts it) and recomputes with a different parent set/timestamp/message content to get a different `trigger.unit` hash, repeating until a favorable draw is found - a zero-cost, unlimited "revert and retry."

### Finding Description
`number_from_seed()` is oscript's canonical randomness primitive for AAs: [1](#0-0) 
It derives a number deterministically from a `sha256` of whatever value is passed as the seed - there is no external/oracle entropy involved.

Trigger fields such as `trigger.unit` and `trigger.address` are directly available to AA formulas and are commonly used as "unique per-call" seed material: [2](#0-1) 
`trigger.unit` is simply the hash of the unit that carries the trigger, and `trigger.address` is the first author's address - both are fully known to the sender at the moment they compose (sign) the unit, well before it is broadcast to the network or included in the DAG.

Critically, ocore ships built-in tooling that lets a wallet/trigger sender simulate an AA's response to a trigger *before* actually sending it: `estimatePrimaryAATrigger()` and `dryRunPrimaryAATrigger()` run `handleTrigger()` against a rolled-back DB transaction and return the AA's response/bounce outcome without persisting anything: [3](#0-2) [4](#0-3) 

Because the AA's behavior is fully deterministic given `trigger` and current state, and because the sender controls (or can iterate) the exact content that produces `trigger.unit`/`trigger.address`/`trigger.data`, an attacker can:
1. Compose a candidate trigger unit locally (choosing parents, timestamp, `data` message content, etc.), compute its hash.
2. Run it through `estimatePrimaryAATrigger`/`dryRunPrimaryAATrigger` (or just replicate the oscript evaluation locally) to see exactly what `number_from_seed(trigger.unit)` (or any seed built from `trigger.address`, `trigger.data`, etc.) will evaluate to, and thus what NFT/attribute/prize/loot the AA will assign.
3. If unfavorable, discard the unit (it costs nothing - it was never sent) and rebuild with different content to get a new hash/outcome.
4. Repeat until a favorable draw is obtained, then finally broadcast that exact unit.

This is a strictly more powerful version of the ai-arena bug class: in Ethereum the attacker at least pays gas and must use an on-chain revert hook (`onERC721Received`) to reject after learning the result mid-transaction; here the sender learns the result with zero cost and zero footprint before ever touching the network, because the "seed" is fully known/chosen by the sender and the platform explicitly provides pre-broadcast simulation.

### Impact Explanation
Any AA that uses `number_from_seed()` (or hashing/derivation) over sender-controlled/sender-predictable trigger data (`trigger.unit`, `trigger.address`, `trigger.data`, or values derivable purely from public state at composition time) to gate randomized value-bearing outcomes - lotteries, gachas/loot-boxes, randomized NFT-like asset attributes, prize draws, fee rebates, etc. - can be defeated deterministically. An attacker can guarantee winning outcomes (e.g., always drawing the jackpot, the rarest attribute, or the maximum payout), causing concrete fund loss to the AA (and, transitively, to honest counterparties funding it), which satisfies the "AA fund loss" impact bar for this class of finding.

### Likelihood Explanation
High for any AA design that follows the natural/idiomatic pattern of seeding `number_from_seed()` with `trigger.unit` or `trigger.address` (which are the most obviously "unique per call" fields exposed to oscript) instead of external unpredictable data (e.g., a data feed/oracle value unknown at composition time). No special privilege is needed - a normal, unprivileged trigger sender can perform the entire attack off-chain using standard wallet/simulation functionality (`estimatePrimaryAATrigger`) that ships with the codebase, at no monetary cost until the final, already-winning unit is submitted.

### Recommendation
- Do not treat `trigger.unit`, `trigger.address`, `trigger.data`, or any other value fully known to the trigger sender at composition time as a randomness seed for value-bearing outcomes in AA templates/documentation and sample AAs.
- Document explicitly (and warn via `formula/validation.js`/AA-definition validation, if feasible) that `number_from_seed()` combined with sender-controlled inputs is not safe randomness, and recommend commit-reveal or oracle/data-feed-based randomness (values unknown at unit-composition time, e.g. supplied later by a trusted/decentralized oracle AA) for any monetary-outcome logic.
- Consider restricting or flagging use of `trigger.unit`/`trigger.address` as direct/sole seed input to `number_from_seed` in AA static validation, or requiring the seed to combine with data unknown until stabilization (e.g., a committed value from a prior separate transaction/oracle) so that outcomes cannot be simulated ahead of broadcast.

### Proof of Concept
1. Deploy an AA whose oscript computes an outcome via `number_from_seed(trigger.unit, 1, 100)` (or `trigger.address`) to decide a prize/attribute, then pays out based on that outcome (a typical "gacha"/lottery AA pattern enabled by `number_from_seed`: see `formula/evaluation.js` lines 1872-1919 and its exposure via `trigger.unit`/`trigger.address` in `aa_composer.js` lines 375-397).
2. As an unprivileged trigger sender, compose (but do not broadcast) a trigger unit with chosen parents/timestamp/data, compute its resulting `trigger.unit` hash locally.
3. Call `estimatePrimaryAATrigger()` (`aa_composer.js` lines 152-213) or `dryRunPrimaryAATrigger()` (`aa_composer.js` lines 272-306) with that composed unit to get the AA's deterministic response/payout for that exact seed, with the DB transaction rolled back and no cost incurred.
4. If the simulated response is unfavorable, discard the candidate unit and rebuild with different content to obtain a different `trigger.unit`; repeat step 3.
5. Once a favorable simulated outcome is found, sign and broadcast that specific unit to the network, guaranteeing the desired randomized outcome from the AA and draining/exploiting its funds accordingly.

### Citations

**File:** formula/evaluation.js (L1872-1898)
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
```

**File:** aa_composer.js (L152-213)
```javascript
// estimates the effects of an AA trigger before it gets stable.
// stateVars and assocBalances are updated after the function returns.
// The estimation is not 100% accurate, e.g. storage_size is ignored, unit validation errors are not caught
function estimatePrimaryAATrigger(objUnit, address, stateVars, assocBalances, onDone) {
	if (!onDone)
		return new Promise(resolve => estimatePrimaryAATrigger(objUnit, address, stateVars, assocBalances, resolve));
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			storage.readAADefinition(conn, address, null, arrDefinition => {
				if (!arrDefinition)
					throw Error("AA not found: " + address)
				readLastUnit(conn, function (objMcUnit) {
					// rewrite timestamp in case our last unit is old (light or unsynced full)
					objMcUnit.timestamp = objUnit.timestamp || Math.round(Date.now() / 1000);
					if (objUnit.main_chain_index)
						objMcUnit.main_chain_index = objUnit.main_chain_index;
					var mci = objMcUnit.main_chain_index;
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					var trigger_opts = {
						bAir: true,
						conn,
						trigger,
						params: {},
						stateVars,
						assocBalances, // balances _before_ the trigger, not including the coins received in the trigger
						arrDefinition,
						address,
						mci,
						objMcUnit,
						arrResponses,
						onDone: function () {
							// remove the 'updated' flag for future triggers
							for (var aa in stateVars) {
								var addressVars = stateVars[aa];
								for (var var_name in addressVars) {
									var state = addressVars[var_name];
									if (state.updated) {
										delete state.updated;
										state.old_value = state.value;
										state.original_old_value = state.value;
									}
								}
							}
							conn.query("ROLLBACK", function () {
								conn.release();
								// copy updatedStateVars to all responses
								if (arrResponses.length > 1 && arrResponses[0].updatedStateVars)
									for (var i = 1; i < arrResponses.length; i++)
										arrResponses[i].updatedStateVars = arrResponses[0].updatedStateVars;
								onDone(arrResponses);
							});
						},
					}
					handleTrigger(trigger_opts);
				});
			});
		});
	});
}
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
