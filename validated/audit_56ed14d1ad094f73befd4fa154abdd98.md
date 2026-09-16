### Title
Predictable/attacker-computable `number_from_seed()` outcomes exploitable via free `light/dry_run_aa` simulation - ([File: formula/evaluation.js], [File: network.js], [File: aa_composer.js])

### Summary
The Obyte external report describes an operational failure to preserve the fairness seed of a gambling backend, breaking the guarantee that game outcomes were unpredictable/unverifiable to any party in advance. The analogous, ocore-reachable bug class is that AA-based gambling/lottery contracts that use the built-in `number_from_seed()` oscript function are fully deterministic, and ocore additionally exposes a free, unauthenticated `light/dry_run_aa` network command that lets any unprivileged client locally simulate an AA response — including its `number_from_seed()`-derived "random" outcome — for arbitrary trigger content, with no unit posted, no fee paid, and no commitment. This lets an attacker precompute the exact random result for many candidate trigger payloads and post only the unit that produces the favorable/winning outcome, defeating the fairness assumption the AA author relies on and draining the AA's fund reserve.

### Finding Description
`number_from_seed` in `formula/evaluation.js` is a pure, deterministic function of its arguments: it hashes the seed with SHA-256 and maps the digest to a number/range. [1](#0-0) 

There is no protocol-level mechanism forcing the seed to depend on something unknowable to the trigger sender at trigger-composition time (e.g., a not-yet-revealed oracle value or a future MC unit hash) — the value is whatever expression the AA author's oscript passes in, and AA authors commonly build it from data under the trigger sender's control (`trigger.data`, `trigger.unit`, `params`, etc.) combined with public state.

Crucially, ocore provides the `light/dry_run_aa` network request, reachable by any peer (including light clients) with no authentication and no payment, which fully executes `aa_composer.dryRunPrimaryAATrigger` for an attacker-supplied `trigger` object against a real, already-deployed AA definition, and returns the complete simulated response: [2](#0-1) 

`dryRunPrimaryAATrigger` runs the exact same `handleTrigger` code path used for real triggers, computing state changes and the resulting response unit, then rolls back the DB transaction — it costs the attacker nothing and leaves no trace on-chain: [3](#0-2) 

Because AA execution (including `number_from_seed`) is fully deterministic given the trigger content and current stable MC state, an attacker can iterate `light/dry_run_aa` requests with different candidate `trigger.data` payloads until the simulated response shows a favorable "random" draw, and only then submit that exact trigger as a real unit, guaranteeing wins against the AA's intended probability distribution.

### Impact Explanation
Any gambling/lottery-style AA (e.g., a poker/coinflip/lottery AA) that relies on `number_from_seed()` for outcome determination can be repeatedly and reliably drained by an attacker who free-simulates candidate triggers via `light/dry_run_aa` before committing funds, because the "randomness" is not secret from, and is fully reproducible by, the party who controls the trigger content. This is a concrete AA fund-loss vector, matching the report's underlying bug class (broken fairness/seed guarantees) but manifesting in ocore as a protocol-level design/exposure issue rather than an operator database mistake.

### Likelihood Explanation
Likelihood is high for any deployed AA using `number_from_seed` with attacker-influenceable or otherwise pre-computable inputs: `light/dry_run_aa` requires no special privileges, no unit posting, and no fees, so the attack is cheap and fully automatable (brute force many trigger variants offline/via dry-run until a winning outcome is found, then submit that specific unit).

### Recommendation
- Document and strongly discourage using `number_from_seed()` alone for fairness-critical AAs; require combining it with values that are unknowable to the trigger sender at composition time (e.g., a future oracle data feed value or a not-yet-existing MC unit hash) so pre-simulation cannot reveal the outcome before the deciding fact is fixed.
- Consider restricting or rate-limiting `light/dry_run_aa` (in `network.js`) for triggers referencing gambling-sensitive AAs, or clearly flag in the wiki/oscript docs that `dry_run_aa` allows perfect outcome prediction for any deterministic AA logic including `number_from_seed`.
- Provide a safer primitive for AA fairness (e.g., a commit-reveal pattern building on data feeds/MCI that only become fixed after the trigger unit is stable) and recommend it over raw `number_from_seed`.

### Proof of Concept
1. Deploy (or target) an AA that computes an outcome via `number_from_seed(trigger.data.nonce)` or similar, paying out from AA reserve on a "win".
2. Attacker locally calls `light/dry_run_aa` with `params.trigger = { address: attacker_address, data: { nonce: N }, outputs: {...} }` for many values of `N` (or other attacker-controlled trigger fields), inspecting `arrResponses[0].objResponseUnit` / `updatedStateVars` for the simulated payout — see handler at `network.js:3939-3961` and execution at `aa_composer.js:272-306`.
3. Once a value of `N` producing a winning `number_from_seed` result is found (no cost, no on-chain footprint), the attacker composes and posts the real unit with that exact `trigger.data`, guaranteeing a win and draining the AA's balance repeatedly.

### Citations

**File:** formula/evaluation.js (L1872-1900)
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
```

**File:** network.js (L3939-3961)
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
