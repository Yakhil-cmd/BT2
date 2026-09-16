### Title
Free, side-effect-free `light/dry_run_aa` oracle lets attackers pre-compute gambling-AA outcomes before risking funds - (File: network.js, aa_composer.js)

### Summary
Obyte AAs implement pseudo-random outcomes with the deterministic `number_from_seed()` oscript function [1](#0-0) . Any peer/light client can call the `light/dry_run_aa` network command with an arbitrary, attacker-chosen `trigger` object (`address`, `data`, `outputs`) and receive the full simulated AA response - including any state-var/output values derived from `number_from_seed`/`response_unit` - without spending a single byte or leaving any on-chain trace [2](#0-1) . This gives an attacker a free, repeatable "what would happen if I bet with this exact data" oracle, exactly the capability the Dice3D/EOS.WIN attackers had to build with costly probing sub-accounts on-chain.

### Finding Description
`case 'light/dry_run_aa'` validates only structural well-formedness of the trigger via `validateAATriggerObject` (positive `outputs.base`, valid `address`, size limits) — it never requires the caller to actually own funds, sign a real unit, or pay any fee [3](#0-2) . It then calls `dryRunPrimaryAATrigger`, which runs the AA's real bytecode with the caller-supplied `trigger.data`/`trigger.outputs` against the real, current stable state variables and rolls back all DB/kvstore writes afterward [4](#0-3) .

Because `trigger.address`, `trigger.data`, and `trigger.outputs` are fully attacker controlled and identical in a dry run and in a genuine future trigger unit, any AA whose payout logic is a deterministic function of these caller-supplied fields (a common pattern for gambling AAs that take a client-chosen “guess”/“seed”/bet parameter and feed it into `number_from_seed()` together with public state) can be probed for free: the attacker repeatedly calls `light/dry_run_aa` with different candidate `data`/`outputs`, observes the exact resulting payout/state, and only ever broadcasts (and pays for) the one real trigger unit that is guaranteed to win. This removes all the cost/detectability the attacker previously incurred with "front feint" probing transactions in the reported EOS.WIN/Dice3D pattern — here the probing costs nothing and produces zero footprint, then the winning bet is submitted once, deterministically, against the AA's real balance.

This differs from the legitimate purpose of `light/dry_run_aa` (previewing a transaction's effect, e.g. for wallets) in that no rate limiting, ownership check, or cost is imposed to prevent using it as a brute-force outcome-prediction oracle for randomness that a naive gambling AA author might reasonably (but incorrectly) assume is unpredictable before broadcast.

### Impact Explanation
Any Obyte gambling/lottery-style AA that derives its payout from `number_from_seed()` (or any other formula) applied to trigger-supplied data can be drained deterministically: the attacker guarantees a win on every real bet they place, extracting the AA's balance similarly to the reported 10,569 EOS loss at Dice3D. This is a fund-loss scenario for any AA relying on this pattern, reachable purely by an unprivileged trigger sender using a standard hub RPC call, with no code changes or privileged access required.

### Likelihood Explanation
Likelihood is Medium: the underlying oscript primitives (`number_from_seed`) are officially documented as an in-protocol source of "randomness" for AAs, and the `light/dry_run_aa` command is a standard, publicly documented light-client API served by every hub/full node without authentication or funds requirement [2](#0-1) . Exploitation requires only that a deployed AA's randomness inputs be fully composed of caller-controlled `trigger` fields (a natural and common design for "you choose the seed, we combine it with something" games) — a design mistake plausible for any third-party gambling AA built on top of ocore's documented primitives, matching precisely the historical class of "predict-then-bet" attacks referenced in the report.

### Recommendation
- Document explicitly (and warn in the oscript/AA guide) that `number_from_seed`/any trigger-derived value must never be seeded solely from data known to the trigger's own author (trigger.data, trigger.address, trigger.outputs) before broadcast, since it can be fully simulated via `light/dry_run_aa`.
- Consider hardening `light/dry_run_aa` so it cannot be used as an unlimited, free oracle for probing arbitrary trigger content: e.g., rate-limit dry-run requests per peer/IP, or require the caller to reference the real balances of a genuinely-owned address for the trigger's payer field.
- For any AA that needs unpredictable-until-response randomness, recommend mixing in `response_unit`/`mc_unit`/state variables that are not reproducible identically between a `dryRunPrimaryAATrigger` call (which uses `constants.GENESIS_UNIT`/fake parents/last-stable MC unit, see `aa_composer.js:280`) and the eventual real stabilized trigger unit, so dry-run results diverge from real execution.

### Proof of Concept
1. Attacker identifies a gambling AA address `G` whose messages compute e.g. `var['win'] = number_from_seed(trigger.data.seed) < 0.5` and pays out based on `win`.
2. Attacker repeatedly sends `{"command":"light/dry_run_aa","params":{"address":"G","trigger":{"address":"<attacker_addr>","data":{"seed":"<candidate>"},"outputs":{"base":100000}}}}` to any hub, varying `data.seed`, until a response shows a winning payout [2](#0-1) .
3. Because `dryRunPrimaryAATrigger` executes the AA's real logic against real, current stable state with the exact same caller-supplied `trigger.data`/`outputs` [4](#0-3)  and rolls back with no cost or trace, the attacker learns the winning `seed` for free.
4. Attacker then composes and broadcasts a single real unit with `data.seed` set to the confirmed winning value, guaranteeing the AA pays out the maximum bet every time.

### Citations

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

**File:** aa_composer.js (L224-270)
```javascript
function validateAATriggerObject(trigger, handle) {
	if (!ValidationUtils.isNonemptyObject(trigger))
		return handle("no trigger");
	if (!ValidationUtils.isNonemptyObject(trigger.outputs))
		return handle("no trigger outputs");
	if (!ValidationUtils.isValidAddress(trigger.address))
		return handle("bad trigger address");
	if ("max_aa_responses" in trigger && (!ValidationUtils.isNonnegativeInteger(trigger.max_aa_responses) || trigger.max_aa_responses > constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER))
		return handle("bad trigger max_aa_responses");
	if (ValidationUtils.hasFieldsExcept(trigger, ["address", "data", "outputs", "max_aa_responses"])) // initial_address and initial_unit cannot be separately set in a primary trigger
		return handle("unexpected trigger fields");
	if (string_utils.isTooBigObj(trigger, { lengthLimit: 10e3 }))
		return handle("trigger data is too big");
	try {
		if (trigger.data)
			string_utils.getJsonSourceString(trigger.data);
	}
	catch (e) {
		return handle("invalid trigger data: " + e);
	}
	var arrAssets = Object.keys(trigger.outputs).filter(function(asset) {return asset !== 'base'});
	if (arrAssets.length >= constants.MAX_MESSAGES_PER_UNIT)
		return handle("too many assets");
	if (!ValidationUtils.isPositiveInteger(trigger.outputs.base))
		return handle("no base payment");
	if (!arrAssets.every(function(asset){return ValidationUtils.isPositiveInteger(trigger.outputs[asset])}))
		return handle("invalid output amount")

	function checkAddressIsNotAA() {
		db.query("SELECT 1 FROM aa_addresses WHERE address=?", [trigger.address], rows => {
			if (rows.length)
				return handle("trigger address must not be an AA");
			else
				return handle();
		});
	}

	if (arrAssets.length === 0)
		return checkAddressIsNotAA();
	// we have to check that assets exist otherwise foreign key constraint would fail when inserting fake outputs
	db.query("SELECT 1 FROM assets WHERE unit IN (?)", [arrAssets], function(rows) {
		if (rows.length !== arrAssets.length)
			return handle("unknown asset");
		else
			checkAddressIsNotAA();
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
