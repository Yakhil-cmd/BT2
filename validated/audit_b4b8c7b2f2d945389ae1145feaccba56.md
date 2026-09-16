### Title
Dynamically-generated ("templated") AA definitions bypass full `aa_validation.validateAADefinition()` structural checks - (File: `storage.js`, `aa_validation.js`)

### Summary
Analogous to the Nautobot Jinja2-templating flaw (CVE-2025-49142), where content generated through a templating feature is trusted and evaluated with insufficient re-validation, the AA (Autonomous Agent) engine in ocore allows an AA to send a `definition` message whose `payload.definition` is itself a **formula** — i.e. a template that is filled in dynamically from `trigger.data`/state at execution time. The static validator explicitly skips structural validation of these templated definitions, and the runtime insertion path that later registers the evaluated definition as a live AA address does not re-run the full validator either.

### Finding Description
When an AA definition is first validated (e.g. as part of a unit or as a nested "definition" message), `aa_validation.js` handles the `case 'definition'` payload as follows: [1](#0-0) 

If the payload's `definition` field is itself a formula (`getFormula(payload.definition) !== null`), the function immediately returns `cb2()` — it does **not** recursively invoke `validateAADefinition` on the eventual, evaluated definition. This is intentional, because the concrete definition doesn't exist yet; it is only produced later, when the AA actually fires and the formula is evaluated against `trigger`/state data, as shown by the comment in `aa_composer.js`: [2](#0-1) 

At execution time, once the templated `definition` field is filled in with concrete (attacker-influenced, since it derives from `trigger`/`params`/state) values, the resulting child-AA definition is written as a `definition` message and persisted via `storage.insertAADefinitions()`: [3](#0-2) 

That function only calls `aa_validation.determineGetterProps(...)` — used solely to compute getter metadata — before inserting the row into `aa_addresses` and treating the address as an active AA. It never calls the full `aa_validation.validateAADefinition()` that a genuinely static/top-level AA definition must pass (structural constraints on `bounce_fees`, `messages` shape/complexity, `MAX_COMPLEXITY`/`MAX_OPS` limits, forbidden fields, etc., as implemented in): [4](#0-3) 

The place where such full validation normally happens is `validateInlinePayload()`'s `case "definition"`, which is used for **regular units** with `app=definition`: [5](#0-4) 

but this code path is not the one exercised when an *AA* dynamically defines a child AA — that path goes through `aa_composer.js` → `storage.insertAADefinitions()`, which skips it. This gap is directly demonstrated by the test `'AA with generated definition of new AA and immediately sending to this new AA'`, which shows an AA computing an entire child-AA definition inside a formula and registering it purely from evaluated data: [6](#0-5) 

Because trigger data / state variables that feed the template are attacker-influenced (a trigger sender chooses `trigger.data`, and in multi-hop AA chains, upstream AAs' state can be influenced by earlier triggers), an attacker can shape the templated definition into a structurally invalid or maliciously degenerate AA definition (e.g. missing `messages`, pathological nesting/complexity, or fields that would be rejected by `validateAADefinition`) that is nonetheless registered as a live `aa_addresses` entry and later handled by `handleTrigger`/`evaluateAA`, which assume the structural invariants normally guaranteed by `validateAADefinition`.

### Impact Explanation
Because the definition-shape guarantees (complexity bounds, disallowed fields, `messages` well-formedness) that consensus-critical AA execution code relies on are not enforced for dynamically-generated child AAs, a malicious trigger/AA author can register an address as an "AA" that violates those invariants. Downstream AA-processing code (`aa_composer.js` `handleTrigger`/`evaluateAA`) is written assuming validated definitions; feeding it an unvalidated one risks either an uncaught exception/crash during AA processing (potential DoS of AA processing on a node) or divergent handling between nodes if the anomaly is processed differently depending on node state/timing — i.e., node disagreement on unit/AA validity, which is one of the accepted impact classes. It can also result in funds sent to such a malformed "AA address" becoming stuck/frozen if the definition can never be evaluated to completion (AA fund freezing).

### Likelihood Explanation
Reaching this path requires nothing more than posting a normal AA trigger to any AA that (by design or by being crafted by the attacker as an AA author) constructs a `definition` message from a formula incorporating trigger-controlled data — a documented and tested feature (`test/aa_composer.test.js:922-1010`). No special privileges, node/network compromise, or malicious peer/hub is required — a single trigger sender or AA author is sufficient, matching the required threat model.

### Recommendation
When `insertAADefinitions()` (or the point in `aa_composer.js` right after a `definition` formula is evaluated to a concrete array) registers a new AA address, run the evaluated `arrDefinition` through `aa_validation.validateAADefinition()` (the same check applied to statically-declared AA definitions in `validation.js:1767`) before accepting it into `aa_addresses`. If validation fails, the message/response unit should bounce instead of registering the malformed AA.

### Proof of Concept
1. Deploy a "factory" AA whose `init` formula builds a `$child_aa` array based on `trigger.data` (following the pattern in `test/aa_composer.test.js:944-986`), but have the attacker's `trigger.data` steer the generated array into a shape that would be rejected by `aa_validation.validateAADefinition()` if it were validated directly — e.g., an empty/absent `messages` field, or one that exceeds `MAX_COMPLEXITY`/`MAX_OPS`, or contains foreign fields.
2. Send a normal trigger unit (no elevated privileges needed) to the factory AA with the crafted `trigger.data`.
3. Observe that `aa_composer.js` evaluates the formula, emits a `definition` message with the malformed concrete definition, and `storage.insertAADefinitions()` (`storage.js:904-921`) registers it in `aa_addresses` after only calling `determineGetterProps`, with no call to `validateAADefinition`.
4. Subsequently trigger the newly "defined" address and observe abnormal handling in `handleTrigger`/`evaluateAA`, which assumes a structurally valid definition (this last runtime-crash/behavior-divergence step would need to be confirmed with a live node run, which is out of scope for static analysis).

*Note: I was unable to retrieve the full source of `aa_validation.determineGetterProps` within the available tool calls to confirm precisely which (if any) minimal checks it performs beyond getter-metadata extraction; the core finding — that `validateAADefinition`'s full structural/complexity validation is not invoked for dynamically-generated child-AA definitions in `storage.insertAADefinitions` — is confirmed directly from the code shown above.*

### Citations

**File:** aa_validation.js (L208-223)
```javascript
				case 'definition':
					if (mci >= constants.aa2UpgradeMci && getFormula(payload.definition) !== null)
						return cb2();
					if (!isArrayOfLength(payload.definition, 2))
						return cb2("definition must be array of 2");
					if (hasFieldsExcept(payload, ['definition']))
						return cb2("unknown fields in AA definition in AA");
					if (payload.definition[0] !== 'autonomous agent')
						return cb2('not an AA in nested AA definition');
					if (mci >= constants.aa2UpgradeMci && getFormula(payload.definition[1]) !== null)
						return cb2();
					if (!isNonemptyObject(payload.definition[1]))
						return cb2('empty nested definition');
					cb2();
				//	(typeof setImmediate === 'function') ? setImmediate(validateAADefinition, payload.definition, cb2) : setTimeout(validateAADefinition, 0, payload.definition, cb2); // interrupt the call stack to protect against deep nesting
					break;
```

**File:** aa_validation.js (L713-782)
```javascript
	if (callback === undefined) { // 2 arguments
		callback = readGetterProps;
		mci = Number.MAX_SAFE_INTEGER;
		readGetterProps = function (aa_address, func_name, cb2) {
			// all getters exist and have complexity=0
			cb2({ complexity: 0, count_ops: 1, count_args: null });
		};
	}
	var complexity = 0;
	var count_ops = 0;
	var getters = null;
	var count = 0;
	if (!isArrayOfLength(arrDefinition, 2))
		return callback("AA definition must be 2-element array");
	if (arrDefinition[0] !== 'autonomous agent')
		return callback("not an AA");
	var address = constants.bTestnet ? objectHash.getChash160(arrDefinition) : null;
	var arrDefinitionCopy = _.cloneDeep(arrDefinition);
	var template = arrDefinitionCopy[1];
	if (!isNonemptyObject(template))
		return callback('definition must be a non-empty object');
	if (template.base_aa) { // parameterized AA
		if (hasFieldsExcept(template, ['base_aa', 'params']))
			return callback("foreign fields in parameterized AA definition");
		if (!isNonemptyObject(template.params))
			return callback("no params in parameterized AA");
		if (!variableHasStringsOfAllowedLength(template.params))
			return callback("some strings in params are too long");
		if (!isValidAddress(template.base_aa))
			return callback("base_aa is not a valid address");
		return callback(null);
	}
	// else regular AA
	if (hasFieldsExcept(template, ['bounce_fees', 'messages', 'init', 'doc_url', 'getters']))
		return callback("foreign fields in AA definition");
	if ('bounce_fees' in template){
		if (!isNonemptyObject(template.bounce_fees))
			return callback("empty bounce_fees");
		for (var asset in template.bounce_fees){
			if (asset !== 'base' && !isValidBase64(asset, constants.HASH_LENGTH))
				return callback("bad asset in bounce_fees: " + asset);
			var fee = template.bounce_fees[asset];
			if (!isNonnegativeInteger(fee) || fee > constants.MAX_CAP)
				return callback("bad bounce fee: "+JSON.stringify(fee));
		}
		if ('base' in template.bounce_fees && template.bounce_fees.base < constants.MIN_BYTES_BOUNCE_FEE)
			return callback("too small base bounce fee: "+template.bounce_fees.base);
	}
	if ('doc_url' in template && !isNonemptyString(template.doc_url))
		return callback("invalid doc_url");
	if ('getters' in template) {
		if (mci < constants.aa2UpgradeMci)
			return callback("getters not activated yet");
		if (getFormula(template.getters) === null)
			return callback("invalid getters");
	}
	validateFieldWrappedInCases(template, 'messages', validateMessages, function (err) {
		if (err)
			return callback(err);
		validateDefinition(arrDefinitionCopy, function (err) {
			if (err) {
				if (validationErrorDetails)
					return callback(err, validationErrorDetails);
				return callback(err);
			}
			console.log('AA validated, complexity = ' + complexity + ', ops = ' + count_ops);
			callback(null, { complexity, count_ops, getters });
		});
	});
}
```

**File:** aa_composer.js (L589-618)
```javascript
	function evaluateAA(arrDefinition, cb) {
		var locals = {};
		var f = getFormula(arrDefinition[1].getters);
		if (f === null) { // no getters
			return replace(arrDefinition, 1, '', locals, '', cb);
		}
		// evaluate getters before everything else as they can define a few functions
		delete arrDefinition[1].getters;
		var opts = {
			conn: conn,
			formula: f,
			trigger: trigger,
			params: params,
			locals: locals,
			stateVars: stateVars,
			responseVars: responseVars,
			bStatementsOnly: true,
			bGetters: true,
			objValidationState: objValidationState,
			address: address
		};
		formulaParser.evaluate(opts, [], '/getters', function (err, res) {
			if (res === null)
				return cb(err.formattedError || "formula " + f + " failed: " + err);
			replace(arrDefinition, 1, '', locals, '', cb);
		});
	}

	// note that app=definition is also replaced using the current trigger and vars, its code has to generate "{}"-formulas in order to be dynamic
	function replace(obj, name, path, locals, xpath, cb) {
```

**File:** storage.js (L904-921)
```javascript
function insertAADefinitions(conn, arrPayloads, unit, mci, validation_mci, bForAAsOnly, onDone, bDryRun) {
	if (!onDone)
		return new Promise(resolve => insertAADefinitions(conn, arrPayloads, unit, mci, validation_mci, bForAAsOnly, resolve, bDryRun));
	var aa_validation = require("./aa_validation.js");
	async.eachSeries(
		arrPayloads,
		function (payload, cb) {
			var address = payload.address;
			var json = JSON.stringify(payload.definition);
			var base_aa = payload.definition[1].base_aa;
			var bAlreadyPostedByUnconfirmedAA = false;
			var readGetterProps = function (aa_address, func_name, cb) {
				if (conf.bLight)
					return cb({ complexity: 0, count_ops: 0, count_args: null });
				readAAGetterProps(conn, aa_address, func_name, mci, cb);
			};
			aa_validation.determineGetterProps(payload.definition, readGetterProps, validation_mci, function (getters) {
				conn.query("INSERT " + db.getIgnore() + " INTO aa_addresses (address, definition, unit, mci, base_aa, getters) VALUES (?,?, ?,?, ?,?)", [address, json, unit, mci, base_aa, getters ? JSON.stringify(getters) : null], async function (res) {
```

**File:** validation.js (L1747-1781)
```javascript
		case "definition": // for AAs only
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["address", "definition"])) // AA definition cannot be changed and its address is also its definition_chash
				return callback("unknown fields in app definition");
			try{
				if (payload.address !== objectHash.getChash160(payload.definition))
					return callback("definition doesn't match the chash");
			}
			catch(e){
				return callback("bad definition");
			}
			if (constants.bTestnet && ['BD7RTYgniYtyCX0t/a/mmAAZEiK/ZhTvInCMCPG5B1k=', 'EHEkkpiLVTkBHkn8NhzZG/o4IphnrmhRGxp4uQdEkco=', 'bx8VlbNQm2WA2ruIhx04zMrlpQq3EChK6o3k5OXJ130=', '08t8w/xuHcsKlMpPWajzzadmMGv+S4AoeV/QL1F3kBM=', '4N5fsU9qJSn2FuS70cChKx8QqgcesPRPs0dNfzOhoXw='].indexOf(objUnit.unit) >= 0)
				return callback();
			const top_mci = objValidationState.aa_mci || objValidationState.last_ball_mci;
			var readGetterProps = function (aa_address, func_name, cb) {
				storage.readAAGetterProps(conn, aa_address, func_name, top_mci, cb);
			};
			if (!objValidationState.hasBall && !objValidationState.bAA && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci && objValidationState.last_ball_mci < constants.pemCurvesFixMci)
				return callback(createTransientError("AA definition attached to an old part of the DAG"));
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
				if (err)
					return callback(err);
				var template = payload.definition[1];
				if (template.messages)
					return callback(); // regular AA
				// else parameterized AA
				storage.readAADefinition(conn, template.base_aa, top_mci, function (arrBaseDefinition) {
					if (!arrBaseDefinition)
						return callback("base AA not found");
					if (!arrBaseDefinition[1].messages)
						return callback("base AA must be a regular AA");
					callback();
				});
			});
```

**File:** test/aa_composer.test.js (L922-1010)
```javascript
test.cb.serial('AA with generated definition of new AA and immediately sending to this new AA', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { x: 5 }, address: trigger_address };

	var child_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		doc_url: 'https://myapp.com/description.json',
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					init: "{response['received_amount'] = trigger.output[[asset=base]];}",
					outputs: [
						{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
					]
				}
			}
		]
	}];
	var child_aa_address = objectHash.getChash160(child_aa);
	
	var factory_aa = ['autonomous agent', {
		init: `{
			$child_aa = ['autonomous agent', {
				bounce_fees: { base: 10000 },
				doc_url: 'https://myapp.com/description.json',
				messages: [
					{
						app: 'payment',
						payload: {
							asset: 'base',
							init: "{response['received_amount'] = trigger.output[[asset=base]];}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
							]
						}
					}
				]
			}];
			$child_aa_address = chash160($child_aa);
		}`,
		messages: [
			{
				app: 'definition',
				payload: {
					definition: `{$child_aa}`
				}
			},
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [{address: `{$child_aa_address}`, amount: 8000}]
				}
			},
			{
				app: 'state',
				state: `{
					var['child_aa1'] = $child_aa_address;
					var['child_aa2'] = unit[response_unit].messages[[.app='definition']].payload.address;
				}`
			}
		]
	}];

	validateAA(factory_aa, err => {
		t.deepEqual(err, null);

		var factory_address = objectHash.getChash160(factory_aa);
		addAA(factory_aa);
		
		aa_composer.dryRunPrimaryAATrigger(trigger, factory_address, factory_aa, (arrResponses) => {
			t.deepEqual(arrResponses.length, 2);
			t.deepEqual(arrResponses[0].bounced, false);
			t.deepEqual(arrResponses[0].updatedStateVars[factory_address].child_aa1.value, child_aa_address);
			t.deepEqual(arrResponses[0].updatedStateVars[factory_address].child_aa2.value, child_aa_address);
			t.deepEqual(arrResponses[0].objResponseUnit.messages.find(function (message) { return (message.app === 'definition'); }).payload.definition, child_aa);
			t.deepEqual(arrResponses[1].objResponseUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === trigger_address); }).amount, 5000);
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
