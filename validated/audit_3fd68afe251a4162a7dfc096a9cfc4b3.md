### Title
Unchecked base_aa nesting in AA-generated definitions causes infinite trigger redirection / crash - (File: aa_composer.js)

### Summary
The Linux `objagg` bug fixed in CVE‑2024‑43846 exists because nesting of aggregated objects is checked on one code path (normal aggregation) but not on another (hint-based aggregation), and the unchecked assumption "nesting cannot happen" eventually causes a general protection fault. Ocore has the same structural pattern in its Autonomous Agent (AA) "parameterized AA" (`base_aa`) mechanism: the invariant "a `base_aa` must point to a *regular* AA, not another parameterized AA" is enforced on the path where a user posts a `definition` message directly in a unit, but it is **not** enforced on the path where an AA dynamically generates a new AA's definition at trigger time. The runtime trigger-redirection code in `aa_composer.js` blindly trusts this invariant and recurses without any nesting/depth check.

### Finding Description
When a plain unit defines a new AA via an inline `definition` message, `validateInlinePayload` explicitly checks that if the new AA is parameterized (`template.base_aa` set), the referenced `base_aa` must itself be a *regular* AA (i.e. have a `messages` field, not another `base_aa`): [1](#0-0) 

`aa_validation.validateAADefinition` itself only checks that `base_aa` is a syntactically valid address and that `params` is well-formed — it never inspects what the target AA actually is: [2](#0-1) 

However, an AA can also generate a brand-new AA definition dynamically at trigger-execution time (a documented and tested feature — see `test/aa_composer.test.js` "AA with generated definition of new AA"), and this generated payload is written directly via `storage.insertAADefinitions` from `writer.js`, never passing through `validateInlinePayload`'s "base AA must be a regular AA" check: [3](#0-2) [4](#0-3) 

`insertAADefinitions` stores whatever `base_aa` string is supplied with no verification that it refers to a regular (non-parameterized) AA, and no verification that the referenced address even exists yet: [5](#0-4) 

At trigger-execution time, `handleTrigger` in `aa_composer.js` unconditionally trusts the "no nesting" invariant: if the definition has `base_aa`, it fetches the base definition and recurses into `handleTrigger` again with the fetched definition, without ever checking that the fetched definition is a regular AA (i.e., without checking that `arrBaseDefinition[1].messages` exists and `arrBaseDefinition[1].base_aa` does not): [6](#0-5) 

Because content-addressed AA addresses are `chash160` of the definition object, an attacker-authored "factory" AA (analogous to the test at `test/aa_composer.test.js:922-1011` that already demonstrates dynamic AA creation) can precompute two addresses `A` and `B` and issue two `definition` messages such that `A.base_aa = B` and `B.base_aa = A`, or more simply a long chain of N parameterized AAs each pointing to the previous parameterized AA. None of this is rejected because the only place that rejects `base_aa → parameterized AA` nesting (`validation.js:1774-1779`) is not invoked for AA-generated definitions.

### Impact Explanation
Once such a nested/cyclic chain of parameterized AAs is registered, any subsequent trigger sent to one of these addresses causes `handleTrigger` to redirect through `base_aa` links with no depth limit — unlike other recursive evaluators in the codebase (`definition.js`'s `evaluate`, which is bounded by `MAX_COMPLEXITY`, and `formula/validation.js`'s `evaluate`, which is bounded by `depth > 100`), there is no equivalent guard here: [7](#0-6) 

For a genuine cycle this becomes unbounded recursion while processing the triggering unit. Depending on whether `storage.readAADefinition` resolves synchronously from an in-process cache (as several other `storage.js` lookup functions do, e.g. `readUnitProps`'s `assocStableUnits`/`assocUnstableUnits` fast paths) or asynchronously via a DB query, this results in either:
- an unbounded synchronous call stack growth (`RangeError: Maximum call stack size exceeded`), crashing the node process while handling the AA trigger, or
- an infinite non-terminating redirection loop that never invokes `onDone`, permanently stalling processing of that trigger/response chain.

Either way, every full node that receives the triggering unit and attempts to execute/verify the AA response must independently trigger the same infinite recursion, so the unit can never be finalized network-wide — matching the "network unable to confirm new units" / node-crash impact class, analogous to the kernel general-protection-fault outcome of the reported CVE.

### Likelihood Explanation
The attack is reachable by any unprivileged party: it only requires (1) deploying an ordinary "factory" AA whose init/state code composes `['autonomous agent', {base_aa: ..., params: ...}]` objects (a documented, already-tested capability) and (2) sending a small payment/trigger to the resulting addresses — both are basic operations any unit poster can perform. No privileged, hub, or peer-manipulation capability is required.

### Recommendation
Enforce the "base_aa must reference a regular (non-parameterized) AA" invariant in the AA-generated-definition path (`storage.insertAADefinitions`, or before it in `writer.js`) the same way `validateInlinePayload` enforces it for user-posted definitions, and additionally add a defensive depth/cycle check inside `handleTrigger`'s `template.base_aa` branch in `aa_composer.js` so that redirection cannot recurse beyond one level regardless of how the definition was created.

### Proof of Concept
1. Deploy `RegularAA` (has `messages`).
2. Deploy `FactoryAA` whose trigger logic computes, in order, in a single response:
   - `defB = ['autonomous agent', { base_aa: <precomputed A_address>, params: {p:1} }]`, compute `B_address = chash160(defB)`.
   - `defA = ['autonomous agent', { base_aa: B_address, params: {p:1} }]`, compute `A_address = chash160(defA)` (must match the address precomputed in step 1 — achievable by trying param combinations, or simpler: build an N-level linear chain instead of a true cycle to avoid the pre-image requirement, e.g. `AA_1.base_aa = AA_0`, `AA_2.base_aa = AA_1`, … `AA_N.base_aa = AA_{N-1}`, with `AA_0` legitimately regular — this is trivially constructible since each level's address is computed only after the previous is emitted, all within one or a few trigger responses).
   - Emit both/all as `definition` messages from `FactoryAA`.
3. Once these unconfirmed AA definitions become active AAs (per `insertAADefinitions`), send a payment to the last AA in the chain (`AA_N` or `A`).
4. `handleTrigger` recurses through `base_aa` redirections with no nesting check (`aa_composer.js:433-445`); for the two-node cyclic variant this never terminates, crashing or hanging every node that processes the trigger.

### Citations

**File:** validation.js (L1770-1779)
```javascript
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
```

**File:** aa_validation.js (L734-744)
```javascript
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
```

**File:** writer.js (L620-629)
```javascript
							if (objValidationState.bAA) {
								if (!objValidationState.initial_trigger_mci)
									throw Error("no initial_trigger_mci");
								var arrAADefinitionPayloads = objUnit.messages.filter(function (message) { return (message.app === 'definition'); }).map(function (message) { return message.payload; });
								if (arrAADefinitionPayloads.length > 0) {
									arrOps.push(function (cb) {
										console.log("inserting new AAs defined by an AA after adding " + objUnit.unit);
										storage.insertAADefinitions(conn, arrAADefinitionPayloads, objUnit.unit, objValidationState.initial_trigger_mci, objValidationState.initial_trigger_mci, true, cb, objValidationState.bDryRun);
									});
								}
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

**File:** aa_composer.js (L424-445)
```javascript
	if (arrDefinition[0] !== 'autonomous agent')
		throw Error('bad AA definition ' + arrDefinition);
	if (!trigger.initial_address)
		trigger.initial_address = trigger.address;
	if (!trigger.initial_unit)
		trigger.initial_unit = trigger.unit;
	var error_message = '';
	var responseVars = {};
	var template = arrDefinition[1];
	if (template.base_aa) { // parameterized AA
		if (params && Object.keys(params).length > 0)
			throw Error("unexpected params");
		storage.readAADefinition(conn, template.base_aa, mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + template.base_aa);
			console.log("redirecting to base AA " + template.base_aa + " with params " + JSON.stringify(template.params));
			trigger_opts.params = template.params;
			trigger_opts.arrDefinition = arrBaseDefinition;
			handleTrigger(trigger_opts);
		});
		return;
	}
```
