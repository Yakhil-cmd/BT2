### Title
Nested AA definitions created by another AA bypass full `validateAADefinition` validation, allowing malformed/unvalidated AAs to be registered and triggered - (File: aa_validation.js, storage.js, writer.js)

### Summary
When a human posts a `definition` message directly, `validation.js` runs the message payload through the full recursive validator `aa_validation.validateAADefinition` before the AA can ever be triggered. But when an *already‑validated AA* itself emits a `definition` message (a "nested"/AA‑created AA, e.g. a factory pattern), the nested definition is never subjected to that same full, deep validation before it is registered in `aa_addresses` and becomes triggerable. This mirrors the CVE‑2019‑14771 bug class: content that flows through an alternate, less‑scrutinized ingestion path ("uploaded" indirectly rather than through the primary, fully‑checked path) skips the checks the primary path enforces.

### Finding Description
For a human‑posted `definition` message, `validation.js` calls the full validator: [1](#0-0) 

That full validator (`aa_validation.validateAADefinition`) recursively checks messages, formulas, complexity, ops, asset payloads, etc. via `validateMessage`/`validatePayload`.

However, inside that very validator, when the *definer AA itself* contains a nested `definition` message (i.e., an AA whose messages array can emit a `definition` app message to create another AA), the nested definition is only shallow-checked: [2](#0-1) 

Note the commented-out recursive call: `// (typeof setImmediate === 'function') ? setImmediate(validateAADefinition, payload.definition, cb2) : ...`. The real recursive validation of the nested AA's `messages`, formulas, complexity, and op-count limits is never performed at this stage. Furthermore, if `payload.definition` (or `payload.definition[1]`) is itself a formula (allowed post‑`aa2UpgradeMci`), validation is skipped entirely and returns success unconditionally: [3](#0-2) [4](#0-3) 

When the outer AA is later triggered and actually emits this `definition` message in its response unit, `writer.js` collects all `definition`-app messages from an AA response unit and hands them to `storage.insertAADefinitions` with `bForAAsOnly=true`: [5](#0-4) 

`insertAADefinitions` inserts the nested AA's definition JSON straight into `aa_addresses` after only computing getter properties via `aa_validation.determineGetterProps` — it never calls the full `validateAADefinition`: [6](#0-5) 

Once inserted, this address is a first‑class AA (`aa_addresses` row with `base_aa`/`definition`) that can immediately receive/be triggered by payments, per the trigger-lookup logic elsewhere in `aa_composer.js`/`storage.js`.

### Impact Explanation
An AA can dynamically compose and post a nested AA definition (via formulas or templated messages) whose final, runtime-evaluated content was never checked by the deep validator: complexity limits, op-count limits, formula legality, `messages`/`bounce_fees`/`asset` payload shape rules that `validateAADefinition` otherwise enforces. Because the actual bytes that get written to `aa_addresses` come from formula evaluation at trigger time — a value that could not have been (and was not) checked by the definer-time shallow check — a node can register/execute an AA whose definition would have been rejected had it gone through the primary human-posting validation path. Downstream, any bytes/assets sent to that newly minted AA address are governed by an AA whose logic was never fully verified, which can result in fund freezing (e.g. a definition that always bounces, or that references undefined/invalid formulas causing every trigger to error and coins to remain stuck) or asymmetric/unexpected consensus behavior between nodes if they rely on differing assumptions established by full validation (e.g., getters/complexity bookkeeping that other logic assumes was already validated).

### Likelihood Explanation
Any address able to get its own AA defined (any user, since AA definition posting is permissionless) can define a "factory" AA whose messages include a `definition`-app message using a formula for `payload.definition`/`payload.definition[1]`. This bypasses the deep check at definition time (lines 209-210, 217-218 of `aa_validation.js`) entirely, and the resulting nested AA is inserted via `insertAADefinitions` without ever calling `validateAADefinition` (only `determineGetterProps`). No special permission, network position, or malicious peer is required — a single unprivileged AA author/trigger sender chain of posted units is sufficient.

### Recommendation
When an AA-produced `definition` message is about to be committed (in `writer.js`/`storage.js insertAADefinitions`), run the resulting concrete `payload.definition` through the same full `aa_validation.validateAADefinition` used for human-posted definitions before inserting it into `aa_addresses`, rejecting (bouncing) the triggering response if validation fails. Alternatively, restore/implement the previously commented-out recursive call to `validateAADefinition` for nested definitions at definer-validation time whenever the nested definition is not formula-derived, and always validate the final evaluated definition at insertion time regardless of whether it originated from a formula.

### Proof of Concept
1. Define AA `F` whose `messages` include a `definition` app message where `payload.address` and `payload.definition` are computed via formulas from `trigger.data` (permitted per the `aa2UpgradeMci` formula-skip branches in `aa_validation.js` lines 209-210/217-218), so `F`'s own definition validation never inspects the concrete nested AA structure.
2. Trigger `F` with a payload whose formula-substituted values produce a nested AA definition that violates constraints normally enforced by `validateAADefinition` (e.g., excessive `messages` complexity, or a self-inconsistent `bounce_fees`/`asset` payload that would fail `hasFieldsExcept`/formula checks).
3. Observe in `writer.js` (lines 620-629) that this `definition` message is collected and passed to `storage.insertAADefinitions` (`storage.js` lines 904-921), which inserts the row into `aa_addresses` after only `determineGetterProps`, with no call to `validateAADefinition`.
4. Send bytes to the newly created AA address and observe it becomes active/triggerable despite never having passed the deep validation that would apply to an equivalent human-posted `definition` message.

Note: full confirmation of exact runtime error/freeze behavior would require inspecting `aa_validation.determineGetterProps` and the `messages` evaluation path inside `aa_composer.js`'s `evaluateAA`, which were not fully retrievable within the available search budget; those areas should be reviewed directly to confirm the precise fund-freezing/consensus-divergence outcome.

### Citations

**File:** validation.js (L1767-1767)
```javascript
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
```

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
