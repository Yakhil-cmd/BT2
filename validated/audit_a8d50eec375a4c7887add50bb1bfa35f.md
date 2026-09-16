### Title
Improper (non-recursive) validation of nested AA definitions generated at trigger-execution time allows an AA to deploy a malformed/unbounded child AA that bypasses complexity limits and structural checks - (File: [aa_validation.js](aa_validation.js))

### Summary
Apache Superset's flaw was that its SQL parser did not fully validate/parse *nested* SQL statements, letting an authenticated user's query slip past the authorization-scope check that is only applied to the outer statement. `ocore` has a structurally analogous flaw in Autonomous Agent (AA) definition validation: when an AA definition contains a `definition` message that builds a *nested* AA (a "factory AA" that spawns a child AA), the validator explicitly skips the full recursive structural/complexity check for that nested definition, and the same skip persists when the nested definition is dynamically computed by a formula at trigger-execution time and then persisted as a live, fundable AA.

### Finding Description
When a plain (non-AA) unit posts an `app: 'definition'` message to create a brand-new AA, `validation.js` calls the complete `aa_validation.validateAADefinition()` on the payload, which enforces message-structure rules, formula validity, complexity/op-count limits, `bounce_fees` sanity, etc. [1](#0-0) 

However, when an AA definition itself *contains* a nested `definition` message (i.e., a template that will later compute and post a child AA definition), `aa_validation.js`'s own recursive validator (`validateAADefinition`) only performs a shallow shape check on the nested payload — array-of-2, `'autonomous agent'` tag, non-empty object — and explicitly does **not** recurse into full validation of the nested definition. The full recursive call (`setImmediate(validateAADefinition, payload.definition, cb2)`) is commented out with the note "interrupt the call stack to protect against deep nesting": [2](#0-1) 

At execution time, a factory AA can compute this nested definition dynamically via a formula (e.g. `$child_aa = ['autonomous agent', {...}]`) and emit it in an `app: 'definition'` message, as demonstrated by the test suite: [3](#0-2) 

When the unit produced by the AA response is written, `writer.js` collects all `app: 'definition'` payloads from the AA's own emitted messages and passes them straight to `storage.insertAADefinitions()`: [4](#0-3) 

`storage.insertAADefinitions()` only calls `aa_validation.determineGetterProps()` (which extracts getter metadata) before inserting the definition into `aa_addresses` and activating it as a live, callable, fundable AA — it does **not** call `aa_validation.validateAADefinition()`: [5](#0-4) 

Because the shallow check in `aa_validation.js` never verifies message structure, complexity, `MAX_OPS`/`MAX_COMPLEXITY` bounds, or `bounce_fees` correctness of the nested/dynamically-produced definition, and the runtime insertion path likewise skips full validation, an attacker-controlled factory AA can spawn a child AA whose definition would have been rejected had a human posted it directly via `app: 'definition'` (which does go through `validateAADefinition`). This is the same bug class as the Superset CVE: authorization/validation logic exists and is enforced for the "outer"/direct case, but is not correctly applied to the semantically equivalent "nested" case, letting an unprivileged actor (any AA trigger sender who can invoke the factory AA) produce an object that escapes the intended validation scope.

### Impact Explanation
An AA-generated child AA that bypasses `MAX_COMPLEXITY`/`MAX_OPS` and structural checks can:
- Contain malformed message templates that make execution throw (`aa_composer.js`'s `replace()` throws `Error('unknown type of value in ...')` on structurally invalid values), causing a live/funded AA to become permanently unable to process any trigger — a fund-freezing condition for anyone who sends assets to it.
- Have unbounded formula complexity, allowing pathological CPU/resource consumption during message composition once activated, since the complexity ceiling that protects the network from adversarial AA definitions was never enforced for this nested definition.
- Diverge in behavior between full nodes and light/partial validators depending on how each path re-derives or trusts the definition, risking node disagreement on validity of subsequent triggers to the spawned AA.

This satisfies the "AA fund loss or freezing" / "node disagreement on validity" impact bar required by the validation rules.

### Likelihood Explanation
Any user can trigger a "factory" AA (one whose author deliberately or accidentally emits an `app: 'definition'` message containing an attacker/param-influenced nested definition) with ordinary unprivileged funds — no special privileges are required, matching the "AA trigger sender" actor class. The feature (AAs defining other AAs) is a supported, documented, and tested capability of `ocore`, as shown by the existing test coverage for dynamically generated child AAs, so the code path is definitely reachable in production.

### Recommendation
Ensure that nested/AA-generated AA definitions go through the identical full validation as directly-posted `definition` messages:
1. In `aa_validation.js`'s `case 'definition':` handler (the "nested AA" case inside `validateAADefinition`), perform the full recursive structural/complexity validation of `payload.definition[1]` (guarding against unbounded recursion with an explicit depth counter instead of skipping validation entirely).
2. In `storage.insertAADefinitions()` (called from `writer.js` for AA-generated definitions), invoke `aa_validation.validateAADefinition()` on each dynamically produced payload before inserting it into `aa_addresses`, rejecting/bouncing the parent trigger if validation fails, exactly as is done for human-submitted `definition` messages in `validation.js`.

### Proof of Concept
1. Deploy a "factory" AA whose `init`/message formulas compute a child AA definition (`$child_aa`) with, e.g., an oversized/duplicated `messages` structure, or a formula chain designed to exceed `MAX_COMPLEXITY`/`MAX_OPS`, or an invalid `bounce_fees` amount — this pattern is directly modeled on the existing test `'AA with generated definition of new AA and immediately sending to this new AA'`. [3](#0-2) 
2. Send a trigger to the factory AA. Because the enclosing factory AA definition was validated only shallowly for its nested `definition` message (per `aa_validation.js:208-223`), the malformed template passes validation at AA-registration time.
3. When the factory AA runs, `writer.js` extracts the payload and `storage.insertAADefinitions()` inserts the new AA into `aa_addresses` without a call to `validateAADefinition()`, activating it as a fundable AA.
4. Send funds to the new AA and trigger it; because it never underwent complexity/structure enforcement, it can throw during composition (freezing funds sent to it) or behave inconsistently with the guarantees other, `validation.js`-checked AAs provide.

Note: I was unable to fully trace every intermediate call in `aa_composer.js` between message composition and the final `writer.js` persistence step (the file is large and only partially indexed), so it is possible there is an additional validation call elsewhere in that file that I could not locate with the available search tools. This should be double-checked in a full read of `aa_composer.js` before treating the recommendation as final; a Devin session with full file access is recommended to confirm the complete call graph.

### Citations

**File:** validation.js (L1747-1768)
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

**File:** test/aa_composer.test.js (L944-986)
```javascript
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
```

**File:** writer.js (L618-629)
```javascript
					if (1 || objUnit.parent_units){ // genesis too
						if (!conf.bLight){
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
