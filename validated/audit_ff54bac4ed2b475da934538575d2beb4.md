### Title
Unvalidated dynamically-generated AA definitions allow formula/code injection into spawned child AAs - ([File: aa_validation.js])

### Summary
`aa_validation.js`'s static validator for AA (Autonomous Agent) definitions deliberately skips deep structural validation of a nested `app: 'definition'` payload whenever the nested definition (or its body) is expressed as an oscript formula rather than a literal object. That formula is only evaluated later, at trigger time, inside `aa_composer.js`'s `replace()` routine, using attacker-controlled `trigger.data`/`trigger.output` values — and the resulting concrete AA body is *never* run back through `validateAADefinition`. This lets a trigger sender smuggle arbitrary, structurally-unchecked oscript into the definition of a freshly spawned child AA, similarly to how XWiki accepted unescaped user-supplied translation text that was later rendered in a privileged macro context.

### Finding Description
`validateAADefinition`'s handling of the `definition` app case short-circuits validation when the payload is a formula: [1](#0-0) 

```
case 'definition':
    if (mci >= constants.aa2UpgradeMci && getFormula(payload.definition) !== null)
        return cb2();
    ...
    if (mci >= constants.aa2UpgradeMci && getFormula(payload.definition[1]) !== null)
        return cb2();
```

If `payload.definition` or `payload.definition[1]` (the AA body: `messages`, `bounce_fees`, etc.) is itself a `"{...}"` formula string, the validator accepts it immediately without recursing into `validateMessages`/`validate()` — i.e., without enforcing the field allow-lists (`hasFieldsExcept`), complexity/op-count limits (`MAX_COMPLEXITY`, `MAX_OPS`), or per-app structural rules that normally constrain every AA (e.g. `cosigned_by_definer must be false`, valid asset/address checks, etc.).

`validateAADefinition` is invoked exactly once, when the *outer* unit carrying the `app: 'definition'` message is validated: [2](#0-1) 

The actual evaluation of that dynamic formula happens much later, at trigger-processing time, inside `aa_composer.js`'s templating engine, using the *current* (attacker-supplied) trigger: [3](#0-2) [4](#0-3) 

Note the comment: "app=definition is also replaced using the current trigger and vars, its code has to generate `{}`-formulas in order to be dynamic" — this confirms the nested AA's messages/fields are meant to be generated dynamically from `trigger.data`, exactly the pattern that bypassed static validation above. Crucially, the value-substitution branch of `replace()` (lines 682-695) assigns the formula result directly into the object with `assignField(obj, name, res)` — there is no re-validation of the resulting AA body via `validateAADefinition`, and (unlike the *key*-substitution branch, which explicitly rejects a result that "looks like a formula again" at line 649-650) there is no check preventing the *value* result from itself containing further unescaped formula syntax.

This exact "meta-AA spawns a child AA whose body depends on `trigger.data`" pattern is a supported, tested feature: [5](#0-4) 

In that test, the nested definition's fields are wrapped in an extra layer of quoting (`"{'{trigger.address}'}"`) specifically to *prevent* premature evaluation — proving that the framework relies on AA authors manually double-escaping data to avoid unintended formula execution, rather than the platform enforcing it. Any AA author (or attacker crafting/triggering such a meta-AA with attacker-controlled `trigger.data`) who fails to add this manual escaping — or who is tricked via nested `definition[1]`-as-formula (which entirely bypasses static shape checks) — can inject formula fragments (additional `payment` outputs, `state` var writes, `asset` fields, etc.) into the child AA's on-chain body that were never checked against `aa_validation.js`'s structural/complexity constraints.

### Impact Explanation
Because the resulting spawned AA's definition is written to storage and becomes that AA's permanent, immutable on-chain program without ever passing back through `validateAADefinition`'s field/format/complexity checks, an attacker who controls the trigger that causes the meta-AA to spawn the child can influence which addresses receive funds, what asset/amount fields look like, or what state-var formulas execute whenever *anyone* later sends funds to that child AA. Since child AAs commonly receive payments from unrelated third parties (that's the point of spawning them), this can result in concrete unauthorized redirection of funds sent to the child AA, i.e., theft of funds belonging to future senders, and it undermines the guarantee that every AA's logic was checked for complexity/structural soundness before being trusted with funds.

### Likelihood Explanation
Exploitation requires a specific but real precondition: an existing "meta-AA" whose definition contains an `app: 'definition'` message that generates the child's body (partly or wholly) from `trigger.data`/`trigger.output` without the author manually double-quoting/escaping every dynamic fragment, or that uses the `definition`/`definition[1]`-as-formula shortcut. This is a documented, tested capability of the AA language (see the cited test), so such meta-AAs are expected to appear in the ecosystem (dynamic-AA-factory patterns are a selling point of oscript v2/getters). Any unprivileged party who can post a trigger to such a meta-AA (which is the normal, intended interaction) can attempt the injection — no special privilege beyond "can send a unit to the AA" is needed.

### Recommendation
- Do not allow `validateAADefinition` to short-circuit deep validation of a `definition` payload merely because it is expressed as a formula; instead, statically validate whichever parts are literal, and additionally re-run `validateAADefinition` (or an equivalent structural/complexity check) on the *runtime-evaluated* result inside `aa_composer.js`'s `replace()` before the new AA's arrDefinition is committed to storage/response unit.
- In `replace()`'s value-substitution branch, mirror the existing key-substitution safeguard (`"calculated value ... looks like a formula again"`) so a formula result that itself looks like a formula cannot be silently embedded into fields (especially nested AA `definition` payloads) without being flagged.
- Consider requiring that any oscript-emitted nested AA definition go through the same allow-list/complexity checks as statically-written AAs, regardless of how it was produced.

### Proof of Concept
1. Deploy a meta-AA (analogous to the tested `definition_aa` pattern) whose `app: 'definition'` message builds the child AA's `messages`/`payment` outputs directly from `trigger.data` fields, e.g. an address field like `outputs: [{address: "{trigger.data.recipient}", amount: ...}]` without wrapping it in an extra quoting layer as the safe pattern in `test/aa_composer.test.js:566-576` does.
2. As an unprivileged user, send a trigger to the meta-AA with `trigger.data.recipient` set to a formula-looking string, e.g. `"{some_injected_formula}"`.
3. Because the value-substitution path in `aa_composer.js` (lines 656-695) performs no "looks like a formula again" check, and `aa_validation.js` never re-validates the generated child AA body, the spawned child AA's on-chain definition now contains the attacker-influenced/unvalidated fragment.
4. When a later, unrelated user sends funds to the spawned child AA, the injected fragment executes with that AA's authority, diverting funds as dictated by the attacker's original trigger data.

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

**File:** validation.js (L1761-1767)
```javascript
			const top_mci = objValidationState.aa_mci || objValidationState.last_ball_mci;
			var readGetterProps = function (aa_address, func_name, cb) {
				storage.readAAGetterProps(conn, aa_address, func_name, top_mci, cb);
			};
			if (!objValidationState.hasBall && !objValidationState.bAA && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci && objValidationState.last_ball_mci < constants.pemCurvesFixMci)
				return callback(createTransientError("AA definition attached to an old part of the DAG"));
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
```

**File:** aa_composer.js (L617-618)
```javascript
	// note that app=definition is also replaced using the current trigger and vars, its code has to generate "{}"-formulas in order to be dynamic
	function replace(obj, name, path, locals, xpath, cb) {
```

**File:** aa_composer.js (L656-695)
```javascript
		if (typeof value === 'number' || typeof value === 'boolean')
			return cb();
		if (typeof value === 'string') {
			var f = getFormula(value);
			if (f === null)
				return cb();
		//	console.log('path', path, 'name', name, 'f', f);
			var bStateUpdates = (path === '/messages/state');
			if (bStateUpdates) {
				if (objStateUpdate)
					return cb({message: "second state update formula: " + f + ", existing: " + objStateUpdate.formula, xpath});
				objStateUpdate = {formula: f, locals: locals, xpath};
				return cb();
			}
			var opts = {
				conn: conn,
				formula: f,
				trigger: trigger,
				params: params,
				locals: locals,
				stateVars: stateVars,
				responseVars: responseVars,
				objValidationState: objValidationState,
				address: address,
				bObjectResultAllowed: true
			};
			formulaParser.evaluate(opts, [], xpath, function (err, res) {
			//	console.log('--- f', f, '=', res, typeof res);
				if (res === null)
					return cb(err.formattedError || "formula " + f + " failed: "+err);
				if (res === '' || isEmptyObjectOrArray(res)) { // signals that the key should be removed (only empty string or array or object, cannot be false as it is a valid value for asset properties)
					if (typeof name === 'string')
						delete obj[name];
					else
						assignField(obj, name, null);
				}
				else
					assignField(obj, name, res);
				cb();
			});
```

**File:** test/aa_composer.test.js (L557-576)
```javascript
test.cb.serial('define new AA and activate it', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { define: true }, address: trigger_address };

	// a chain of 3 AA responses
	// 1. define new AA, save its address in var['new_aa'] state var, and send bytes to forwarder AA
	// 2. forwarder sends the bytes to the new AA
	// 3. the new AA posts data

	var data_poster_hidden_definition = ['autonomous agent', {
		messages: [
			{
				app: 'data',
				payload: {
					trigger_address: "{'{trigger.address}'}",
					amount_received: "{'{trigger.output[[asset=base]]}'}",
				}
			},
		]
	}];
```
