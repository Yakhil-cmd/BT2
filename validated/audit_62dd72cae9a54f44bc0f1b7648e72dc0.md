## Title
Dynamically-composed AA definitions allow injected oscript formulas from untrusted trigger data to persist as live code in child AAs - ([File: aa_composer.js])

### Summary
When an Autonomous Agent (AA) dynamically deploys another AA by embedding `{...}`-formulas inside a `definition` message (a documented pattern noted at [1](#0-0) ), the composer's `replace()` function resolves each formula field using the current trigger data and writes the resulting string back into the definition object. For *value* fields, the code never checks whether the computed result itself looks like a formula (`{...}`), unlike the analogous *key*-substitution branch a few lines above which explicitly guards against this. This asymmetry lets an untrusted trigger sender inject a live, self-authored oscript formula into a field of a newly created child AA, which will then be executed with the child AA's own authority every time it is triggered thereafter.

### Finding Description
`aa_composer.js`'s `replace()` function walks the AA definition template and substitutes any `{...}`-wrapped string with the result of evaluating it as an oscript formula against the current `trigger`/`params`/`stateVars`: [2](#0-1) 

Note the guard at line 649-650: when the **key name** of an object is itself a formula, the resolved result is explicitly checked with `getFormula(res) !== null` and rejected if the computed key "looks like a formula again."

However, the parallel branch that resolves **values** (i.e., `obj[name]` is itself a `{...}` formula) performs no such check: [3](#0-2) 

`assignField(obj, name, res)` stores the computed `res` string directly, with no verification that `res` doesn't start with `{` and end with `}` (which is exactly the pattern `getFormula()` uses to recognize formulas, per `formula/common.js`): [4](#0-3) 

Since virtually every string field in an AA definition schema is allowed to alternatively be a live formula — addresses, assets, data-feed names, poll choices, attestors, vote units, etc. — `validateAADefinition` in `aa_validation.js` explicitly accepts `getFormula(...)`-matching strings as valid in place of concrete values, by design, to allow programmable child AAs: [5](#0-4) 

Because the parent (factory) AA's `replace()` step builds `res` from ordinary string concatenation (e.g. `'{' || trigger.data.x || '}'`), any AA that assembles a dynamically-deployed sub-AA's definition using untrusted `trigger.data` in a value position can be coerced into leaving a `{...}`-wrapped, attacker-authored oscript expression embedded in the deployed child AA. Because that embedded value still matches `getFormula()`, it is accepted by `validateAADefinition` as a legitimate deferred formula, and it will be evaluated as live code by `evaluateAA`/`replace()` (or wherever that same field is used) every time the new AA is triggered in the future.

### Impact Explanation
This lets an unprivileged unit poster who merely sends a trigger to a "factory" AA (one that programmatically builds and deploys other AAs, a supported and documented pattern) implant persistent, self-authored oscript logic into the freshly minted AA — logic the factory AA's actual developer never wrote or reviewed. Once deployed, that logic runs with the full authority (balance, state) of the child AA on every subsequent trigger, enabling the attacker to redirect the child AA's outputs, drain its balance, or otherwise manipulate its state — i.e., concrete AA fund loss, matching the accepted impact categories for this analysis.

### Likelihood Explanation
Any AA developer who follows the documented pattern of dynamically composing sub-AA definitions from trigger data (as illustrated in the codebase's own comment and test fixtures such as `test/aa.test.js`'s `definition` message using `trigger.address`/`trigger.data`) is exposed. No special privileges are needed by the attacker — they only need to be able to post a unit that triggers the factory AA and control a string field that ends up embedded, unescaped, into a dynamically generated child-AA value.

### Recommendation
In `aa_composer.js`'s `replace()` function, apply the same safeguard used for computed keys (line 649-650) to computed values: after evaluating a `{...}`-formula value and obtaining `res`, reject (or otherwise safely escape) results for which `getFormula(res) !== null`, so that a resolved value can never re-enter the definition as an active, un-vetted formula.

### Proof of Concept
1. Deploy factory AA `F` whose `messages` include a nested `definition` message for a new AA, where some field (e.g., an output `address` or a `data` payload string) is set to a formula such as `"{'{' || trigger.data.payload || '}'}"`.
2. Send a trigger unit to `F` with `data.payload` containing attacker-chosen oscript, e.g. `response['sent'] = payment[{asset: 'base', outputs: [{address: trigger.address, amount: 'all'}]}];` (any valid formula body).
3. `aa_composer.js`'s `replace()` (lines 656-695) evaluates the outer formula, produces `res = "{...attacker code...}"`, and stores it via `assignField(obj, name, res)` with no re-check.
4. The resulting `definition` message is validated by `aa_validation.js` (lines 63-82), which accepts the field because `getFormula(res) !== null`.
5. The newly deployed AA is created with this attacker-authored formula embedded in a "static" field.
6. On any future trigger of the new AA, that field is evaluated by `evaluateAA`/`replace()`, executing the attacker's injected oscript with the new AA's own funds/state authority.

### Citations

**File:** aa_composer.js (L617-654)
```javascript
	// note that app=definition is also replaced using the current trigger and vars, its code has to generate "{}"-formulas in order to be dynamic
	function replace(obj, name, path, locals, xpath, cb) {
		count++;
		if (count % 100 === 0) // interrupt the call stack
			return setImmediate(replace, obj, name, path, locals, xpath, cb);
		locals = _.clone(locals);
		var value = obj[name];
		if (typeof name === 'string') {
			xpath += '/' + name;
			var f = getFormula(name);
			if (f !== null) {
				var opts = {
					conn: conn,
					formula: f,
					trigger: trigger,
					params: params,
					locals: _.clone(locals),
					stateVars: stateVars,
					responseVars: responseVars,
					objValidationState: objValidationState,
					address: address
				};
				return formulaParser.evaluate(opts, [], xpath, function (err, res) {
					if (res === null)
						return cb(err.formattedError || "formula " + f + " failed: "+err);
					delete obj[name];
					if (res === '')
						return cb(); // the key is just removed from the object
					if (typeof res !== 'string')
						return cb({message: "result of formula " + name + " is not a string: " + res, xpath});
					if (ValidationUtils.hasOwnProperty(obj, res))
						return cb({message: "duplicate key " + res + " calculated from " + name, xpath});
					if (getFormula(res) !== null)
						return cb({message: "calculated value of " + name + " looks like a formula again: " + res, xpath});
					assignField(obj, res, value);
					replace(obj, res, path, locals, xpath, cb);
				});
			}
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

**File:** formula/common.js (L82-93)
```javascript
function getFormula(str, bOptionalBraces) {
	if (bOptionalBraces)
		throw Error("braces cannot be optional");
	if (typeof str !== 'string')
		return null;
	if (str[0] === '{' && str[str.length - 1] === '}')
		return str.slice(1, -1);
	else if (bOptionalBraces)
		return str;
	else
		return null;
}
```

**File:** aa_validation.js (L63-82)
```javascript
			if (!['string', 'object'].includes(typeof payload) || !payload)
				return cb2("payload must be a string or object: " + payload);

			if (message.app !== 'text' && isNonemptyString(payload)) {
				var payload_formula = getFormula(payload);
				if (payload_formula === null)
					return cb2("payload is a string but doesn't look like a formula: " + payload);
				return cb2();
			}

			if (['payment', 'asset', 'asset_attestors', 'attestation', 'poll', 'vote'].indexOf(message.app) >= 0) {
				if ('init' in payload) {
					if (!isNonemptyString(payload.init))
						return cb2("bad init: " + JSON.stringify(payload.init));
					var f = getFormula(payload.init);
					if (f === null)
						return cb2("init is not a formula: " + payload.init);
				}
			}

```
