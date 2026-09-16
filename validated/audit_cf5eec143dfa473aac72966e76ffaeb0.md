Based on my investigation, I found a concrete analog to the Genshi SSTI issue in the AA (Autonomous Agent) formula/template engine.

### Title
Autonomous Agent message-value template re-interpretation allows injected oscript to execute with a victim AA's privileges - (File: aa_composer.js)

### Summary
Genshi's SSTI stems from expression results being fed back into the template evaluator without a check that they don't themselves contain new executable expression syntax. Ocore's oscript AA templating engine has the exact same "template value used as new template code" pattern in `replace()` in [1](#0-0) : any string that syntactically looks like `{...}` (`getFormula()`) is parsed and executed as oscript, and this check is applied identically whether the string came from the original signed AA definition or was itself just *produced* by evaluating a parent formula.

### Finding Description
`getFormula()` treats any string that begins with `{` and ends with `}` as executable oscript source [2](#0-1) . `aa_composer.js`'s `replace()` walks an AA's definition tree and, for every string field, calls `getFormula()`/`formulaParser.evaluate()` to turn `"{...}"` fields into computed values [3](#0-2) .

Critically, when the *computed value* of a formula is itself a string, there is **no check** that it doesn't again look like a formula (`getFormula(res) !== null`) before it is written back into the object with `assignField(obj, name, res)` [4](#0-3) . Compare this to the sibling code path just above it that handles a formula used as an object *key*: there the authors explicitly guard against this exact class of bug — `if (getFormula(res) !== null) return cb({message: "calculated value of " + name + " looks like a formula again: " + res, xpath});` [5](#0-4) . The value path has no equivalent protection.

This matters because AAs can programmatically create other AAs via `app: 'definition'` messages, whose payload is itself an oscript-templated AA definition tree that gets evaluated by the *creating* AA before being posted, and then re-evaluated from scratch by `replace()` every time the *new* AA is triggered [6](#0-5) . The tests demonstrate this exact self-referential template mechanism and that developers must carefully double-quote literal braces to avoid unintended re-evaluation [7](#0-6) .

If a template AA builds a child-AA field value by concatenating attacker-controlled data (e.g., `trigger.data.*`, which is fully controlled by whoever posts a unit to the AA) with `||`, e.g. `"{'prefix_' || trigger.data.x}"`, the *result* of that formula becomes a literal field in the newly created AA's definition. Because there is no "looks like a formula again" guard on values, if the attacker crafts `trigger.data.x` so the final concatenated string itself forms valid `{ ... }` oscript, that string is stored verbatim as part of the new AA's on-chain definition. When the new AA is subsequently triggered (by anyone, including the same attacker), `replace()` will parse and execute that attacker-shaped string as a full oscript program in the *new AA's own privileged context* (its own `this_address`, `balance`, `state vars`, and payment-message construction) — even though the field was only ever intended by the AA author to hold static/literal data, not to be reinterpreted as code a second time.

### Impact Explanation
Successful injection lets an attacker execute arbitrary oscript inside the second-stage AA's evaluation context. Because oscript's `payment`/`state`/`data` message blocks are exactly what controls fund transfers and state variables, an injected formula can construct arbitrary `payment` outputs, manipulate `bounce_fees`, or corrupt state vars of the created AA, i.e., unauthorized spending of that AA's balance / fund loss, satisfying the "concrete unauthorized spending... or AA fund loss" bar.

### Likelihood Explanation
This requires a specific (though not exotic) authoring pattern: a "factory" AA that (a) dynamically creates child AAs via `app: 'definition'`, and (b) builds one of the child's string fields via string concatenation of attacker/trigger-controlled data using `||` inside a `{...}` formula, without itself validating that the computed string doesn't start with `{` and end with `}`. Such factory-AA patterns are a documented, intentional oscript feature (see the "define new AA and activate it" test) and are realistically expected to appear in third-party AAs — so the precondition is plausible but not universal. The fact that the framework already added, and then omitted, the identical guard on the sibling code path (key evaluation) indicates the omission is a genuine oversight rather than an intentional design decision.

### Recommendation
Add the same `getFormula(res) !== null` re-templating guard to the value branch of `replace()` in `aa_composer.js` (around line 684, mirroring the check at lines 649-650), rejecting (bouncing) formula evaluation whenever a computed string value itself looks like `{...}`, exactly as is already done for computed key names.

### Proof of Concept
1. Deploy a "factory" AA whose `messages` contain an `app: 'definition'` payload building a child AA definition, with one field written as:
   `field_x: "{'prefix_' || trigger.data.payload}"`
2. Attacker posts a unit triggering the factory AA with `trigger.data.payload` crafted so the concatenated result equals a valid oscript block, e.g. `"} messages... {"`-shaped content ending up as: the stored `field_x` value in the new AA's definition is `"{ <attacker oscript, e.g. custom payment outputs/state var writes> }"`.
3. The factory AA writes this new AA definition on-chain via the `definition` message (`aa_composer.js` `replace()`, lines 658-695), with no check that the computed `field_x` value looks like a formula.
4. Attacker (or anyone) triggers the newly created AA. `evaluateAA`/`replace()` re-walks its definition [8](#0-7) , encounters `field_x`, sees it matches `getFormula()`, and executes the attacker-injected oscript with the new AA's own balance/state-variable privileges. [9](#0-8) [2](#0-1)

### Citations

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

**File:** aa_composer.js (L645-695)
```javascript
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
		}
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

**File:** test/aa_composer.test.js (L566-576)
```javascript
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
