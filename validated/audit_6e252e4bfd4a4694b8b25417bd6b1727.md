This confirms the key finding: `validateAADefinition` in `aa_validation.js` explicitly **skips validation of the nested AA definition's contents whenever it is expressed as a formula** — `if (mci >= constants.aa2UpgradeMci && getFormula(payload.definition) !== null) return cb2();` and `if (mci >= constants.aa2UpgradeMci && getFormula(payload.definition[1]) !== null) return cb2();` [1](#0-0) . The recursive call that would have validated a static nested AA body is even commented out [2](#0-1) . This is the exact "template injection" analog: the parent AA author is allowed (and, per the code comment in `aa_composer.js`, expected) to build a brand-new AA's source dynamically out of trigger-derived data [3](#0-2) , but the framework never checks, at either definition time or generation time, that the resulting object graph is free of attacker-supplied `{...}` strings, because `getFormula()` treats *any* string that starts with `{` and ends with `}` as executable Oscript, regardless of which field it occupies [4](#0-3) . When the newly generated definition is later processed for its own trigger, `aa_composer.js`'s `replace()` walks the whole template recursively and evaluates every such string as a formula [5](#0-4) .

### Title
Unvalidated Formula-Generated Nested AA Definitions Allow Trigger-Data Template Injection - (File: aa_validation.js)

### Summary
`validateAADefinition()` skips all structural/semantic validation of a nested `definition` message payload whenever the payload (or its template body) is itself expressed as an Oscript formula (`aa_validation.js:208-223`). This is intended to let a "factory" AA build a child AA's code dynamically at trigger time, but it means the resulting child-AA source that eventually gets created and executed can be assembled, unchecked, out of raw trigger data. Because ocore's uniform convention treats *any* string bounded by `{`…`}` as an executable Oscript formula wherever it occurs in an AA definition tree (`getFormula()` in `formula/common.js:82-93`, consumed recursively by `replace()` in `aa_composer.js:618-695`), an unprivileged trigger sender who controls `trigger.data` can smuggle a string shaped like `{...oscript...}` into the factory AA's `init`/formula logic. If that logic embeds trigger-controlled substrings verbatim (a natural pattern, since child-AA generation is explicitly meant to be built from trigger data) into the generated child definition, the attacker's payload is executed as code with the authority, address, balance and state variables of the freshly spawned child AA the moment that child AA is triggered — exactly the “backend-configured string passed directly into a template engine without restriction” pattern of the reference CVE, except here the “template engine” is Oscript itself and the reachable actor is any address that can post a trigger unit, not a privileged backend account.

### Finding Description
- `getFormula(str)` is the single gate that decides whether a string anywhere in an AA definition is data or code: it returns the code only by checking the first/last character are `{`/`}` [4](#0-3) .
- `aa_composer.js`'s `replace()` recursively walks every field of the (possibly dynamically-generated) AA template and evaluates any value matching that shape as a formula, including inside a newly minted `definition` message payload — the comment even documents that dynamic child definitions "[have] to generate `{}`-formulas in order to be dynamic" [6](#0-5) .
- `aa_validation.validateAADefinition()`'s handling of the `definition` app explicitly bails out of validating the nested definition's contents once it detects the payload (or the inner template) is a formula string, rather than recursively validating what that formula will eventually produce: [1](#0-0) .
- The test `AA with generated definition of new AA and immediately sending to this new AA` demonstrates the intended, legitimate use of this mechanism — a factory AA computing `$child_aa` in its `init` formula and emitting it via `{ app: 'definition', payload: { definition: "{$child_aa}" } }` [7](#0-6) . Nothing in this pipeline prevents `$child_aa`'s construction from splicing in attacker-controlled `trigger.data` fields as raw leaf strings that happen to be wrapped in `{}`.
- Once such a child AA is created and later triggered, its own `handleTrigger`/`replace` pass will treat those attacker-shaped strings as genuine Oscript and execute them with the new AA's own `address`, `objValidationState`, and state variables (`stateVars`) — i.e., with a different (elevated, AA-level) trust context than the original trigger sender ever had.

### Impact Explanation
Because the injected formula executes as if the spawned AA's own author wrote it, an unprivileged trigger sender can potentially manipulate the child AA's state variables, redirect its payment outputs, or otherwise divert funds/assets that the child AA controls — this maps to unauthorized spending or fund loss/freezing at the AA level, matching the "Critical" impact class required by the validation rules (concrete unauthorized AA fund loss/freezing).

### Likelihood Explanation
Exploitability depends entirely on whether a factory-style AA author embeds trigger-derived strings unsanitized into a generated child AA's template — this is a foreseeable, even encouraged, pattern (as shown by the shipped test case), and the framework provides no automatic escaping/sanitization or re-validation step to prevent it. The attack requires only posting a normal trigger unit to a factory AA, which is fully within reach of an unprivileged unit poster/trigger sender.

### Recommendation
When a `definition` message payload (or its inner template) is generated via formula, `aa_validation.js` should not skip validation of the *resulting* structure — after evaluation at trigger time, the generated child definition should be passed through the same `validateAADefinition` logic (currently commented out at `aa_validation.js:222`) before it is allowed to become an active AA, and/or `getFormula`/`replace` should refuse to re-interpret leaf string values that were copied verbatim from `trigger.data` without being explicitly re-wrapped by the AA author's own code path (i.e., distinguish "formula literal written by the AA author" from "opaque data value that happens to look like a formula").

### Proof of Concept
Conceptual (based on the legitimate pattern in `test/aa_composer.test.js:922-1010`):
1. Deploy a "factory" AA whose `init` formula builds a child AA definition that embeds a trigger-supplied field directly as a message field value, e.g. `outputs: [{address: trigger.data.address, amount: ...}]` where `trigger.data.address` is copied in unwrapped/unsanitized (or concatenated into a string later wrapped in `{}` by the factory's own logic).
2. An attacker posts a trigger to the factory AA with `data.address` (or another data field) set to a string of the form `{...malicious oscript expression touching var[...] or response[...]...}`.
3. The factory AA spawns the child AA containing this attacker string verbatim.
4. When the child AA later receives its own trigger, `aa_composer.js`'s `replace()` detects the `{}`-wrapped attacker string and executes it as Oscript in the child AA's own privileged context (its `address`, `stateVars`), letting the original attacker control the child AA's state/outputs despite having no authority over that AA.

Note: I could not find, within the indexed portion of the repo, an explicit sanitization/whitelist step that ocore applies to trigger-derived strings before they are spliced into a dynamically generated AA definition, nor a re-validation call on the fully-resolved child definition at trigger time — this gap is what the finding above rests on. Given index-size limits, a full audit of every factory/child-AA pattern used in production AAs (outside this repo) is not possible from Ask alone; a Devin session with full repository and any deployed-AA-source access would be needed to confirm a concretely exploitable, currently-deployed factory AA.

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

**File:** aa_composer.js (L617-695)
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

**File:** test/aa_composer.test.js (L922-970)
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
```
