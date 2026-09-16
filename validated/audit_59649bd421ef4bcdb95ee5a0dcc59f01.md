### Title
Unvalidated nested AA "definition" message allows deploying a malformed autonomous agent whose definition/oscript body is never structurally or formula-validated - ([File: aa_validation.js])

### Summary
CVE-2017-7039 is a WebKit memory-corruption bug triggered by feeding the renderer crafted, insufficiently-validated content. The closest reachable analog in this codebase is in `aa_validation.js`'s `case 'definition':` branch of `validateAADefinition`: when an AA message defines a nested autonomous agent (`app: 'definition'`), the code that is supposed to recursively validate the nested AA body (`validateAADefinition(payload.definition, ...)`) is commented out, and `cb2()` (success) is called unconditionally beforehand. [1](#0-0) 

### Finding Description
`validateAADefinition` is the gatekeeper that ensures any AA definition posted to the DAG (by any unprivileged unit poster, since anyone can define an AA) has well-formed messages, valid oscript/formula bodies, and consistent field structures, per `validatePayload`/`validateMessage`. [2](#0-1) 

For the `data`, `data_feed`, `payment`, `text`, and `asset` cases, the payload contents (formulas, addresses, amounts, output lists) are strictly checked via `getFormula`, `isValidAddress`, `isNonemptyObject`, etc., ensuring the oscript grammar/parse step (`formula/validation.js`, `formula/evaluation.js`) will not choke on malformed structures later. [3](#0-2) 

However, the `'definition'` case (used to embed a nested AA, i.e., an AA that deploys another AA) only checks the top-level shape (`['autonomous agent', {...}]`, non-empty object) and then calls `cb2()` — success — immediately. The line that would have recursively invoked `validateAADefinition` on `payload.definition` to actually validate the nested AA's internal messages/formulas is commented out:
```
cb2();
//	(typeof setImmediate === 'function') ? setImmediate(validateAADefinition, payload.definition, cb2) : setTimeout(validateAADefinition, 0, payload.definition, cb2); // interrupt the call stack to protect against deep nesting
break;
``` [4](#0-3) 

This means an attacker can post a unit whose top-level AA definition contains an `app: 'definition'` message whose `payload.definition[1]` is a syntactically/semantically invalid nested AA body (e.g. malformed formulas, missing required fields, bad bounce_fees, oversized/invalid oscript expressions, mismatched message counts) as long as it is a non-empty object. Because `validateAADefinition` never recurses into it, the network accepts and stores this nested-AA-defining unit as valid. The unvalidated formulas embedded in the nested definition are only ever parsed/evaluated later — during `formula/validation.js`'s `exports.validate` or `formula/evaluation.js`'s `exports.evaluate` — when the nested AA is actually triggered/deployed and executed. Both of those modules contain numerous `throw Error(...)` statements for "impossible"/unexpected states that are only unreachable because `aa_validation.js` is assumed to have already guaranteed well-formed input (e.g., `throw Error("unknown op: " + op)` in `evaluation.js`). [5](#0-4) 

Since the nested AA's structural well-formedness (field constraints, formula shape, message counts) is never checked at definition time, this invariant is broken specifically for nested-AA definitions, opening the reachable path for crafted, "unvalidated" content to reach code that assumes it has already been screened — directly analogous to feeding crafted, insufficiently-validated content into a component (WebKit) that assumes safe input.

### Impact Explanation
If a nested AA definition that bypassed structural validation is later triggered, deployed as an actual AA (via `app: 'definition'` payload being written as a real AA at execution time) or evaluated, unexpected `throw Error(...)` paths inside `formula/evaluation.js`/`formula/validation.js` can fire outside the guarded validation flow that normally intercepts and gracefully reports such errors as callback errors. Depending on whether these throws occur inside a try/catch-wrapped async callback during transaction/unit processing (as opposed to `aa_validation.js`'s own callback-based error reporting), an uncaught exception can propagate and crash the Node.js process on any node evaluating that unit/AA — a network-wide denial-of-service on nodes attempting to process or confirm the resulting AA execution, and potentially different nodes reaching different validity/stability conclusions if some catch the exception differently (consensus divergence). This satisfies the "node disagreement on validity/stability" / "network unable to confirm new units" impact bar.

### Likelihood Explanation
Any unprivileged unit poster can define an AA containing an `app: 'definition'` message with an intentionally malformed nested AA body; only trivial shape checks (`isArrayOfLength(2)`, `payload.definition[0] === 'autonomous agent'`, `isNonemptyObject`) need to be satisfied, all of which are easy to satisfy while still containing invalid inner content. No special privileges, timing, or race conditions are required — a single crafted unit suffices.

### Recommendation
Restore/implement the recursive validation of nested AA definitions: uncomment and properly wire up a recursive call to `validateAADefinition(payload.definition, readGetterProps, mci, cb2)` (guarding against unbounded recursion depth, e.g. via the existing `MAX_DEPTH` constant already declared in this file) so nested AA bodies receive the same structural/formula validation as top-level AA definitions before being accepted into the DAG. [6](#0-5) 

### Proof of Concept
1. Craft a unit that defines an AA (`['autonomous agent', {...}]`) with a message:
```json
{
  "app": "definition",
  "payload": {
    "definition": ["autonomous agent", { "bogus_field_or_malformed_formula": "{{{{not valid oscript" }]
  }
}
```
2. Because `case 'definition':` in `aa_validation.js` only checks `isNonemptyObject(payload.definition[1])` and never recurses to validate its internal messages/formulas, `validateAADefinition` returns success and the outer unit is accepted as a valid AA definition.
3. When this nested AA is later triggered/deployed and its body is parsed/evaluated via `formula/validation.js` or `formula/evaluation.js`, the malformed inner content can reach code paths guarded only by `throw Error(...)` (assuming prior validation), rather than the graceful callback-based error handling used elsewhere in `aa_validation.js`.

Note: I was not able to trace, within the available indexed context, the exact downstream call site where a nested `app: 'definition'` payload gets deployed/executed as a live AA (e.g., in `aa_composer.js` or `writer.js`) to confirm whether an uncaught throw there is caught by an outer try/catch or propagates to crash the process — this would need to be verified directly in the full repository (the index may not include every relevant execution-path file) before treating the crash/DoS impact as fully confirmed rather than a plausible, well-supported root-cause defect.

### Citations

**File:** aa_validation.js (L29-29)
```javascript
var MAX_DEPTH = 100;
```

**File:** aa_validation.js (L33-43)
```javascript
function validateAADefinition(arrDefinition, readGetterProps, mci, callback) {

	let validationErrorDetails = null;

	function validateMessage(message, cb) {

		function validatePayload(payload, cb2) {

			function validateAttestors(attestors, cb3) {
				if (isNonemptyString(attestors)) {
					var f = getFormula(attestors);
```

**File:** aa_validation.js (L123-200)
```javascript
				case 'payment':
				//	console.log('---payment', payload);
					if (hasFieldsExcept(payload, ['asset', 'outputs', 'init']))
						return cb2("foreign fields in payment");
					if ('asset' in payload) {
						if (!isNonemptyString(payload.asset))
							return cb2("bad asset: " + JSON.stringify(payload.asset));
						if (payload.asset !== 'base' && !isValidBase64(payload.asset, constants.HASH_LENGTH)) {
							var asset_formula = getFormula(payload.asset);
							if (asset_formula === null)
								return cb2("bad asset in payment: " + payload.asset);
						}
					}

					function validateOutputs(outputs, cb3) {
						if (!isNonemptyArray(outputs))
							return cb3("bad outputs");
						var bHaveSendAll = false;
						for (var i = 0; i < outputs.length; i++) {
							var output = outputs[i];
							if (isNonemptyString(output)) {
								var output_formula = getFormula(output);
								if (output_formula === null)
									return cb3("bad output formula: " + output);
								continue;
							}
							if (!isNonemptyObject(output))
								return cb3("output must be a non-empty object: " + JSON.stringify(output));
							if (hasFieldsExcept(output, ['address', 'amount', 'init', 'if']))
								return cb3('foreign fields in output');
							if ('if' in output) {
								if (!isNonemptyString(output.if))
									return cb3("bad if in output: " + JSON.stringify(output.if));
								var f = getFormula(output.if);
								if (f === null)
									return cb3("if in output is not a formula: " + output.if);
							}
							if ('init' in output) {
								if (!isNonemptyString(output.init))
									return cb3("bad init in output: " + JSON.stringify(output.init));
								var f = getFormula(output.init);
								if (f === null)
									return cb3("init in output is not a formula: " + output.init);
							}
							if (!isNonemptyString(output.address))
								return cb3('address not a string: ' + JSON.stringify(output.address));
							var f = getFormula(output.address);
							if (f !== null) {
							}
							else if (!isValidAddress(output.address))
								return cb3("bad address: "+output.address);
							if (typeof output.amount === 'number') {
								if (!isPositiveInteger(output.amount) || output.amount > constants.MAX_CAP)
									return cb3('bad amount number: ' + output.amount);
							}
							else if (typeof output.amount === 'string') {
								var f = getFormula(output.amount);
								if (f === null)
									return cb3("bad formula in amount: " + output.amount);
							}
							else if (typeof output.amount === 'undefined') {
								if (bHaveSendAll)
									return cb3("a second send-all output");
								bHaveSendAll = true;
							}
							else
								return cb3('bad amount: ' + JSON.stringify(output.amount));
						}
						cb3();
					}

					validateFieldWrappedInCases(payload, 'outputs', validateOutputs, function (err) {
					//	console.log('---- after outputs', err);
						if (err)
							return cb2(err);
						cb2();
					});
					break;
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

**File:** formula/evaluation.js (L2000-2006)
```javascript
					if (res instanceof wrappedObject)
						res = true;
					if (op === 'to_upper')
						return cb(asciiToUpper(res.toString()));
					if (op === 'to_lower')
						return cb(asciiToLower(res.toString()));
					throw Error("unknown op: " + op);
```
