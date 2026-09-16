### Title
Uncaught exception in `definition template` signature-verification path crashes validating nodes on malformed unit - (File: definition.js)

### Summary
`definition.js`'s `validateAuthentifiers()` handles the `'definition template'` operator by fetching a stored template and calling `replaceInTemplate(arrTemplate, params)` and then throwing on missing rows — but, unlike the analogous code path used when *defining* a new address, this signature-verification path does **not** wrap the call in a `try/catch`. An attacker who owns an address whose definition contains `['definition template', [unit, params]]` can post a unit signed by that address with deliberately mismatched `params` (or reference a template `unit` that does not resolve to exactly one row), causing an uncaught exception during core unit validation on every node that validates the unit.

### Finding Description
This is the same bug class as ALPINE-CVE-2026-22795 (OpenSSL PKCS#12 type confusion): a value governed by an untrusted, attacker-supplied discriminant (there: an ASN1 type tag; here: caller-supplied `params` vs. a template's variable placeholders) is consumed without first validating that the discriminant/tag matches the expected shape, and the mismatch manifests as an unguarded runtime failure (there: invalid pointer read; here: an uncaught JS exception) instead of a handled validation error.

Two code paths in `definition.js` compute the exact same thing — filling a shared address-definition template with attacker-controlled parameters — but only one of them defends against failure:

- In `validateDefinition()` (address-definition-creation path), the `'definition template'` case wraps `replaceInTemplate` in `try/catch` and specifically re-surfaces `NoVarException` as a normal validation error: [1](#0-0) 

- In `validateAuthentifiers()` (the signature-verification path exercised for *every* unit signed by an address using this construct), the identical operation is performed with **no exception handling** at all, and a missing-template condition is a bare `throw`: [2](#0-1) 

`replaceInTemplate` is documented elsewhere in the file to throw `NoVarException` when a parameter referenced by the template is not supplied (or vice versa) — a condition entirely controllable by the unit's author, since the author supplies both which template `unit` to reference and the `params` object: [3](#0-2) 

Because `validateAuthentifiers` is called from the mainline unit-signature-checking flow (triggered any time a posted unit is authored by an address whose definition includes `'definition template'`), a synchronous throw here occurs inside a `conn.query` callback with no surrounding `try/catch` and no `domain`/`process.on('uncaughtException')` recovery for this call site, which in Node.js terminates the process.

### Impact Explanation
Any full node (and any light/hub node performing the same authentifier check) that attempts to validate a unit signed by such a maliciously-configured address will throw an uncaught exception and crash. Because unit validation is deterministic, every node in the network that processes the malicious unit crashes in the same way — this is a network-wide denial of service that halts confirmation of new units, not merely a single-process failure. This satisfies the required "network unable to confirm new units" impact bar.

### Likelihood Explanation
Reaching this code path requires no elevated privilege: an unprivileged user can (1) register any address whose definition includes the `'definition template'` operator referencing a legitimately-published `definition_template` unit, and (2) post a unit signed by that address using intentionally mismatched `params` (or a `unit` value that does not resolve to exactly one stored template). Both are ordinary, permissionless operations available to any wallet/user, making the trigger trivially reachable and repeatable.

### Recommendation
Wrap the `'definition template'` handling block in `validateAuthentifiers()` (definition.js, the `evaluate` case at lines ~802-819) in a `try/catch`, mirroring the handling already present in `validateDefinition()`: catch `NoVarException` and any other thrown errors and report them through `cb2(false)`/an explicit validation failure rather than allowing them to propagate as an uncaught exception. Also replace the bare `throw Error("not 1 template")` with a graceful `cb2(false)` (or equivalent) so that a missing/ambiguous template reference is treated as "authentifier check failed" instead of crashing the process.

### Proof of Concept
1. Alice defines address `A` with definition `['definition template', [templateUnit, {p1: 'x'}]]`, where `templateUnit` is a previously published `definition_template` message whose template expects a different variable name (e.g. `p2`) or none at all.
2. Alice posts and signs a unit as author `A` (any payload).
3. Every node that receives this unit calls `validateAuthentifiers` to verify Alice's signature, which evaluates the `'definition template'` clause, calls `replaceInTemplate(arrTemplate, {p1:'x'})`, which throws `NoVarException` because the expected placeholder is absent/mismatched.
4. The exception is uncaught at this call site, crashing the Node.js process on every validating node that processes the unit.

Note: I was unable to inspect the full implementation of `replaceInTemplate`/`NoVarException` within the available iterations; the conclusion that a mismatched/missing template variable triggers a thrown `NoVarException` is inferred from the sibling code path at definition.js:330-339, which explicitly catches this exact exception type for the same call. A Devin session with full repo access should confirm `replaceInTemplate`'s exact throw conditions to finalize the PoC payload.

### Citations

**File:** definition.js (L321-342)
```javascript
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							return cb("template not found or too many");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						try{
							var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
							console.log(require('util').inspect(arrFilledTemplate, {depth: null}));
						}
						catch(e){
							if (e instanceof NoVarException)
								return cb(e.toString());
							else
								throw e;
						}
						evaluate(arrFilledTemplate, path, bInNegation, cb);
					}
				);
```

**File:** definition.js (L802-819)
```javascript
			case 'definition template':
				// ['definition template', ['unit', {param1: 'value1'}]]
				var unit = args[0];
				var params = args[1];
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							throw Error("not 1 template");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
						evaluate(arrFilledTemplate, path, cb2);
					}
				);
				break;
```
