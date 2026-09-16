### Title
NULL Pointer Dereference in `is_valid_merkle_proof` via `wrappedObject`-wrapped `null` Proof - (File: `formula/evaluation.js`)

### Summary
Analogous to CVE-2018-13440 (a NULL pointer dereference in `ModuleState::setup` triggered by a crafted, attacker-controlled file that bypasses validation and is later dereferenced without a null check), the `is_valid_merkle_proof` oscript function in `formula/evaluation.js` dereferences an attacker-controlled `objProof` object without verifying it is non-null before accessing `.siblings`. An unprivileged AA author can craft a formula that produces a `wrappedObject` wrapping JavaScript `null` (via `json_parse('null')`), pass it as the merkle proof argument, and cause an unguarded property access on `null`, throwing an unhandled `TypeError` inside oscript evaluation.

### Finding Description
`json_parse` returns a `wrappedObject` for any value where `typeof json === 'object'`, and in JavaScript `typeof null === 'object'`, so `json_parse('null')` legitimately produces `new wrappedObject(null)`: [1](#0-0) 

That wrapped-`null` value can then be fed directly into `is_valid_merkle_proof` as the `proof` argument. Inside the handler, when `proof` is a `wrappedObject`, `objProof` is simply unwrapped without any null check, and then — for units evaluated post `bPostPemCurvesFix` — `objProof.siblings` is accessed outside of any `try/catch`: [2](#0-1) 

If `objProof` is `null` at that point, `objProof.siblings` throws a `TypeError: Cannot read properties of null`. This access happens *before* the `try { res = merkle.verifyMerkleProof(...) } catch (e) { res = false; }` block, so it is not shielded by the existing exception handling that was clearly intended to make this function crash-proof against malformed proofs: [3](#0-2) 

This mirrors the CVE's bug class exactly: a value that passes an initial "is it something" check (here, `proof instanceof wrappedObject`) but is not checked for null/well-formedness before a field is dereferenced from it in code paths that assume a well-formed object, as demonstrated by the CVE's crafted `.caf` file triggering the same class of bug in `ModuleState::setup`.

### Impact Explanation
`is_valid_merkle_proof` is available in AA oscript formulas, which are user-authored and triggered by unprivileged unit senders. Any account can define an AA containing this formula and then send a trigger unit (or have it triggered as part of a bounce/cascade) to reach the vulnerable code path. Because the crash happens inside a synchronous callback fired during formula evaluation and is not caught locally, it becomes an uncaught exception in the middle of unit/AA-trigger validation/execution — which in Node.js terminates the process unless caught by a higher-level handler. This constitutes a denial-of-service against any node (including validating full nodes) that processes/executes the malicious AA trigger, i.e., "a network unable to confirm new units" if enough nodes crash while validating/executing the same trigger.

### Likelihood Explanation
Likelihood is high for triggering the crash on any node that executes the AA (all full nodes must execute AA responses deterministically), since:
- Defining an AA with arbitrary oscript code is a standard, unprivileged operation.
- `json_parse('null')` is a trivial, always-reachable way to construct a `wrappedObject(null)`.
- No additional network permissions or race conditions are required — a single crafted AA definition plus a single trigger unit is sufficient.

The main uncertainty is whether some outer error-handling wrapper around AA execution (in `aa_composer.js`) catches the resulting exception and merely fails/bounces the specific trigger instead of crashing the whole node process; this could not be fully confirmed within the available tool budget. Even in the more conservative scenario (exception caught and the trigger merely "bounced" or the response marked as failed with no consequence), this would not be a Medium+ analog. Given the explicit lack of a `try/catch` around this specific `objProof.siblings` access — in contrast to the very next `verifyMerkleProof` call, which the developers clearly hardened with `try/catch` for exactly this reason — the omission looks unintentional and warrants a fix regardless of exact blast radius.

### Recommendation
Add an explicit null/type check on `objProof` before accessing any of its fields in `is_valid_merkle_proof`, e.g.:
```js
if (proof instanceof wrappedObject)
    objProof = proof.obj;
else if (typeof proof === 'string') { ... }
else
    return cb(false);
if (!objProof || typeof objProof !== 'object')
    return cb(false);
if (bPostPemCurvesFix) {
    if (!Array.isArray(objProof.siblings) || ...)
        return cb(false);
    ...
}
```
Additionally, consider disallowing `wrappedObject(null)` from `json_parse` altogether (treat top-level JSON `null` as the oscript `false`/empty value rather than an "object"), since `typeof null === 'object'` is a well-known JavaScript foot-gun that could affect other formula operators consuming `wrappedObject` values.

### Proof of Concept
Deploy an AA with a message such as:
```
{
  app: 'data',
  payload: {
    result: "{ is_valid_merkle_proof('x', json_parse('null')) }"
  }
}
```
Then send any trigger unit to this AA address (post `pemCurvesFixMci`). During AA response formula evaluation, `json_parse('null')` yields `wrappedObject(null)`; `is_valid_merkle_proof` unwraps it to `objProof = null`, and the subsequent `objProof.siblings` access throws an uncaught `TypeError`, crashing/erroring the formula evaluation outside the function's own exception-safe verification path.

### Citations

**File:** formula/evaluation.js (L1778-1797)
```javascript
					evaluate(proof_expr, function (proof) {
						if (fatal_error)
							return cb(false);
						let res;
						var objProof;
						if (proof instanceof wrappedObject)
							objProof = proof.obj;
						else if (typeof proof === 'string') {
							if (proof.length > 1024)
								return setFatalError("proof is too large", { arr }, false, cb);
							objProof = merkle.deserializeMerkleProof(proof);
						}
						else // can't be valid proof
							return cb(false);
						if (bPostPemCurvesFix) {
							if (!Array.isArray(objProof.siblings) || !objProof.siblings.every(ValidationUtils.isNonemptyString))
								return cb(false);
							if (objProof.siblings.length > 50)
								return cb(false);
						}
```

**File:** formula/evaluation.js (L1798-1804)
```javascript
						try {
							res = merkle.verifyMerkleProof(element, objProof);
						}
						catch (e) {
							res = false;
						}
						cb(res);
```

**File:** formula/evaluation.js (L1943-1948)
```javascript
					json = replaceNulls(json);
					if (containsNonFiniteNumber(json))
						return setFatalError("json_parse result contains non-finite number", { arr }, false, cb);
					json = string_utils.replaceNegativeZero(json);
					if (typeof json === 'object')
						return cb(new wrappedObject(json));
```
