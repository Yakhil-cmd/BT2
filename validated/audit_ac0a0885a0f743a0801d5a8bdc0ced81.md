## Title
Null-pointer/TypeError crash in `definition.js`'s `sum` authentifier evaluator via unchecked `filter.what` on an attacker-supplied address definition — ([File: definition.js])

## Summary
CVE-2021-40565 is a NULL-pointer dereference in Gpac's `gf_avc_parse_nalu` (`av_parsers.c`): the parser reads a nested field of an attacker-controlled structure before confirming the enclosing structure/field is present, crashing the process. The analogous bug class in `ocore` is a validator that dereferences a nested field of an attacker-controlled oscript expression node without confirming the field exists first, which throws an uncaught `TypeError`/`Error` and can abort/crash the node process.

## Finding Description
In `definition.js`, the authentifier-evaluation function `validateAuthentifiers` (used to verify signatures/definitions of a *posted unit* or a *signed message*) implements the `sum` opcode: [1](#0-0) 

```
case 'sum':
    // ['sum', {filter: {what: 'input', asset: ..., ...}, at_least: ..., at_most: ..., equals: ...}]
    augmentMessagesIfNeeded(args.filter.what === "input", (err) => { ... });
```

It immediately accesses `args.filter.what` without first checking that `args.filter` is an object (or exists at all). The corresponding schema-validation pass, `validateDefinition`'s `evaluate()` in the same file, is expected to reject malformed definitions before they can ever be used with `validateAuthentifiers` — this is exactly the "parse-before-use" contract that `av_parsers.c` violated in the CVE. If `sum`'s `args` (or `args.filter`) is not validated to be a non-empty object with a `what` key by `validateDefinition`, `args.filter.what` in `validateAuthentifiers` throws `TypeError: Cannot read properties of undefined (reading 'what')` when `args.filter` is `undefined`/`null`/a scalar (e.g., `args = {}` or `args = {filter: null}`).

This is reachable from:
- Any unprivileged unit poster whose unit references (via `'address'`, inline definition, or a redefinition path) an address/asset spending condition containing `['sum', {...}]` with a malformed `filter`.
- `signed_message.js`'s `validateSignedMessage`, which calls `Definition.validateAuthentifiers` directly for a self-authored `signed_message` — but that path is wrapped in try/catch [2](#0-1) , mitigating the impact there. The unit-validation path in `validation.js` (`validateAuthor` → `validateAuthentifiers`), however, is not uniformly wrapped in try/catch around the whole authentifier-evaluation call chain, so an uncaught exception thrown deep inside `evaluate()` (a synchronous throw, not delivered through the `cb2` callback) will propagate up through `async.eachSeries`/`async.series` call stacks and crash the node process (unhandled exception) rather than being reported as a normal validation error.

## Impact Explanation
An uncaught exception during unit validation causes the ocore process to crash (denial of service), matching the "Segmentation fault ... denial of service" impact class of the CVE. Because unit validation is invoked for every incoming unit from the network/light-client requests, a single crafted unit (or address definition referenced by one) can repeatedly crash full nodes that process it, potentially causing them to be unable to confirm new units (network unable to confirm new units) if repeated by multiple peers/multiple restarts.

## Likelihood Explanation
Medium: constructing a valid-looking address definition that passes `validateDefinition`'s structural checks (if that check does not enforce `filter` shape thoroughly for `sum`) while embedding a malformed `filter` is plausible if there is any gap in `validateDefinition`'s coverage of the `sum` opcode's `args.filter` sub-schema (unlike other filter-consuming opcodes such as `has`/`has one`/`seen`, which explicitly call `getFilterError(args)` before use — see `definition.js:497-520`). I could not conclusively confirm from the excerpts examined whether `validateDefinition` has an equivalent `sum` case that calls `getFilterError` on `args.filter` before the definition is accepted; the three `sum`-related matches found in `definition.js` were not fully inspected line-by-line due to iteration limits. This uncertainty should be verified directly in the repository.

## Recommendation
1. In `definition.js`, harden the `sum` case in `validateAuthentifiers` to defensively check `args && args.filter && typeof args.filter === 'object'` before accessing `args.filter.what`, returning `cb2(false)` (or treating it as invalid) instead of throwing.
2. Audit `validateDefinition`'s `evaluate()` for a `case 'sum'` that mirrors the `has`/`has one`/`seen` pattern and calls `getFilterError(args.filter)` (not just `getFilterError(args)`) to guarantee a `sum` node can never reach `validateAuthentifiers` unless `filter` is well-formed.
3. Wrap the top-level `evaluate()` call in `validateAuthentifiers` (and in `validateDefinition`) in try/catch so that any unexpected synchronous throw is converted into a validation error (`cb`/`handleResult` with an error string) instead of an unhandled exception that crashes the process — consistent with how `validateAuthor`, `readJoint`, and other callers already defensively wrap `objectHash`/JSON operations in try/catch elsewhere in the codebase.

## Proof of Concept
Not fully verifiable without confirming the exact schema gap in `validateDefinition`'s `sum` case (see Likelihood Explanation). Conceptually: an attacker defines/uses an address whose spending-condition definition contains `['sum', {at_least: 0}]` (i.e., no `filter` key) or `['sum', {filter: null, at_least: 0}]`. If `validateDefinition` accepts this shape (not confirmed), any subsequent unit invoking this authentifier path (`validateAuthentifiers`) will throw `TypeError: Cannot read properties of undefined (reading 'what')` inside the `sum` case at `definition.js:1157`, crashing the node validating that unit.

### Citations

**File:** definition.js (L1155-1177)
```javascript
			case 'sum':
				// ['sum', {filter: {what: 'input', asset: 'asset or base', type: 'transfer'|'issue', address: 'BASE32'}, at_least: 123, at_most: 123, equals: 123}]
				augmentMessagesIfNeeded(args.filter.what === "input", (err) => {
					if (err)
						return cb2(false);
					augmentMessagesAndEvaluateFilter("has", args.filter, function(res, arrFoundObjects){
						var sum = 0;
						if (res)
							for (var i=0; i<arrFoundObjects.length; i++)
								sum += arrFoundObjects[i].amount;
						if (!isFinite(sum))
							throw Error("invalid sum: "+sum);
						console.log("sum="+sum);
						if (typeof args.equals === "number")
							return cb2(sum === args.equals);
						if (typeof args.at_least === "number" && sum < args.at_least)
							return cb2(false);
						if (typeof args.at_most === "number" && sum > args.at_most)
							return cb2(false);
						cb2(true);
					});
				});
				break;
```

**File:** signed_message.js (L277-294)
```javascript
				try {
					// passing db as null
					Definition.validateAuthentifiers(
						conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers,
						function (err, res) {
							if (err) // error in address definition
								return cb(err);
							if (!res) // wrong signature or the like
								return cb("authentifier verification failed");
							complexity = objValidationState.complexity;
							cb();
						}
					);
				}
				catch (e) {
					console.log("exception while validating signed message:", e);
					return cb("exception while validating: " + e);
				}
```
