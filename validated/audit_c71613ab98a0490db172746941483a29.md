### Title
Recursive-descent unit hashing runs before the depth-limit check, allowing stack-overflow DoS from a crafted joint - ([File: validation.js], [File: object_hash.js], [File: string_utils.js])

### Summary
`validation.js`'s `validate()` function computes `objectHash.getUnitHash(objUnit)` to verify the unit hash **before** it runs the unbounded-recursion guard `isTooDeeplyNestedOrHasTooManyNodes(objUnit)`. `getUnitHash()` funnels into `getSourceString`/`getJsonSourceString` in `string_utils.js`, which are classic recursive-descent stringifiers that walk the object graph with no depth bound of their own — exactly the same bug class as the SCIM PEG-grammar recursion in the external report: an unbounded recursive traversal is executed before the code path that is supposed to bound recursion depth.

### Finding Description
In `validation.js`: [1](#0-0) 
`objectHash.getUnitHash(objUnit)` is invoked to check the unit hash, and only afterwards, at [2](#0-1) 
does the code call `isTooDeeplyNestedOrHasTooManyNodes(objUnit)`, which is the function meant to reject pathologically nested/huge units.

`getUnitHash()` (`object_hash.js:60-65`) calls `getBase64Hash(getStrippedUnit(objUnit), ...)` or `getNakedUnit`, both of which serialize via `getSourceString`/`getJsonSourceString`: [3](#0-2) 
`getJsonSourceString`'s `stringify()` helper recurses into every array element / object value with **no depth counter or bound** — it only memoizes by object identity, not by depth: [4](#0-3) 

Compare this to `isTooDeeplyNestedOrHasTooManyNodes`, which *does* carry an explicit depth parameter and bails out early: [5](#0-4) 
— but this safety net is invoked only after the unbounded hashing recursion has already run to completion (or overflowed) in `validate()`.

This exactly parallels the CVE root cause: “the existing semantic depth limit … is enforced … after the parse has already produced [walked] the structure, so it cannot prevent the [recursive walk] itself from blowing the stack.”

### Impact Explanation
An attacker who can get a crafted joint into `validate()` (e.g., via `validateLight()` used by light-wallet peers, or any other caller that constructs/receives a joint object before the network-layer `isTooDeeplyNestedOrHasTooManyNodes` pre-filters seen in `network.js` at lines 995, 2874, and 3353) can supply a unit whose `messages`/`payload` contains thousands of nested arrays/objects. When `validate()` reaches line 133 and calls `getUnitHash → getSourceString/getJsonSourceString`, the unguarded recursion can exhaust the V8 call stack before the depth check at line 154 ever executes.

**Important caveat/uncertainty:** unlike Rust, a V8/Node.js stack overflow normally throws a catchable `RangeError: Maximum call stack size exceeded`, and the `getUnitHash()` call in `validate()` is wrapped in a `try { … } catch(e) { return callbacks.ifJointError(...) }` block (`validation.js:131-138`), so in the common case this would be caught and turned into a joint-validation error rather than a hard process abort. I could not fully verify, within the remaining investigation budget, whether every reachable caller of `validate()`/`validateLight()` is preceded by the network-layer `isTooDeeplyNestedOrHasTooManyNodes` gate, nor whether any recursive native (C++) operations inside the hash/stringify path (as opposed to pure JS recursion) could bypass V8's catchable-exception guard and hard-crash the process the way Rust's `process::abort()` does. This uncertainty means the severity here is likely lower than the CVE's "High" (unauthenticated full-process abort) — most probably this degrades to a per-unit validation failure rather than a node crash, unless a caller path exists that skips the outer nested-object filter.

### Likelihood Explanation
Likelihood is limited by the fact that the three network entry points that hand joints to `validate()`/`handleOnlineJoint`/`handlePostedJoint` (`network.js:995`, `network.js:2874`, `network.js:3353`) already invoke `isTooDeeplyNestedOrHasTooManyNodes` before reaching `validate()`, which would filter out the malicious deep-nesting payload before it ever reaches the vulnerable `getUnitHash()` call inside `validate()`. The `validateLight()` entry point (`validation.js:97-116`), however, calls `validate()` directly without a preceding nested-object check, and I was unable to confirm within this session whether all of its actual callers pre-filter the joint elsewhere.

### Recommendation
Move the `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` check in `validate()` (`validation.js:154`) to execute **before** the `objectHash.getUnitHash(objUnit)` call at `validation.js:133`, so that no recursive hashing/stringification ever executes on an object that hasn't already been bounded for depth and node count. Additionally, add an explicit depth guard inside `getSourceString`/`getJsonSourceString` (`string_utils.js`) itself, mirroring the depth parameter already used in `isTooDeeplyNestedOrHasTooManyNodes`, so the hashing routines are safe by construction regardless of call order, and confirm that `validateLight()` and any other direct callers of `validate()` are always preceded by (or wrap) a nested-object depth check.

### Proof of Concept
Construct a unit whose payload contains deeply nested arrays, e.g. a message payload equal to `JSON.parse('['.repeat(50000) + '1' + ']'.repeat(50000))`, embed it in a unit/joint object, and feed it into `validateLight(objJoint)` (or any `validate()` call path that is not preceded by the network-layer `isTooDeeplyNestedOrHasTooManyNodes` check). During hash verification (`objectHash.getUnitHash(objUnit)` → `getSourceString`/`getJsonSourceString`), the recursive stringifier will attempt to descend 50,000 levels, which is well beyond typical Node.js default stack limits (~10,000–15,000 frames depending on frame size), triggering a stack-overflow condition before the code reaches the `isTooDeeplyNestedOrHasTooManyNodes` bound-check at `validation.js:154`. Whether this manifests as a caught `RangeError` (most likely, given the surrounding `try/catch`) or a harder crash depends on call-path specifics not fully verified in this session.

### Citations

**File:** validation.js (L131-138)
```javascript
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}
```

**File:** validation.js (L154-155)
```javascript
	if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
		return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");
```

**File:** object_hash.js (L27-30)
```javascript
function getBase64Hash(obj, bJsonBased) {
	var sourceString = bJsonBased ? getJsonSourceString(obj) : getSourceString(obj)
	return crypto.createHash("sha256").update(sourceString, "utf8").digest("base64");
}
```

**File:** string_utils.js (L220-257)
```javascript
function getJsonSourceString(obj, bAllowEmpty) {
	let cache = new WeakMap();  // object to stringified result
	function stringify(variable){
		if (variable === null)
			throw Error("null value in "+JSON.stringify(obj));
		switch (typeof variable){
			case "string":
				return toWellFormedJsonStringify(variable);
			case "number":
				if (!isFinite(variable))
					throw Error("invalid number: " + variable);
			case "boolean":
				return variable.toString();
			case "object":
				// return cached result if already processed
				if (cache.has(variable))
					return cache.get(variable);
				let result;
				if (Array.isArray(variable)){
					if (variable.length === 0 && !bAllowEmpty)
						throw Error("empty array in "+JSON.stringify(obj));
					result = '[' + variable.map(stringify).join(',') + ']';
				}
				else{
					var keys = Object.keys(variable).sort();
					if (keys.length === 0 && !bAllowEmpty)
						throw Error("empty object in "+JSON.stringify(obj));
					result = '{' + keys.map(function(key){ return toWellFormedJsonStringify(key)+':'+stringify(variable[key]) }).join(',') + '}';
				}
				cache.set(variable, result);  // memoize for future references
				return result;
			default:
				throw Error("getJsonSourceString: unknown type="+(typeof variable)+" of "+variable+", object: "+JSON.stringify(obj));
		}
	}

	return stringify(obj);
}
```

**File:** string_utils.js (L260-284)
```javascript
function isTooDeeplyNestedOrHasTooManyNodes(obj, depthLimit = 100, nodesLimit = 10000) {
	let nodeCount = 0;

	function check(variable, depth){
		if (depth > depthLimit || nodeCount > nodesLimit)
			return true;
		if (variable === null || typeof variable !== "object")
			return false;
		if (Array.isArray(variable)) {
			nodeCount += variable.length;
			for (let v of variable)
				if (check(v, depth + 1))
					return true;
		}
		else {
			nodeCount += Object.keys(variable).length;
			for (let key in variable)
				if (check(variable[key], depth + 1))
					return true;
		}
		return false;
	}

	return check(obj, 1);
}
```
