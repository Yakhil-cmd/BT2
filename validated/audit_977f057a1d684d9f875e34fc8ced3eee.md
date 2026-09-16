### Title
Unit hash/signature-hash computation recurses over the entire unstructured JSON object before the size/depth limit check rejects it - (File: validation.js)

### Summary
`validation.validate()` calls `objectHash.getUnitHash(objUnit)` (which recursively walks every string/number/array/object field of the untrusted posted unit via `getSourceString`/`getJsonSourceString` in `string_utils.js`) *before* it calls `isTooDeeplyNestedOrHasTooManyNodes(objUnit)`, the function whose sole purpose is to cap the cost of exactly this kind of recursive walk.

### Finding Description
In `validate()`: [1](#0-0) 
the unit hash is computed by recursively concatenating every field of `objUnit` (`objectHash.getUnitHash` → `getStrippedUnit`/`getNakedUnit` → `getBase64Hash` → `getSourceString`/`getJsonSourceString`), which does a full unbounded depth/array-length recursion: [2](#0-1) [3](#0-2) 

Only *after* this expensive recursive hash has already been computed does the code call the guard that is supposed to bound the cost of walking the object: [4](#0-3) 
```
if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
    return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");
```
`isTooDeeplyNestedOrHasTooManyNodes` itself is defined with a depth limit of 100 and a node-count limit of 10000: [5](#0-4) 

This mirrors the Netty SPDY pattern precisely: a nominal "maxHeaderSize"/`isTooDeeplyNestedOrHasTooManyNodes`-style limit exists, but it is enforced only *after* the expensive decode/hash pass has already fully processed the oversized/deeply-nested payload. Since `objUnit` comes straight from `objJoint.unit` in a posted joint with no upstream size restriction applied before this point (the only earlier check is `isStringOfLength(objUnit.unit, ...)`, which does not bound the rest of the object), an unprivileged peer can post a single unit whose `messages`/`payload` (or any other field) contains a JSON structure that is arbitrarily deeply nested or has an arbitrarily large number of nodes/array entries. `getSourceString`'s `extractComponents` recurses once per nesting level with no depth cap and iterates once per array element/object key with no count cap, so the CPU cost of hash computation scales with the attacker-controlled node count/depth, not with any pre-checked bound — the size limit that exists (`isTooDeeplyNestedOrHasTooManyNodes`) is evaluated only afterward, and by then the expensive recursive work has already been fully performed.

### Impact Explanation
A single unprivileged unit poster can submit a joint whose unit JSON is extremely deep or has an extreme node count within (or even slightly above, since the true guard runs after) the `MAX_UNIT_LENGTH` byte budget, forcing every full/light node that receives and validates the joint to perform expensive, effectively unbounded recursive traversal/hash computation (`getSourceString`) before the request is rejected. Because JS recursion for `extractComponents`/`isTooDeeplyNestedOrHasTooManyNodes` is depth-based, sufficiently deep nesting can also trigger a stack overflow inside the hashing routine itself, i.e. before the node-limit check that would otherwise catch it, causing the validating process to crash. This is a compression-amplification-style, decode-before-limit CPU/stack exhaustion analogous to the Netty SPDY bug: reachable by any peer that can post a unit to a node's validation pipeline, causing denial of service (CWE-400) rather than direct fund loss.

### Likelihood Explanation
High reachability: `validate()` is the entry point for every unit a node receives from the p2p network or from its own wallet composing joints, and the check ordering (hash first, structural-limit check second) is unconditional and applies to every unit, including from unauthenticated/unprivileged posters. No additional preconditions (special signatures, specific mci, etc.) are needed—only a syntactically well-formed JSON unit object that passes the earlier lightweight `isStringOfLength`/`objUnit.unit` checks.

### Recommendation
Move the `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` check (and ideally a raw byte-size check on the serialized joint) to occur immediately after parsing the incoming joint and before any hash computation (`objectHash.getUnitHash`), so that no recursive traversal of attacker-controlled JSON structures is ever performed on an object that would ultimately be rejected for being too deeply nested or having too many nodes. Additionally, consider making `getSourceString`/`getJsonSourceString`/`extractComponents` themselves depth- and node-limited (mirroring `isTooDeeplyNestedOrHasTooManyNodes`) so that even if invoked directly (e.g. via other callers such as `getUnitHashToSign`, `getBallHash`, `getDeviceMessageHashToSign`) they cannot be driven into unbounded recursive work by attacker-supplied data.

### Proof of Concept
1. Craft a joint whose `unit` object contains a `messages` array where one message's `payload` field is a deeply nested array/object structure, e.g. `["a",["a",["a", ... ]]]` nested thousands of levels deep, or an array with hundreds of thousands of trivial elements, kept under `constants.MAX_UNIT_LENGTH` (5e6 bytes) in raw serialized size but with pathological structure (many short tokens instead of few long strings).
2. Submit this joint to a node exactly as an ordinary unit (`objJoint.unit`), triggering `validation.validate(objJoint, callbacks)`.
3. Observe that `objectHash.getUnitHash(objUnit)` at `validation.js:133` recurses through the entire structure via `getSourceString`/`extractComponents` before `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` at `validation.js:154` gets a chance to reject it, causing measurable CPU stall or, for sufficiently deep nesting, a stack-overflow exception inside the hash computation rather than the intended `ifJointError("unit is too deeply nested")`.

Note: I was unable to run this PoC in a live environment to measure exact timing/stack-depth thresholds; the finding above is based on static analysis of the ordering of checks in `validation.js`, `object_hash.js`, and `string_utils.js`. Confirming precise resource consumption or the exact stack-depth needed to crash a node would require execution, which is outside the scope of this ask-only analysis.

### Citations

**File:** validation.js (L128-138)
```javascript
	if (!isStringOfLength(objUnit.unit, constants.HASH_LENGTH))
		return callbacks.ifJointError("wrong unit length");
	
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

**File:** string_utils.js (L11-59)
```javascript
function getSourceString(obj) {
	var arrComponents = [];
	function extractComponents(variable){
		if (variable === null)
			throw Error("null value in "+JSON.stringify(obj));
		switch (typeof variable){
			case "string":
				if (variable.includes(STRING_JOIN_CHAR))
					throw Error("00 byte in string value in " + JSON.stringify(obj));
				arrComponents.push("s", variable);
				break;
			case "number":
				if (!isFinite(variable))
					throw Error("invalid number: " + variable);
				arrComponents.push("n", variable.toString());
				break;
			case "boolean":
				arrComponents.push("b", variable.toString());
				break;
			case "object":
				if (Array.isArray(variable)){
					if (variable.length === 0)
						throw Error("empty array in "+JSON.stringify(obj));
					arrComponents.push('[');
					for (var i=0; i<variable.length; i++)
						extractComponents(variable[i]);
					arrComponents.push(']');
				}
				else{
					var keys = Object.keys(variable).sort();
					if (keys.length === 0)
						throw Error("empty object in "+JSON.stringify(obj));
					keys.forEach(function(key){
						if (typeof variable[key] === "undefined")
							throw Error("undefined at "+key+" of "+JSON.stringify(obj));
						if (key.includes(STRING_JOIN_CHAR))
							throw Error("00 byte in object key in " + JSON.stringify(obj));
						arrComponents.push(key);
						extractComponents(variable[key]);
					});
				}
				break;
			default:
				throw Error("getSourceString: unknown type="+(typeof variable)+" of "+variable+", object: "+JSON.stringify(obj));
		}
	}

	extractComponents(obj);
	return arrComponents.join(STRING_JOIN_CHAR);
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

**File:** object_hash.js (L56-65)
```javascript
function getUnitContentHash(objUnit){
	return getBase64Hash(getNakedUnit(objUnit), objUnit.version !== constants.versionWithoutTimestamp);
}

function getUnitHash(objUnit) {
	var bVersion2 = (objUnit.version !== constants.versionWithoutTimestamp);
	if (objUnit.content_hash) // already stripped and objUnit doesn't have messages
		return getBase64Hash(getNakedUnit(objUnit), bVersion2);
	return getBase64Hash(getStrippedUnit(objUnit), bVersion2);
}
```
