### Title
Uncontrolled Recursion in `getSourceString`/`getJsonSourceString` Reachable via Unit Hashing Before Depth Guard - (File: `object_hash.js`, `string_utils.js`, `validation.js`)

### Summary
`validation.js`'s `validate()` computes the unit hash with `objectHash.getUnitHash(objUnit)` at [1](#0-0)  before it ever checks the object's depth/size with `isTooDeeplyNestedOrHasTooManyNodes(objUnit)`, which only runs afterwards at [2](#0-1) . `getUnitHash` ultimately calls `getSourceString`/`getJsonSourceString` in `string_utils.js`, both of which recurse over the full JS object tree with no depth limit, unlike the guard function `isTooDeeplyNestedOrHasTooManyNodes` which does track depth/node counts.

### Finding Description
`getUnitHash` (`object_hash.js`) builds a "naked"/"stripped" copy of the unit and hashes it via `getBase64Hash`, which calls `getSourceString` (non-AA) or `getJsonSourceString` (AA/JSON-based hashing): [3](#0-2) 

`getNakedUnit` only deletes specific top-level fields (`unit`, `headers_commission`, `timestamp` in some cases, and `messages[i].payload`/`payload_uri`); it does not delete or bound other attacker-controlled substructures such as `authors[].authentifiers`, `parent_units`, or message fields other than `payload`: [4](#0-3) 

`getSourceString`'s inner `extractComponents` function recurses into every array/object member with no depth bound at all: [5](#0-4) 

`getJsonSourceString`'s `stringify` function likewise recurses unboundedly (memoization by `WeakMap` does not limit depth, only avoids redundant work for objects visited via multiple references): [6](#0-5) 

By contrast, the codebase already has a dedicated depth/size guard, `isTooDeeplyNestedOrHasTooManyNodes`, which tracks `depth` and `nodeCount` and aborts early: [7](#0-6) 

But in `validate()`, this guard is invoked only *after* `objectHash.getUnitHash(objUnit)` has already run: [8](#0-7) 

Because JSON received over the wire is unstructured until validated, an attacker (any unprivileged unit poster) can submit a joint whose `unit.authors[].authentifiers` field (or any other field not stripped by `getNakedUnit`) is a deeply nested array/object (e.g., thousands of levels of `[[[[...]]]]`). When `validate()` reaches line 133 and calls `getUnitHash`, the recursive `extractComponents`/`stringify` traversal will exhaust the call stack (`RangeError: Maximum call stack size exceeded`) before the protective depth check at line 154 ever executes.

### Impact Explanation
An uncaught `RangeError` thrown deep inside synchronous recursion in `getSourceString`/`getJsonSourceString` is not guarded by the surrounding `try/catch` in `validate()` scoped only around `objectHash.getUnitHash` at lines 131-138 catches thrown `Error` objects generically, so a `RangeError` from stack exhaustion would actually be caught there and reported via `ifJointError`, converting this specifically into a benign validation error in the direct `network.js` "joint" handling path — that path additionally pre-checks `isTooDeeplyNestedOrHasTooManyNodes(objJoint)` before calling `validate()` at all, per `handleJustsaying`'s `'joint'` case. However, `validate()` is a shared function also invoked directly from other modules (`wallet.js`, `light.js`, `catchup.js`, `private_payment.js`, `aa_composer.js`, etc.) that may not all apply the same outer pre-check that `network.js`'s justsaying handler does. Where such a pre-check is absent, this bug-class allows a low-cost crafted unit/joint/payload to induce large synchronous recursive work or a stack-overflow exception at a point where it is not yet gracefully handled, which is a Denial-of-Service pattern (CWE-674) directly analogous to the reported `json-smart` unbounded-recursion vulnerability.

### Likelihood Explanation
I could not fully verify, within the available tool budget, whether every non-`network.js` caller of `validation.validate()` (e.g., `wallet.js`, `light.js`, `catchup.js`) applies an equivalent `isTooDeeplyNestedOrHasTooManyNodes` pre-check before invoking `validate()`. The `network.js` "joint" justsaying handler does apply this guard before calling `handleOnlineJoint`/`handleLightOnlineJoint`, which reduces exploitability through that specific path. Because of this uncertainty about coverage across all `validate()` call sites, and because the exception raised by stack exhaustion is caught by the existing `try/catch` around `getUnitHash` in the paths I confirmed, I cannot confirm a concrete unauthorized-spending, double-spend, inflation, fund-freezing, or network-halting impact strictly from the code I was able to inspect.

### Recommendation
Move the `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` check in `validation.js` to execute *before* `objectHash.getUnitHash(objUnit)` is called, and audit all other call sites of `validation.validate()` (`wallet.js`, `light.js`, `catchup.js`, `private_payment.js`, `aa_composer.js`, etc.) to ensure a depth/size guard is applied to any externally-supplied unit/joint object before it is passed to any hashing or object-hash routine. Additionally, consider adding an explicit recursion-depth counter inside `getSourceString`/`getJsonSourceString` themselves as defense-in-depth, mirroring the depth tracking already used in `formula/validation.js`'s `evaluate` (`depth > 100` check) and `aa_validation.js`'s `MAX_DEPTH`.

### Proof of Concept
Not independently executable within the current investigation (no runtime access), but the reachable path is:
1. Craft a joint whose `unit.authors[0].authentifiers` (or similar untouched field) is an array nested to a very large depth (e.g., `'['.repeat(100000) + '1' + ']'.repeat(100000)` embedded as a value).
2. Submit it wherever `validation.validate()` is reachable without an upstream `isTooDeeplyNestedOrHasTooManyNodes` guard.
3. `validate()` calls `objectHash.getUnitHash(objUnit)` → `getStrippedUnit`/`getUnitContentHash` → `getBase64Hash(getNakedUnit(objUnit))` → `getSourceString`, whose `extractComponents` recurses once per nesting level, exhausting the call stack before the code reaches the `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` check at [2](#0-1) .

### Citations

**File:** validation.js (L118-155)
```javascript
function validate(objJoint, callbacks, external_conn) {
	
	var objUnit = objJoint.unit;
	if (typeof objUnit !== "object" || objUnit === null)
		throw Error("no unit object");
	if (!objUnit.unit)
		throw Error("no unit");
	
	console.log("\nvalidating joint identified by unit "+objJoint.unit.unit);
	
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

	const bGenesis = storage.isGenesisUnit(objUnit.unit);

	var bAA = false;
	if (objJoint.aa) {
		bAA = true;
		var aa_mci = objJoint.aa_mci;
		delete objJoint.aa;
		delete objJoint.aa_mci;
	}
	else {
		if (isArrayOfLength(objUnit.authors, 1) && !isNonemptyObject(objUnit.authors[0].authentifiers) && !objUnit.content_hash && !conf.bLight)
			return callbacks.ifTransientError("possible AA");
	}
	
	if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
		return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");
```

**File:** object_hash.js (L33-54)
```javascript
function getNakedUnit(objUnit){
	var objNakedUnit = _.cloneDeep(objUnit);
	delete objNakedUnit.unit;
	delete objNakedUnit.headers_commission;
	delete objNakedUnit.payload_commission;
	delete objNakedUnit.oversize_fee;
//	delete objNakedUnit.tps_fee; // cannot be calculated from unit's content and environment, users might pay more than required
	delete objNakedUnit.actual_tps_fee;
	delete objNakedUnit.main_chain_index;
	if (objUnit.version === constants.versionWithoutTimestamp)
		delete objNakedUnit.timestamp;
	//delete objNakedUnit.last_ball_unit;
	if (objNakedUnit.messages){
		for (var i=0; i<objNakedUnit.messages.length; i++){
			delete objNakedUnit.messages[i].payload;
			delete objNakedUnit.messages[i].payload_uri;
		}
	}
	//console.log("naked Unit: ", objNakedUnit);
	//console.log("original Unit: ", objUnit);
	return objNakedUnit;
}
```

**File:** object_hash.js (L60-87)
```javascript
function getUnitHash(objUnit) {
	var bVersion2 = (objUnit.version !== constants.versionWithoutTimestamp);
	if (objUnit.content_hash) // already stripped and objUnit doesn't have messages
		return getBase64Hash(getNakedUnit(objUnit), bVersion2);
	return getBase64Hash(getStrippedUnit(objUnit), bVersion2);
}

function getStrippedUnit(objUnit) {
	var bVersion2 = (objUnit.version !== constants.versionWithoutTimestamp);
	var objStrippedUnit = {
		content_hash: getUnitContentHash(objUnit),
		version: objUnit.version,
		alt: objUnit.alt,
		authors: objUnit.authors.map(function(author){ return {address: author.address}; }) // already sorted
	};
	if (objUnit.witness_list_unit)
		objStrippedUnit.witness_list_unit = objUnit.witness_list_unit;
	else if (objUnit.witnesses)
		objStrippedUnit.witnesses = objUnit.witnesses;
	if (objUnit.parent_units){
		objStrippedUnit.parent_units = objUnit.parent_units;
		objStrippedUnit.last_ball = objUnit.last_ball;
		objStrippedUnit.last_ball_unit = objUnit.last_ball_unit;
	}
	if (bVersion2)
		objStrippedUnit.timestamp = objUnit.timestamp;
	return objStrippedUnit;
}
```

**File:** string_utils.js (L11-60)
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
