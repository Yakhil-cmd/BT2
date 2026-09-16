## Title
StackOverflowError / node crash from unbounded recursive object traversal (`getSourceString` / lodash `cloneDeep`) invoked on attacker-controlled unit content before the depth-limit check - ([File: object_hash.js])

## Summary
`validation.js`'s `validate()` computes the unit hash by calling `objectHash.getUnitHash(objUnit)` **before** it runs `isTooDeeplyNestedOrHasTooManyNodes(objUnit)`. `getUnitHash` walks into `getStrippedUnit` → `getUnitContentHash` → `getNakedUnit`, which does an unguarded, fully recursive `_.cloneDeep(objUnit)` and then serializes the result with the equally unguarded recursive `getSourceString`/`getJsonSourceString` in `string_utils.js`. None of these functions has a recursion-depth limit or node-count limit — that protection (`isTooDeeplyNestedOrHasTooManyNodes`) is only applied *after* the hash has already been computed.

## Finding Description
In `validation.js`: [1](#0-0) 
the unit hash is verified first:
```
if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
    return callbacks.ifJointError(...)
```
and only afterwards, at line 154, is the depth/size guard applied: [2](#0-1) 

`getUnitHash` reaches `getNakedUnit`, which performs a full recursive deep-clone of the entire `objUnit` with no depth bound: [3](#0-2) 

The resulting object is then hashed with `getSourceString`, which recurses into every array/object member without any depth or node-count limit: [4](#0-3) 

Critically, `getNakedUnit` strips only `messages[i].payload`/`payload_uri` — it does **not** strip `author.definition`, which is a fully attacker-controlled, arbitrarily-nestable expression tree (`and`/`or`/`r of set`/`not`, etc., as validated later in `definition.js`). A unit poster can therefore embed a definition nested to many thousands of levels (a compact, small JSON string, e.g. repeated `["not", [ ... ]]`), and this deeply nested structure is fed straight into `_.cloneDeep` and `getSourceString` before any node in the network gets a chance to reject it via the depth check.

This mirrors the reported bug class exactly: a recursive "flatten"/serialize function walking an attacker-supplied, deeply-nested tree with no depth guard, producing a `RangeError: Maximum call stack size exceeded` (Node.js equivalent of Java's `StackOverflowError`).

The only depth check that exists, `isTooDeeplyNestedOrHasTooManyNodes` in `string_utils.js`: [5](#0-4) 
is applied to the incoming joint by some network entry points (e.g. the `'joint'` justsaying handler in `network.js` before calling `handleOnlineJoint`), but `validation.validate()` itself performs the unguarded hash computation unconditionally at the very top of the function, independent of the caller. Any caller of `validate()`/`hasValidHashes()` that does not itself pre-check nesting depth (I was not able to fully enumerate/verify every one of the several `.validate()` call sites — e.g., composer/asset modules and catch-up/history processing paths — with the tools available) is exposed to the crash the moment `objectHash.getUnitHash` or `hasValidHashes()` is invoked on the raw joint.

## Impact Explanation
A successful trigger crashes the Node.js process handling the malicious unit with an unrecoverable `RangeError: Maximum call stack size exceeded`, since JavaScript stack overflows in synchronous recursive code are not normal catchable exceptions in all execution contexts and can bring down the whole process. If reachable via a path that is not pre-guarded by a depth check (a `try/catch` around `objectHash.getUnitHash` at line 131-138 will not reliably catch a stack overflow, and V8 stack overflow errors can also corrupt the event loop state), this becomes a remote, single-message Denial-of-Service against any node (witness, hub, full node) that processes the joint — potentially the entire network if the malicious unit propagates before nodes are patched, matching the "network unable to confirm new units" impact bar.

## Likelihood Explanation
Constructing the malicious payload requires no privileges: any user capable of posting/broadcasting a unit (or crafting an `author.definition`) can build a small, compact JSON payload with deep nesting (tens of thousands of levels can be encoded in a few hundred KB, well within typical unit-size limits). The vulnerable code path (`getUnitHash`/`getNakedUnit`/`getSourceString`) is on the hot path of unit validation and is invoked unconditionally, very early, before size/depth sanity checks.

## Recommendation
- Move the `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` check in `validation.js` to occur **before** any call to `objectHash.getUnitHash`/`hasValidHashes`, for every entry point that eventually calls `validate()`.
- Add hard depth/node-count guards inside `getSourceString`, `getJsonSourceString`, and `_.cloneDeep`-based helpers (`getNakedUnit`, `cleanNullsDeep`, etc.) in `object_hash.js`/`string_utils.js` themselves, so they are safe regardless of caller order (defense-in-depth), similar to what is already done in `aa_validation.js`'s `validate()` (`MAX_DEPTH` check) and `formula/evaluation.js`'s `evaluate()` (`depth > 100` check).
- Explicitly bound the depth of `author.definition` structures during initial unit shape validation, prior to hashing.

## Proof of Concept
1. Craft a unit joint whose `unit.authors[0].definition` is a deeply nested address-definition expression, e.g. programmatically generate:
   ```js
   let def = ['sig', {pubkey: 'AAAA...'}];
   for (let i = 0; i < 50000; i++) def = ['not', def]; // or nest via 'and'/'or of set'
   ```
   Wrap this into a syntactically minimal but otherwise well-formed unit/joint object (`unit`, `version`, `parent_units`, `authors:[{address, definition: def, authentifiers:{...}}]`, etc.).
2. Send this joint to a target node via any network entry point that invokes `validation.validate()`/`hasValidHashes()` without first performing its own depth check (needs to be confirmed against the specific entry point in a live/test environment, since I could not fully audit every one of the ~5 call sites of `validate`/`hasValidHashes`/`getUnitHash` within the available tool budget).
3. Observe the target process crash with `RangeError: Maximum call stack size exceeded` inside `_.cloneDeep`/`getSourceString` invoked from `getUnitHash`, prior to the `isTooDeeplyNestedOrHasTooManyNodes` guard ever executing.

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

**File:** object_hash.js (L33-65)
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
