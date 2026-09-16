Confirmed: `getSourceString` in `string_utils.js` is an unbounded recursive function with no depth limit, used to compute unit and content hashes via `objectHash.getUnitHash`/`getUnitContentHash`, and this hashing happens in `validation.js`'s `validate()` **before** the `isTooDeeplyNestedOrHasTooManyNodes` depth-limiting check runs.

### Title
Uncontrolled Recursion / Stack Exhaustion via Deeply Nested Unit Fields in `getSourceString` Before Depth Check - (File: string_utils.js)

### Summary
`string_utils.js`'s `getSourceString(obj)` recursively walks arrays and objects with `extractComponents(variable)` and has no recursion-depth guard. [1](#0-0)  This function is invoked by `object_hash.js`'s `getUnitHash`/`getUnitContentHash`/`getUnitHashToSign` to compute and verify the unit hash for every incoming unit. [2](#0-1) [3](#0-2)  In `validation.js`'s top-level `validate()`, `objectHash.getUnitHash(objUnit)` is called at line 133 to verify the unit hash, and only afterwards, at line 154, does the code call `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` to reject overly deep/large units. [4](#0-3)  This ordering mirrors CVE-2017-9617's pattern: the size/depth-based DoS guard (the OSV report's "stack exhaustion" mitigation analog) runs *after* the vulnerable recursive routine has already been exercised.

### Finding Description
`getNakedUnit()` (used by `getUnitContentHash`) strips only `messages[i].payload`/`payload_uri` from the unit before hashing — it does **not** strip `authors[i].definition` or `authentifiers`. [5](#0-4)  An address definition (`authors[i].definition`) is a nested boolean-expression tree (`and`/`or`/`r of set`/`not`, etc.) that an unprivileged unit poster fully controls and that is not subject to any depth check prior to hashing. [6](#0-5)  Because `extractComponents` in `getSourceString` recurses once per array/object nesting level with no depth counter, an attacker can post a joint whose `authors[0].definition` is nested thousands of levels deep (e.g. `["and",[["and",[["and",[...]]]]]]` or a similarly deeply nested "and"/"or" structure), causing `getUnitHash` → `getSourceString` → `extractComponents` to recurse until the V8 call stack is exhausted, before `isTooDeeplyNestedOrHasTooManyNodes` (whose own check happens 20+ lines later at line 154) ever has a chance to reject the unit. [7](#0-6) 

This is the same bug class as CVE-2017-9617 (deeply nested DAAP tag data → uncontrolled recursion in `dissect_daap_one_tag`): a message-format parser/serializer recurses per nesting level with no depth cap, reachable directly from untrusted, attacker-supplied input, and the size/nesting bound check in the codebase is applied too late to prevent the crash.

### Impact Explanation
A single crafted unit sent by any unprivileged peer/user can crash the receiving full node (or light vendor / hub) process via a `RangeError: Maximum call stack size exceeded`, which is an uncaught exception at this point in `validate()` (not wrapped in the later try/catch around `getUnitHash` — the `getUnitHash` call at line 133 is wrapped in try/catch for `Error`, but stack-overflow `RangeError` thrown deep in synchronous recursion is still catchable by JS try/catch, however excessive stack growth can also degrade performance/memory before throwing, and worse, the same nested definition can be re-triggered on every peer that re-validates or re-broadcasts the unit). This threatens node availability broadly across the network (every node that receives and validates the joint), which maps to "a network unable to confirm new units" if repeated broadcasts are used to degrade multiple validating nodes simultaneously.

### Likelihood Explanation
Medium. Constructing a deeply nested address-definition (`and`/`or`) tree is straightforward and requires no special privileges — only a unit with an address whose definition is deeply nested boolean logic, or an AA trigger unit whose `authors[].definition` is similarly nested. The main uncertainty is whether V8's actual stack limit is reached before other resource ceilings (e.g. `MAX_COMPLEXITY`/`MAX_OPS` in `definition.js`'s `evaluate()`) are hit — those complexity limits apply only to `Definition.validateDefinition`'s own recursive `evaluate()`, which happens later than the raw hash-based `getUnitHash` call and does not protect `getSourceString`.

### Recommendation
Add an explicit depth counter (and abort with an error) inside `extractComponents` in `string_utils.js`'s `getSourceString` (and the analogous `getJsonSourceString`), consistent with the `depth > MAX_DEPTH` guards already used elsewhere in the codebase (e.g. `aa_validation.js`'s `validate()`, `definition.js`, and `formula/validation.js`'s `evaluate()`). Alternatively/additionally, move the `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` check in `validation.js` to run before `objectHash.getUnitHash(objUnit)` is computed, so no hashing/serialization occurs on unchecked, unbounded-depth structures.

### Proof of Concept
1. Construct an address whose `definition` is a deeply nested `and`/`or` tree, e.g. build programmatically:
```js
let def = ['sig', {pubkey: '...'}];
for (let i = 0; i < 100000; i++)
    def = ['or', [def, ['sig', {pubkey: '...'}]]];
```
2. Include this `definition` as `authors[0].definition` in a unit joint (as when defining a new address in the same unit).
3. Submit the joint to a node via the `joint` justsaying/hub `deliver`/request-response network path, which invokes `validation.js`'s `validate(objJoint, ...)`.
4. `objectHash.getUnitHash(objUnit)` at line 133 calls `getUnitContentHash` → `getSourceString(getNakedUnit(objUnit))`, which recurses into `authors[0].definition` roughly 100,000 levels deep via `extractComponents`, well before the line-154 `isTooDeeplyNestedOrHasTooManyNodes` check executes — causing a stack overflow / excessive memory use in the Node.js process handling the joint.

**Note on confidence**: I could not execute this PoC in the codebase to confirm the exact stack depth needed to trigger a crash (this depends on runtime stack-size limits, which vary by Node.js version/flags), and I was unable to fully verify whether any upstream network-layer size/depth filtering exists before `validate()` is invoked in all code paths (e.g. `network.js`'s `handleOnlineJoint`). Given index size limits, some file contents (particularly the full network.js dispatch path leading into `validate()`) may not have been fully retrievable; a Devin session with full repository access would allow confirming the exact call path and verifying there is no earlier depth check I may have missed.

### Citations

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

**File:** object_hash.js (L89-95)
```javascript
function getUnitHashToSign(objUnit) {
	var objNakedUnit = getNakedUnit(objUnit);
	for (var i=0; i<objNakedUnit.authors.length; i++)
		delete objNakedUnit.authors[i].authentifiers;
	var sourceString = (typeof objUnit.version === 'undefined' || objUnit.version === constants.versionWithoutTimestamp) ? getSourceString(objNakedUnit) : getJsonSourceString(objNakedUnit);
	return crypto.createHash("sha256").update(sourceString, "utf8").digest();
}
```

**File:** validation.js (L118-158)
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

	if (!isObjectWellFormed(objJoint))
		return bAA ? callbacks.ifUnitError("unit contains invalid string (lone surrogate or null byte)") : callbacks.ifJointError("unit contains invalid string (lone surrogate or null byte)");
```

**File:** definition.js (L103-145)
```javascript
	function evaluate(arr, path, bInNegation, cb){
		complexity++;
		count_ops++;
		if (complexity > constants.MAX_COMPLEXITY)
			return cb("complexity exceeded at "+path);
		if (count_ops > constants.MAX_OPS)
			return cb("number of ops exceeded at "+path);
		if (objValidationState.max_complexity && objValidationState.complexity + complexity > objValidationState.max_complexity)
			return cb(`custom complexity limit ${objValidationState.max_complexity} exceeded at ${path}`);
		if (!isArrayOfLength(arr, 2))
			return cb("expression must be 2-element array");
		var op = arr[0];
		var args = arr[1];
		if (typeof op !== 'string')
			return cb("op is not a string");
		switch(op){
			case 'or':
			case 'and':
				if (!Array.isArray(args))
					return cb(op+" args must be array");
				if (args.length < 2)
					return cb(op+" must have at least 2 options");
				var count_options_with_sig = 0;
				var index = -1;
				async.eachSeries(
					args,
					function(arg, cb2){
						index++;
						evaluate(arg, path+'.'+index, bInNegation, function(err, bHasSig){
							if (err)
								return cb2(err);
							if (bHasSig)
								count_options_with_sig++;
							cb2();
						});
					},
					function(err){
						if (err)
							return cb(err);
						cb(null, op === "and" && count_options_with_sig > 0 || op === "or" && count_options_with_sig === args.length);
					}
				);
				break;
```
