## Analysis: Stack overflow reachable in unit hash computation, before depth-limiting checks

The reported `alloy-json-abi` bug class (uncontrolled recursion while parsing/processing untrusted structured input → stack overflow → crash) has a direct analog in ocore's unit-hashing code path, which runs *before* ocore's own depth-limiting defenses are applied.

### Root cause

`validation.js`'s `validate()` function computes the unit hash immediately upon receiving a joint, before any structural sanity checks are performed: [1](#0-0) 

The depth/size guard `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` (limit: depth 100 / 10000 nodes) is only invoked afterward: [2](#0-1) 

`objectHash.getUnitHash()` calls `getStrippedUnit()` → `getUnitContentHash()` → `getNakedUnit()`, which only strips `messages[i].payload`/`payload_uri`, leaving `authors[].definition` (and other fields) intact: [3](#0-2) 

The hash is then computed via `getSourceString`/`getJsonSourceString`, both of which recurse into every array/object level with **no depth limit at all**: [4](#0-3) [5](#0-4) 

Since `authors[].definition` is an address-definition expression tree (`['and'/'or'/'not', [...]]`), which is exactly the kind of structure an unprivileged unit poster fully controls, a unit can be crafted with an `author.definition` nested to an arbitrary depth (e.g., thousands of `['not', [...]]` wrappers or nested arrays). `JSON.parse` of the incoming network message is native/iterative and won't itself overflow, so the malicious payload parses fine — but the very first processing step, `getUnitHash()` at `validation.js:133`, recurses once per nesting level in `getSourceString`/`getJsonSourceString` and can exhaust the V8 call stack, crashing the node **before** `isTooDeeplyNestedOrHasTooManyNodes` (which exists precisely to prevent this) ever gets a chance to reject the unit.

Elsewhere in the codebase, this exact bug class is already recognized and guarded against with explicit depth counters/`setImmediate` stack-unwinding (`MAX_DEPTH` in `aa_validation.js`, `depth > 100` in `formula/validation.js`, complexity/op counters in `definition.js`'s `evaluate()`), which confirms the project's own awareness of this risk — but the ordering bug in `validation.js` means the very first touch of attacker data (`getUnitHash`) bypasses all of them.

### Title
Stack overflow via deeply nested `author.definition` in unit hash computation, reachable before depth-limit checks - (File: `validation.js`)

### Summary
`validation.js`'s `validate()` calls `objectHash.getUnitHash(objUnit)` to verify the unit hash before calling `isTooDeeplyNestedOrHasTooManyNodes(objUnit)`, the guard meant to reject deeply nested/oversized units. `getUnitHash` recurses through the entire unit (including `authors[].definition`, which is not stripped by `getNakedUnit`) via `string_utils.getSourceString`/`getJsonSourceString`, both unboundedly recursive. A single posted unit with a deeply nested address-definition expression can crash any node (full or light) that attempts to validate it, before the depth guard is reached.

### Finding Description
`validate()` in [6](#0-5)  performs hash verification first and structural depth/size validation second. `getUnitHash`/`getStrippedUnit`/`getUnitContentHash`/`getNakedUnit` in [3](#0-2)  retain `authors[].definition` unmodified, and pass the whole naked unit into `getSourceString` or `getJsonSourceString`, both of which walk nested arrays/objects with plain unbounded recursion ( [4](#0-3) , [5](#0-4) ). An attacker fully controls `author.definition` content of a unit they post; nesting it (e.g. thousands of `['not', [...]]`) produces a JS object that parses fine but overflows the call stack the moment `getUnitHash` walks it — well before `isTooDeeplyNestedOrHasTooManyNodes` (depth limit 100) at [7](#0-6)  is ever invoked.

### Impact Explanation
A crafted unit triggers an uncaught `RangeError: Maximum call stack size exceeded` deep inside synchronous recursive string-building code, which is not the kind of error the `try/catch` around `getUnitHash` at [1](#0-0)  is generally relied on to fully absorb without side effects in all call contexts (and even where caught, it is invoked repeatedly on every relevant path: light client validation, full validation, catchup joints, etc.). Since every node (full and light) must call `validate()`/`getUnitHash()` on every unit it receives — including via ordinary unit posting — a single malicious unit can reliably crash any node that processes it, preventing the network from making progress on validating/confirming new units that reference or bundle the malicious unit.

### Likelihood Explanation
High reachability: any unprivileged party can post a unit; the only requirement is a normal-looking joint whose `author.definition` (or nested inner-address definitions) is nested far beyond the depth that the later `isTooDeeplyNestedOrHasTooManyNodes` check would reject. No signature bypass or protocol violation is needed to reach the vulnerable code — the hash check happens unconditionally as step one of `validate()`.

### Recommendation
Reorder `validate()` so that `isTooDeeplyNestedOrHasTooManyNodes(objUnit)` (and other structural sanity checks) run strictly before `objectHash.getUnitHash(objUnit)` is ever invoked. Additionally, add an explicit depth guard inside `getSourceString`/`getJsonSourceString` in `string_utils.js` (mirroring the `MAX_DEPTH`/`setImmediate` pattern already used in `aa_validation.js` and `formula/validation.js`) so that hashing code is itself defensive regardless of call order elsewhere.

### Proof of Concept
1. Construct a unit joint whose `unit.authors[0].definition` is `['sig', {...}]` wrapped in tens of thousands of `['not', [ ... ]]` layers (or a deeply nested array/object elsewhere in `authors`/`parent_units`/etc. that survives `getNakedUnit` stripping).
2. Submit this joint to a node as a normal new unit (e.g., via `network.js` joint-handling path that calls into `validation.js`'s `validate()`).
3. `validate()` immediately calls `objectHash.getUnitHash(objUnit)` (`validation.js:133`) before any depth/size check runs.
4. `getUnitHash` → `getStrippedUnit` → `getUnitContentHash` → `getBase64Hash` → `getSourceString`/`getJsonSourceString` recurse once per nesting level of `definition`, exceeding the V8 stack limit and throwing `RangeError: Maximum call stack size exceeded`, crashing or destabilizing the receiving node's process before `isTooDeeplyNestedOrHasTooManyNodes` at `validation.js:154` is ever reached.

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
