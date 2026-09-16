### Title
Unbounded recursion in `getSourceString`/`cleanNullsDeep` allows stack-overflow DoS via crafted paired-device message or oscript `chash160`/`sha256` object hashing - ([File: string_utils.js], [File: object_hash.js])

### Summary
`string_utils.js`'s `getSourceString()` and `object_hash.js`'s `cleanNullsDeep()` recursively walk arbitrary nested objects/arrays with no depth limit, analogous to the unbounded recursive-descent bug in CVE-2016-9625 (w3m infinite recursion on crafted nested HTML causing DoS). Both functions are reachable with attacker-controlled, deeply-nested data before any complexity/depth guard is applied.

### Finding Description
`getSourceString` recurses once per nesting level of an object/array with no depth check: [1](#0-0) 

`object_hash.getDeviceMessageHashToSign` calls `cleanNullsDeep` (itself unboundedly recursive) and then `getSourceString` on a device message whose format is explicitly untrusted, per the code's own comment ("device messages have free format and we can't guarantee absence of malicious fields"): [2](#0-1) 

Separately, in oscript formula evaluation the `chash160`/`sha256` operators call `objectHash.getChash160`/`getSourceString`/`getJsonSourceString` on an AA-formula-produced object. A size/depth guard (`isTooBigObj`) exists but is only enforced when `bPostPemCurvesFix` is true, i.e. gated behind an mci-based feature flag: [3](#0-2) 

`isTooBigObj`/`isTooDeeplyNestedOrHasTooManyNodes` in `string_utils.js` are themselves depth-limited implementations that were clearly added later to fix this exact class of unbounded-recursion issue, but they are not applied uniformly to every recursive object-walking path (e.g., `getSourceString` itself has no such limit, and `cleanNullsDeep`/`getDeviceMessageHashToSign` for device messages have none at all): [4](#0-3) 

Because JS engines have a bounded call stack, a sufficiently deep object (e.g., thousands of nested arrays/objects) fed into `getSourceString`/`cleanNullsDeep` will throw `RangeError: Maximum call stack size exceeded`, crashing or hanging the process depending on where the exception is caught (or not caught) up the call chain — directly mirroring the w3m infinite-recursion DoS.

### Impact Explanation
A crash/hang triggered on `getSourceString`/`cleanNullsDeep`/`getChash160` denies the node the ability to process the device message queue, the AA trigger, or hash/validate incoming data, i.e. "a network unable to confirm new units" or a node unable to process its own paired-device correspondent traffic (both wallet and hub nodes exchange device messages routinely). Because `getSourceString` is also used for unit/ball/signed-package hashing, an uncaught stack-overflow in the middle of processing could destabilize the calling process rather than just failing gracefully, amplifying the severity beyond mere resource exhaustion.

### Likelihood Explanation
Reachability is straightforward for the device-message path: any paired device correspondent can send a `cleanNullsDeep`/`getDeviceMessageHashToSign`-processed message with deep nesting since the format is explicitly documented as untrusted/free-form. For the oscript path, an AA author can craft a trigger/formula producing a deeply nested object and feed it to `chash160(...)`/`sha256(...)`; whether this is currently exploitable depends on whether the deployed network mci is already past `pemCurvesFixMci` (in which case `isTooBigObj` already blocks it) — I could not fully confirm the current activation status of `pemCurvesFixMci` on the live network from the available context, so likelihood for that specific vector is uncertain. The device-message vector, however, has no comparable guard at all in the code shown.

### Recommendation
- Add an explicit depth (and node-count) limit to `getSourceString` (mirroring `isTooDeeplyNestedOrHasTooManyNodes`/`isTooBigObj`) and reject/short-circuit before recursing past the limit, or convert the recursion to an iterative worklist-based traversal.
- Apply the same depth guard to `cleanNullsDeep` before it is invoked from `getDeviceMessageHashToSign`, since device messages are explicitly untrusted.
- Ensure `isTooBigObj` checks in `formula/evaluation.js` (`chash160`, `sha256`, `json_stringify`, etc.) are unconditionally enforced rather than gated behind the `bPostPemCurvesFix` flag, so older/pre-upgrade nodes are equally protected.

### Proof of Concept
Conceptual PoC (device-message vector): a paired device correspondent constructs and sends a device message whose JSON payload contains ~50,000+ levels of nested arrays/objects (e.g. `{a:{a:{a:...}}}`). When the receiving node calls `object_hash.getDeviceMessageHashToSign` (via `cleanNullsDeep` then `getSourceString`) to verify/process the message, the unbounded recursion exhausts the V8 call stack and throws `RangeError: Maximum call stack size exceeded`, crashing or destabilizing the device-message-handling code path — the direct analog of the w3m infinite-recursion crash from a crafted nested document.

### Citations

**File:** string_utils.js (L11-38)
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
```

**File:** string_utils.js (L260-323)
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

function isTooBigObj(obj, { depthLimit = 100, nodesLimit = 10000, lengthLimit = 1000000 }) {
	let nodeCount = 0;
	let length = 0;

	function check(variable, depth){
		if (depth > depthLimit || nodeCount > nodesLimit || length > lengthLimit)
			return true;
		if (typeof variable === "string")
			length += variable.length;
		else if (typeof variable === "number" || typeof variable === "boolean")
			length += variable.toString().length;
		else if (variable === null)
			length += 4; // "null"
		else if (typeof variable !== "object")
			throw Error("isTooBigObj: unexpected type=" + (typeof variable) + " of " + variable);
		if (length > lengthLimit)
			return true;
		if (typeof variable !== "object" || variable === null)
			return false;
		if (Array.isArray(variable)) {
			nodeCount += variable.length;
			for (let v of variable)
				if (check(v, depth + 1))
					return true;
		}
		else {
			const keys = Object.keys(variable);
			nodeCount += keys.length;
			length += keys.reduce((sum, key) => sum + key.length, 0);
			for (let key in variable)
				if (check(variable[key], depth + 1))
					return true;
		}
		return false;
	}

	return check(obj, 1);
}
```

**File:** object_hash.js (L130-153)
```javascript
function cleanNullsDeep(obj){
	Object.keys(obj).forEach(function(key){
		if (obj[key] === null)
			delete obj[key];
		else if (typeof obj[key] === 'object') // array included
			cleanNullsDeep(obj[key]);
	});
}

// -----------------

// prefix device addresses with 0 to avoid confusion with payment addresses
// Note that 0 is not a member of base32 alphabet, which makes device addresses easily distinguishable from payment addresses 
// but still selectable by double-click.  Stripping the leading 0 will not produce a payment address that the device owner knows a private key for,
// because payment address is derived by c-hashing the definition object, while device address is produced from raw public key.
function getDeviceAddress(b64_pubkey){
	return ('0' + getChash160FromString(b64_pubkey));
}

function getDeviceMessageHashToSign(objDeviceMessage) {
	var objNakedDeviceMessage = _.clone(objDeviceMessage);
	delete objNakedDeviceMessage.signature;
	cleanNullsDeep(objNakedDeviceMessage); // device messages have free format and we can't guarantee absence of malicious fields
	return crypto.createHash("sha256").update(getSourceString(objNakedDeviceMessage), "utf8").digest();
```

**File:** formula/evaluation.js (L1848-1869)
```javascript
			case 'chash160':
				var expr = arr[1];
				evaluate(expr, function (res) {
					if (fatal_error)
						return cb(false);
					if (res instanceof wrappedObject) {
						if (bPostPemCurvesFix && isTooBigObj(res.obj))
							return setFatalError("to-be-hashed object is too big", { arr }, false, cb);
						try {
							var chash160 = objectHash.getChash160(res.obj);
						}
						catch (e) {
							return setFatalError("chash160 failed: " + e, { arr }, false, cb);
						}
						return cb(chash160);
					}
					if (!isValidValue(res))
						return setFatalError("invalid value in chash160: " + res, { arr }, false, cb);
					if (Decimal.isDecimal(res))
						res = toDoubleRange(res);
					cb(chash.getChash160(res.toString()));
				});
```
