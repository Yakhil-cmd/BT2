### Title
Unbounded recursion in device-message hashing/cleanup enables stack-overflow DoS via a paired device message - (File: object_hash.js, string_utils.js)

### Summary
CVE-2018-20574 is a stack-exhaustion DoS in yaml-cpp caused by unbounded recursion (`HandleFlowMap`) while parsing an attacker-supplied, deeply-nested document. The closest reachable analog in ocore is the recursive, depth-unlimited processing of attacker-controlled JSON-like objects that are explicitly documented as "free format" and thus not validated for shape before being walked recursively: `cleanNullsDeep()` and `getSourceString()`, both invoked from `getDeviceMessageHashToSign()` in `object_hash.js`, which is used to verify/sign messages exchanged between paired devices.

### Finding Description
`getDeviceMessageHashToSign` is used to compute the hash of a device message before signature verification: [1](#0-0) 

The comment itself acknowledges the danger: "device messages have free format and we can't guarantee absence of malicious fields" — yet the mitigation (`cleanNullsDeep`) is itself an unbounded, depth-first recursive walker with no depth limit or interruption of the call stack: [2](#0-1) 

After cleaning, the object is passed to `getSourceString` (via `require('./string_utils').getSourceString`), which — like its sibling `getJsonSourceString` shown in the same file — recursively stringifies nested arrays/objects with no depth cap: [3](#0-2) 

By contrast, other recursive validators in the codebase that process untrusted, unit-embedded structures (AA definitions, address definitions, formula ASTs) explicitly guard against this exact bug class with `MAX_DEPTH` checks and periodic `setImmediate` calls to break up the JS call stack: [4](#0-3) [5](#0-4) 

`string_utils.js` even ships a dedicated depth/size guard, `isTooDeeplyNestedOrHasTooManyNodes`, used by the formula evaluator to reject deeply nested wrapped objects: [6](#0-5) 

However, this guard is not applied on the device-message path before `cleanNullsDeep`/`getSourceString` run — a paired device (or anyone able to reach `device.js`'s message-handling flow with a "free format" payload) can submit an object with thousands of nesting levels (e.g. `{a:{a:{a:...}}}`) and drive both recursive functions to a JS call-stack exhaustion (`RangeError: Maximum call stack size exceeded`), crashing or hanging the process — directly analogous to the `HandleFlowMap` stack-consumption crash in the CVE.

### Impact Explanation
A crash of the node process handling device messages is a denial of service: it can stop a wallet/hub-adjacent node from processing further paired-device correspondence (chat messages, private-payment chain notifications, multi-sig signing requests, etc.), which in the private-payment/AA trigger flows described in scope can prevent a node from confirming or forwarding time-sensitive messages. This matches the "network unable to confirm new units"/DoS category permitted by the validation rules — it is not merely a resource-only bug, since it can fully terminate/crash the process abruptly via stack overflow, not just consume CPU/memory gracefully.

### Likelihood Explanation
Likelihood is moderate-to-high for any component that accepts device messages (paired devices, e.g. multi-sig cosigners, chat, private-payment notifications): the field is documented in-code as "free format", implying no schema/depth validation is expected to occur upstream, and the recursive cleanup/hashing functions have no depth or node-count limits, unlike comparable unit/AA/formula validators in the same codebase that were clearly hardened against this exact issue.

### Recommendation
Add a depth/node-count guard (reusing `isTooDeeplyNestedOrHasTooManyNodes` semantics or a similar limit, e.g. `MAX_DEPTH`) to `cleanNullsDeep` and to `getSourceString`/`getJsonSourceString` when they are invoked on untrusted, free-format inputs such as device messages, rejecting objects before recursion begins or converting the recursion to an iterative depth-tracked walk with an explicit maximum depth (mirroring the pattern already used in `aa_validation.js` and `formula/validation.js`).

### Proof of Concept
1. As a paired device, construct a device message whose payload contains deeply nested objects, e.g. programmatically build `{a:{a:{a: ... 50000 levels ... }}}`.
2. Send it through the device-message channel so that `getDeviceMessageHashToSign` is invoked on it (`object_hash.js:149-154`).
3. `cleanNullsDeep` recurses once per nesting level with no depth limit (`object_hash.js:130-137`), and/or the subsequent `getSourceString` call recurses similarly (pattern shown for `getJsonSourceString`, `string_utils.js:220-257`), exhausting the JS call stack and crashing/hanging the receiving process before signature verification ever occurs.

### Citations

**File:** object_hash.js (L130-137)
```javascript
function cleanNullsDeep(obj){
	Object.keys(obj).forEach(function(key){
		if (obj[key] === null)
			delete obj[key];
		else if (typeof obj[key] === 'object') // array included
			cleanNullsDeep(obj[key]);
	});
}
```

**File:** object_hash.js (L149-154)
```javascript
function getDeviceMessageHashToSign(objDeviceMessage) {
	var objNakedDeviceMessage = _.clone(objDeviceMessage);
	delete objNakedDeviceMessage.signature;
	cleanNullsDeep(objNakedDeviceMessage); // device messages have free format and we can't guarantee absence of malicious fields
	return crypto.createHash("sha256").update(getSourceString(objNakedDeviceMessage), "utf8").digest();
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

**File:** aa_validation.js (L598-603)
```javascript
	function validate(obj, name, path, locals, depth, cb, bValueOnly) {
		if (depth > MAX_DEPTH)
			return cb("max depth reached");
		count++;
		if (count % 100 === 0) // interrupt the call stack
			return setImmediate(validate, obj, name, path, locals, depth, cb, bValueOnly);
```

**File:** formula/validation.js (L272-288)
```javascript
	function evaluate(arr, cb, bTopLevel) {
		count++;
		if (count % 100 === 0) // avoid extra long call stacks to prevent Maximum call stack size exceeded
			return (typeof setImmediate === 'function') ? setImmediate(evaluate, arr, cb) : setTimeout(evaluate, 0, arr, cb);
		depth++;
		const orig_cb = cb;
		cb = err => {
			depth--;
			if (err && !errorLocation && arr && typeof arr === 'object' && arr.line !== undefined) {
				errorLocation = arr.source_location
					? Object.assign({}, arr.source_location)
					: { line: arr.line };
			}
			orig_cb(err);
		};
		if (depth > 100 && (mci >= constants.pemCurvesFixMci || require('../storage.js').getMinRetrievableMci() >= constants.pemCurvesFixMci))
			return cb("maximum depth exceeded");
```
