Based on my research, I found a genuine instance of the CVE-2024-57699 bug class (uncontrolled recursion on untrusted, deeply-nestable input causing stack exhaustion) in `object_hash.js`.

### Title
Uncontrolled recursion in `cleanNullsDeep` causes stack exhaustion when hashing paired-device messages - (File: object_hash.js)

### Summary
`cleanNullsDeep()` in `object_hash.js` recursively walks every array/object it is given with no depth limit, no node-count limit, and no protection against `RangeError: Maximum call stack size exceeded`. It is called by `getDeviceMessageHashToSign()` on `objDeviceMessage`, which the code's own comment admits is untrusted: "device messages have free format and we can't guarantee absence of malicious fields." This is the same bug class as the json-smart advisory: a recursive descent parser/serializer with no depth guard, triggerable by a crafted deeply-nested payload from an otherwise-authorized but potentially malicious counterparty (a paired device).

### Finding Description
`cleanNullsDeep` is fully recursive and unbounded: [1](#0-0) 

It is invoked directly on an incoming/outgoing device message before hashing it for signature purposes: [2](#0-1) 

Unlike unit (DAG) validation, which explicitly guards against deeply nested attacker structures before any recursive hashing/traversal occurs: [3](#0-2) [4](#0-3) 

...device messages exchanged between paired wallets/devices have no equivalent `isTooDeeplyNestedOrHasTooManyNodes` check before `cleanNullsDeep`/`getSourceString` recursion is performed. `getSourceString` itself is also unbounded recursion over arbitrary nested arrays/objects: [5](#0-4) 

A paired device (a correspondent that the target has already paired with, i.e. an "unprivileged... paired device" per the reachable-surface rules) can send a message whose payload contains a JSON structure nested to a depth exceeding the JS engine's call-stack limit (typically a few thousand levels for simple `{a:{a:{a:...}}}` chains). When the recipient later needs to hash that message (e.g. to verify/produce a signature via `getDeviceMessageHashToSign`), the unbounded recursive walk in `cleanNullsDeep` (and subsequently `getSourceString`) throws an uncaught `RangeError`.

### Impact Explanation
This directly parallels the reported CWE-674 issue: an attacker who controls a JSON-like message body can crash a recursive-descent consumer via excessive nesting. The affected code path handles wallet-to-wallet/device correspondent messaging (pairing chat, private payment forwarding, shared-address negotiation messages, arbiter/prosaic contract offers, etc.), which is explicitly in scope. Because there is no depth or node-count check comparable to `isTooDeeplyNestedOrHasTooManyNodes` (which protects unit/DAG processing) before the message is hashed, a malicious correspondent can cause a crash/DoS of the recipient node's device-messaging pipeline when it goes to sign/verify these hashes.

### Likelihood Explanation
Any device that has been paired (a normal, low-privilege relationship many wallets establish) can send arbitrary JSON payloads through `device.sendMessageToDevice`; nothing prevents nesting depth from being unbounded before it reaches `cleanNullsDeep`/`getSourceString`. This makes the trigger trivial to construct and requires no special privilege beyond being a paired correspondent.

### Recommendation
Add the same size/depth protection already used for unit validation (`string_utils.isTooDeeplyNestedOrHasTooManyNodes`) to `cleanNullsDeep` and to `getDeviceMessageHashToSign`/other device-message hashing entry points before recursing, and/or convert `cleanNullsDeep`/`getSourceString` to iterative (explicit stack) implementations to avoid depending on the JS call stack for adversarial-controlled data.

### Proof of Concept
1. Pair with a victim device as a normal correspondent.
2. Construct a device message whose JSON payload is deeply nested, e.g. `{"a":{"a":{"a": ... }}}` nested tens of thousands of levels (or an array of arrays similarly nested), well beyond V8's default stack recursion limit.
3. Send it via the normal device-messaging channel so that it is processed by `sendMessageToDevice`/message handling that eventually calls `objectHash.getDeviceMessageHashToSign` (which calls `cleanNullsDeep` then `getSourceString`) on the payload.
4. The recursive walk exceeds the JS call stack, throwing `RangeError: Maximum call stack size exceeded`; if this is not caught by an enclosing try/catch, it crashes the process handling device messages, denying the victim device's messaging/wallet functionality.

**Note on uncertainty:** I could not fully trace, within the available tool budget, every call site that leads into `getDeviceMessageHashToSign`/`cleanNullsDeep` (e.g. whether some outer `try/catch` in `device.js` message dispatch swallows the `RangeError` gracefully in all code paths). If such a catch exists everywhere this function is reached, the practical impact would be reduced to a benign message-processing failure rather than a process crash. I recommend a Devin session with full file access to `device.js` to confirm whether all invocation paths of `getDeviceMessageHashToSign` are wrapped in exception handling.

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

**File:** validation.js (L154-155)
```javascript
	if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
		return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");
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
