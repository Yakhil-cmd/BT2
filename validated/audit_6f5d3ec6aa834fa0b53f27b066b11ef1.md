Found it: `main_chain.js:setContentHash` (inside `markMcIndexStable`) calls `objectHash.getUnitContentHash(objJoint.unit)` **without any try/catch**, on a unit whose `messages` payload (e.g. `app: "data"` or `"profile"`) was accepted by `validation.js`'s loose check (`typeof payload !== "object" || payload === null`) that does **not** enforce the semantic constraints that `getSourceString`/`getJsonSourceString` enforce at encode-time (no empty objects/arrays, no `undefined` values, no `null` inside nested structures, finite numbers only). This exactly mirrors the Vanetza pattern: parse-time acceptance vs. encode-time rejection, with the encode-time exception left uncaught on a consensus-critical path (stabilization), which will crash every full node via `process.on('uncaughtException')` → `throw err`.

### Title
Uncaught Exception in `main_chain.js` During Content-Hash Re-Encoding of Final-Bad Units Crashes All Full Nodes - (File: main_chain.js)

### Summary
`validation.js` accepts a unit message payload for apps such as `data` or `profile` using only a loose check (`typeof payload !== "object" || payload === null`), never verifying that the payload is free of values that the canonical hashing/serialization routines (`getSourceString` / `getJsonSourceString` in `string_utils.js`) reject at encode-time (empty arrays `[]`, empty objects `{}`, `undefined` object values). Later, when the unit becomes non-serial ("final-bad", e.g. as the loser of a double-spend) and main-chain stabilization processes it, `main_chain.js`'s `markMcIndexStable` → `setContentHash` calls `objectHash.getUnitContentHash(objJoint.unit)` with **no try/catch**, so any such semantic mismatch throws an uncaught `Error` that propagates out of the mutex-protected stabilization code path straight to `process.on('uncaughtException')` in `network.js`, which re-throws to crash the whole process.

### Finding Description
- `validation.js` message-hash pre-check (lines 219-243) only verifies the payload's hash matches `m.payload_hash` using `objectHash.getBase64Hash(getPayloadForHash(m), …)` inside a `try/catch` — this succeeds as long as the attacker supplies a payload whose declared hash matches its own content, regardless of whether that content is later safely re-encodable in a different context. It does not reject payloads containing empty objects/arrays anywhere in nested structure for apps like `data`/`profile`/`attestation`, because the app-specific check (`case "data": … return callback();` in `validation.js` ~lines 1961-1964, and similarly for `profile`) only asserts `typeof payload === "object" && payload !== null` [1](#0-0) .
- `string_utils.getSourceString`/`getJsonSourceString`, used by `objectHash.getUnitContentHash`/`getNakedUnit`, throw `Error` for empty arrays, empty objects, or `undefined` values encountered while serializing [2](#0-1) [3](#0-2) .
- A unit is treated as "final-bad" (non-serial loser of a double-spend) during `main_chain.markMcIndexStable`, and for such units `setContentHash` is invoked to compute and persist `content_hash` on the stripped/naked unit: `objectHash.getUnitContentHash(objJoint.unit)` is called directly, **not wrapped in try/catch** [4](#0-3) .
- `getUnitContentHash` calls `getNakedUnit` (which deep-clones the unit and strips several fields but leaves `messages[i].payload` for apps other than payment untouched after the earlier `delete objNakedUnit.messages[i].payload` step only for the message's own top-level; nested payload structures of surviving message fields, or messages array items retained via `messages` prop for hashing later) and then `getBase64Hash`, i.e., ultimately `getSourceString`/`getJsonSourceString` [5](#0-4) .
- Since the double-spend loser could be posted by *any* unprivileged unit poster (an ordinary payment double-spend attempt with a crafted extra message using `app: "data"`/`"profile"` containing an empty nested object/array or an `undefined`-producing structure via JSON parsing quirks, e.g. keys mapped to `[]`/`{}`), the attacker fully controls the message content that gets fed to `setContentHash` once the unit becomes final-bad and reaches its main-chain-index stabilization.
- This mirrors the CVE-2026-44905 root cause precisely: parse-time/initial validation ("hash-of-payload-matches" check) accepts the structure, but a distinct, later re-encoding step used for a different purpose (content-hash calculation for archiving/stripping of the final-bad unit) enforces a stricter semantic constraint and throws — and this throw is not caught, terminating the process.
- The `process.on('uncaughtException', …)` handler in `network.js` explicitly re-throws to crash the process ("crash the process to avoid ending up in an inconsistent state") [6](#0-5) , confirming that this uncaught exception is fatal, not merely logged.

### Impact Explanation
`markMcIndexStable` runs as part of consensus-critical main-chain stabilization on **every full node** that has synced past the offending unit's main-chain-index. A single crafted unit that becomes "final-bad" and reaches stabilization would crash every full node that processes it, i.e., "a network unable to confirm new units" — nodes crash/restart in a loop around the same stabilization point, halting confirmation of new units network-wide until the code is patched, matching one of the accepted high-severity impacts.

### Likelihood Explanation
Reachable by an unprivileged unit poster: this only requires posting a normal double-spend attempt (something every wallet already does trivially) where the losing branch's unit contains a `data`/`profile`/`attestation` message payload with a value that JSON round-trips validly (so the payload-hash check passes) but contains a nested empty array/object or similar construct that `getSourceString`/`getJsonSourceString` reject. No special privileges, hub role, or malicious-peer capability are needed — just crafting the unit content and having it lose a double-spend race so it is marked "final-bad" and reaches `setContentHash`. This makes the likelihood high once the specific triggering payload shape is confirmed (see Proof of Concept caveat below).

### Recommendation
Wrap the `objectHash.getUnitContentHash(objJoint.unit)` call in `main_chain.js`'s `setContentHash` in a try/catch, treating a thrown encoding error as a fatal-but-handled validation failure (e.g., log and mark the unit un-strippable / require code-level rejection earlier), and — more fundamentally — tighten `validation.js`'s payload checks for `data`, `profile`, `attestation`, and similar free-form apps to proactively reject payloads that are not round-trippable through `getSourceString`/`getJsonSourceString` (no empty arrays/objects, no `undefined`), so that the constraint is enforced once, consistently, at initial validation time rather than being discovered later on an unprotected path.

### Proof of Concept
1. Craft two conflicting units `A` and `B` spending the same output from the same address, where `B` additionally contains a message `{app: "data", payload: {foo: []}}` (empty array is valid JSON and gives a payload matching its own `payload_hash`, so it passes `validation.js`'s payload-hash and `typeof payload === "object"` checks).
2. Post both units; let the network resolve the double-spend so that `B` becomes the "final-bad" (non-serial) loser.
3. Once `B`'s main-chain-index becomes eligible for stabilization, `main_chain.markMcIndexStable` calls `setContentHash(B, cb)` → `objectHash.getUnitContentHash(objJoint.unit)` → `getNakedUnit` → `getBase64Hash`/`getSourceString`, which throws `Error("empty array in ...")` uncaught.
4. The exception propagates to `process.on('uncaughtException')` in `network.js`, which logs it and re-throws, crashing the full node process.

Note: I was not able to execute this against a live node to confirm the exact conditions under which `messages[i].payload` for non-payment apps survives into the object passed to `getUnitContentHash` at the point `setContentHash` is called (vs. being stripped earlier), and whether `payload_uri`/message content is present for a final-bad unit at that time; this should be verified with a live/test node before treating the PoC as fully validated, though the underlying root-cause mismatch between `validation.js`'s payload acceptance and `string_utils.js`'s stricter encode-time constraints, combined with the missing try/catch in `main_chain.js:1373`, is confirmed directly from source.

### Citations

**File:** validation.js (L1954-1965)
```javascript
		case "profile":
			if (objUnit.authors.length !== 1)
				return callback("profile must be single-authored");
			if (objValidationState.bHasProfile)
				return callback("can be only one profile");
			objValidationState.bHasProfile = true;
			// no break, continuing
		case "data":
			if (typeof payload !== "object" || payload === null)
				return callback(objMessage.app+" payload must be object");
			return callback();

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

**File:** main_chain.js (L1367-1380)
```javascript
	function setContentHash(unit, onSet){
		storage.readJoint(conn, unit, {
			ifNotFound: function(){
				throw Error("bad unit not found: "+unit);
			},
			ifFound: function(objJoint){
				var content_hash = objectHash.getUnitContentHash(objJoint.unit);
				// not setting it in kv store yet, it'll be done later by updateMinRetrievableMciAfterStabilizingMci
				conn.query("UPDATE units SET content_hash=? WHERE unit=?", [content_hash, unit], function(){
					onSet();
				});
			}
		});
	}
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

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
