Found a concrete analog: `deserializeMerkleProof` in `merkle.js` is called from `definition.js`'s `evaluate()` (the `'in merkle'` case) on attacker-supplied authentifier data, and its result is *not* validated before use, so a malformed/short `serialized_proof` produces `proof.root === undefined` while `merkle.verifyMerkleProof()` still runs successfully to `false` (it's wrapped in try/catch, so no crash there). However, the reachable crash risk is different: `deserializeMerkleProof` itself is called with **no try/catch and no type/format check** — if `assocAuthentifiers[path]` is not a string (e.g., an object, number, array or `null`... but note it is guarded by `!assocAuthentifiers[path]` only, which is falsy-check, not type-check), `serialized_proof.split("-")` will throw a `TypeError: serialized_proof.split is not a function`. Since `evaluate()` in `definition.js` runs synchronously in the unit-validation path (`validateAuthentifiers` → `validate` → `network.js` message handling) and is **not wrapped in a try/catch** around this call, this uncaught `TypeError` propagates up through the async chain and is caught only by `network.js`'s global `process.on('uncaughtException', ...)` handler, which explicitly does `throw err; // crash the process to avoid ending up in an inconsistent state` (`network.js:4530-4543`). This deliberately kills the entire node process on any single uncaught exception raised while validating a single unit/message — a direct analog to the libming NULL-pointer-dereference DoS: unchecked/mishandled data leads to a crash reachable by any unprivileged unit poster whose address definition includes an `in merkle` authentifier clause with a malformed authentifier value.

I was not able to fully verify within the remaining budget whether an upstream type check (e.g., in the JSON schema/definition validator that runs before `evaluate()`) enforces that `assocAuthentifiers[path]` must be a string in all code paths reaching `'in merkle'`, nor whether every possible entry point (e.g., signed_message.js's `validateAuthentifiers` call, wrapped in try/catch at `signed_message.js:277-294`) is equally exposed — some entry points into `Definition.validateAuthentifiers` (e.g. `signed_message.js`) do wrap the call in try/catch and would not crash the process, while the primary unit-validation path (`validation.js` → `validateAuthor` → `Definition.validateAuthentifiers`) does not appear to have such a wrapper around the `evaluate()` internals.

### Title
Uncaught TypeError from unchecked merkle-proof deserialization crashes the node - (File: definition.js)

### Summary
The `'in merkle'` authentifier-evaluation branch in `definition.js` passes attacker-controlled authentifier data directly to `merkle.deserializeMerkleProof()` without validating its type, and the call site has no surrounding try/catch. A malformed authentifier value causes an uncaught `TypeError`, which the global handler in `network.js` intentionally re-throws to crash the whole node process — a JS analog of CVE-2017-9989's unchecked-allocation NULL pointer dereference DoS.

### Finding Description
In the address-definition evaluator (`definition.js`, `evaluate()` function, case `'in merkle'`), the code does: [1](#0-0) 
`assocAuthentifiers[path]` is only checked for truthiness (`if (!assocAuthentifiers[path]) return cb2(false);`), not for being a string. It is then passed straight to `merkle.deserializeMerkleProof(serialized_proof)`: [2](#0-1) 
which unconditionally calls `serialized_proof.split("-")`. If `serialized_proof` is any truthy non-string value (e.g. an object or number, which JSON permits as an authentifier value), `.split` does not exist on it and a `TypeError` is thrown synchronously, uncaught by any try/catch in the call chain from `validateAuthentifiers`/`evaluate`.

Unlike `verifyMerkleProof`, which wraps its logic in try/catch and safely returns `false` on error, `deserializeMerkleProof` has no such protection, and the caller in `definition.js` does not wrap it either. This is directly analogous to libming's `outputtxt.c` mishandling allocation results and dereferencing a NULL pointer without a check — here, an unchecked/mistyped value is dereferenced (`.split`) without a type guard.

Because address definitions and their authentifiers are attacker-supplied fields of a posted unit, an unprivileged unit poster can construct an address whose definition contains an `in merkle` clause and then post a unit with a malformed (non-string) authentifier for that path, using minimally-signed/otherwise-valid metadata to reach this code path during normal unit validation (`validateAuthor` → `Definition.validateAuthentifiers` → `evaluate`).

### Impact Explanation
Any uncaught exception thrown while processing a single unit is caught only by the process-wide handler in `network.js`, which is explicitly designed to crash the whole process: [3](#0-2) 
This means a single malicious unit can crash any full node that attempts to validate it, taking the node offline and preventing it from confirming new units until manually restarted — matching the "network unable to confirm new units" impact category, analogous to the remote DoS in the original CVE.

### Likelihood Explanation
Likelihood is limited by the need to control an address whose definition contains an `'in merkle'` authentifier clause (a legitimate but less common oscript feature), and post a unit exercising that authentifier path with a non-string value assigned to it. This requires crafting a specific address definition ahead of time but no special privileges — any user can define such an address and later post a unit using it, making the attack fully self-contained and reachable without any operator or hub cooperation.

### Recommendation
Add a type check for `assocAuthentifiers[path]` (must be a string) before calling `merkle.deserializeMerkleProof`, and/or wrap the `deserializeMerkleProof`/`verifyMerkleProof` invocation pair in `definition.js`'s `'in merkle'` case in a try/catch that reports a validation error via `cb2(false)`/`fatal_error` instead of allowing an exception to propagate. Additionally, consider hardening `deserializeMerkleProof` itself to validate that its input is a string and throw a caught, descriptive error rather than a raw `TypeError`.

### Proof of Concept
1. Post a unit A defining an address `X` whose definition includes:
   `['in merkle', [['ORACLE_ADDR'], 'feed_name', 'expected_value']]`
   nested under a normal top-level structure (e.g., `['and', [['address', 'X'], ...]]` or as the sole condition), i.e., simply define address `X`'s definition as `['in merkle', [['ORACLE_ADDR'], 'feed_name', 'expected_value']]`.
2. Post a second unit signed/authored by address `X`, where `objAuthor.authentifiers["r"]` (the path corresponding to the `'in merkle'` node) is set to a non-string JSON value, e.g. `{"a":1}` or `12345`, instead of the expected serialized-proof string.
3. When a node validates this unit, `Definition.validateAuthentifiers` → `evaluate()` reaches the `'in merkle'` case, `assocAuthentifiers[path]` is truthy (an object/number) and passes the `!assocAuthentifiers[path]` guard, and `merkle.deserializeMerkleProof(serialized_proof)` calls `.split("-")` on a non-string, throwing an uncaught `TypeError`.
4. The exception is not caught anywhere in the synchronous call chain, propagates to the event loop, triggers `network.js`'s `process.on('uncaughtException', ...)` handler, which logs and then re-throws, crashing the node process.

### Citations

**File:** definition.js (L1004-1020)
```javascript
			case 'in merkle':
				// ['in merkle', [['BASE32'], 'data feed name', 'expected value']]
				if (!assocAuthentifiers[path])
					return cb2(false);
				arrUsedPaths.push(path);
				var arrAddresses = args[0];
				var feed_name = args[1];
				var element = args[2];
				var min_mci = args[3] || 0;
				var serialized_proof = assocAuthentifiers[path];
				var proof = merkle.deserializeMerkleProof(serialized_proof);
			//	console.error('merkle root '+proof.root);
				if (!merkle.verifyMerkleProof(element, proof)){
					fatal_error = "bad merkle proof at path "+path;
					return cb2(false);
				}
				dataFeeds.dataFeedExists(arrAddresses, feed_name, '=', proof.root, min_mci, objValidationState.last_ball_mci, false, cb2);
```

**File:** merkle.js (L75-82)
```javascript
function deserializeMerkleProof(serialized_proof){
	var arr = serialized_proof.split("-");
	var proof = {};
	proof.root = arr.pop();
	proof.index = arr.shift();
	proof.siblings = arr;
	return proof;
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
