### Title
Uncaught exception in `in merkle` authentifier evaluation crashes the node processing an untrusted unit - (File: `definition.js`, `merkle.js`)

### Summary
Analogous to CVE-2024-23449 (Elasticsearch crashing on a malformed encrypted PDF attachment because the ingest pipeline dereferenced attacker-controlled structured data without validating its shape), `ocore` contains a code path where an attacker-controlled authentifier value is passed unvalidated into a parser that assumes a specific type, throwing an uncaught `TypeError` that is not caught anywhere in the call chain. Because `network.js` deliberately re-throws inside its global `uncaughtException` handler to "crash the process to avoid ending up in an inconsistent state," this turns a single crafted unit into a full node crash for any full node/hub that validates it.

### Finding Description
When validating the authentifiers supplied by a unit's author against that author's address definition, `definition.js`'s `validateAuthentifiers` evaluates each definition operator against the attacker-supplied `assocAuthentifiers` map (`author.authentifiers` from the posted unit). For most operators the code carefully checks the type of the corresponding authentifier before using it — e.g. the `hash` operator: [1](#0-0) 

which explicitly checks `typeof assocAuthentifiers[path] !== 'string'`.

However, the `in merkle` operator only checks truthiness, not type, before handing the value to the merkle-proof parser: [2](#0-1) 

`merkle.deserializeMerkleProof` assumes its argument is a string and immediately calls `.split("-")` on it with no type check and no try/catch: [3](#0-2) 

If an attacker supplies a non-string truthy authentifier value (e.g. a number, boolean-ish truthy value is fine but numbers/objects/arrays are valid JSON values that survive `isObjectWellFormed`/JSON parsing of the unit) at the path corresponding to an `in merkle` clause in the referenced address definition, `serialized_proof.split` is not a function and a `TypeError` is thrown synchronously inside the `evaluate()` callback chain of `validateAuthentifiers`. This exception is not wrapped in a `try/catch` at the call site (`definition.js:1014`) nor anywhere up the `validateAuthor` → `validation.validate()` async chain that this code executes in.

Unlike `verifyMerkleProof`, which does wrap its logic in `try/catch` and safely returns `false` on malformed proofs: [4](#0-3) 

`deserializeMerkleProof` has no such protection, and it is invoked *before* `verifyMerkleProof` is ever reached, so the safety net in `verifyMerkleProof` never gets a chance to run.

This validation path is reached for any unit whose author uses an address definition containing an `in merkle` clause, as part of ordinary unit/AA-trigger validation: [5](#0-4) 

Since `network.js` installs a process-wide handler that intentionally re-throws any uncaught exception to crash the node: [6](#0-5) 

any full node or hub that receives and validates such a unit (posted directly, gossiped, or included as a parent) crashes.

### Impact Explanation
A single unprivileged unit poster can craft an address (and corresponding unit with author `authentifiers`) whose definition includes an `in merkle` clause, and set the authentifier value at that path to a non-string JSON value (e.g. a number). When any node — including witnesses and hubs — attempts to validate this unit (a normal, unauthenticated, unprivileged action reachable via ordinary unit posting), it hits the unguarded `.split()` call and throws an uncaught `TypeError`. Because ocore's own `network.js` exception handler is designed to re-throw and crash the process on any uncaught exception, this results in a full node process crash. If propagated to enough nodes (any node that receives/relays/validates the unit), this can prevent the network from confirming new units, satisfying the "network unable to confirm new units" impact bar.

### Likelihood Explanation
Likelihood is high: constructing the malicious address definition and unit requires no special privileges — only the ability to post a unit whose author has an `in merkle` address definition and to supply a malformed (non-string) authentifier value at the corresponding path. No signing bypass, race condition, or privileged access is needed; the type-confusion is purely a validation gap in `definition.js` that is inconsistent with the type-checks already present for sibling operators (`hash`, `sig`) in the same function, indicating this is an overlooked edge case rather than a hardened path.

### Recommendation
Add an explicit type check (`typeof assocAuthentifiers[path] === 'string'`) before calling `merkle.deserializeMerkleProof` in the `in merkle` case of `validateAuthentifiers` in `definition.js`, mirroring the existing check used in the `hash` case. Additionally, harden `merkle.deserializeMerkleProof` in `merkle.js` itself to validate that its input is a string (and reasonably bounded in size) and to fail gracefully (e.g., return `null`/throw a caught, descriptive error) rather than letting a raw `TypeError` propagate, so that any other current or future unguarded call site cannot crash the process.

### Proof of Concept
1. Attacker creates address `A` with definition `["in merkle", [["ORACLE_ADDR"], "feed_name", "expected_value"]]`.
2. Attacker composes and posts a unit authored by `A` with `authentifiers = { "r": 12345 }` (a JSON number instead of the expected serialized-proof string) — this passes JSON well-formedness checks and the `!assocAuthentifiers[path]` truthiness check in `definition.js` at line 1006.
3. Any node validating this unit (via `validation.validate` → `validateAuthor` → `validateAuthentifiers`) reaches the `in merkle` case and calls `merkle.deserializeMerkleProof(12345)`, which executes `(12345).split("-")`, throwing `TypeError: serialized_proof.split is not a function`.
4. This uncaught exception propagates to the process-level `uncaughtException` handler in `network.js`, which logs it and re-throws, crashing the node process.

### Citations

**File:** definition.js (L756-759)
```javascript
			case 'hash':
				// ['hash', {algo: 'sha256', hash: 'base64'}]
				if (!assocAuthentifiers[path] || typeof assocAuthentifiers[path] !== 'string')
					return cb2(false);
```

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

**File:** merkle.js (L84-101)
```javascript
function verifyMerkleProof(element, proof){
	// Node-as-Leaf issue might matter in some cases
	try {
		var index = proof.index;
		var the_other_sibling = hash(element);
		for (var i = 0; i < proof.siblings.length; i++) {
			// this also works for duplicated trailing nodes
			if (index % 2 === 0)
				the_other_sibling = hash(the_other_sibling + proof.siblings[i]);
			else
				the_other_sibling = hash(proof.siblings[i] + the_other_sibling);
			index = Math.floor(index / 2);
		}
		return (the_other_sibling === proof.root);
	}
	catch (e){
		return false;
	}
```

**File:** validation.js (L118-180)
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

	if (objJoint.unsigned){
		if (hasFieldsExcept(objJoint, ["unit", "unsigned"]))
			return callbacks.ifJointError("unknown fields in unsigned unit-joint");
	}
	else if ("ball" in objJoint){
		if (!isStringOfLength(objJoint.ball, constants.HASH_LENGTH))
			return callbacks.ifJointError("wrong ball length");
		if (hasFieldsExcept(objJoint, ["unit", "ball", "skiplist_units"]))
			return callbacks.ifJointError("unknown fields in ball-joint");
		if ("skiplist_units" in objJoint){
			if (!isNonemptyArray(objJoint.skiplist_units))
				return callbacks.ifJointError("missing or empty skiplist array");
			//if (objUnit.unit.charAt(0) !== "0")
			//    return callbacks.ifJointError("found skiplist while unit doesn't start with 0");
		}
	}
	else{
		if (hasFieldsExcept(objJoint, ["unit"]))
			return callbacks.ifJointError("unknown fields in unit-joint");
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
