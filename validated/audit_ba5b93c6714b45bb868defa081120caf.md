### Title
Unhandled TypeError from non-string `in merkle` authentifier crashes node during address-definition validation - (File: definition.js)

### Summary
The CVE describes ImageMagick crashing with a NULL pointer dereference when it blindly assumes a crafted PNG chunk has the expected internal structure. `ocore`'s `in merkle` address-definition operator has the same bug class: it takes an attacker-supplied authentifier value straight from the unit and passes it into `merkle.deserializeMerkleProof()` without checking its type, so a unit that defines an `in merkle` condition and supplies a non-string authentifier at that path throws an uncaught `TypeError` deep inside validation, crashing the validating node's process.

### Finding Description
`validateAuthentifiers()` in `definition.js` handles the `in merkle` definition operator: [1](#0-0) 

```
case 'in merkle':
    if (!assocAuthentifiers[path])
        return cb2(false);
    ...
    var serialized_proof = assocAuthentifiers[path];
    var proof = merkle.deserializeMerkleProof(serialized_proof);
    if (!merkle.verifyMerkleProof(element, proof)){
        fatal_error = "bad merkle proof at path "+path;
        return cb2(false);
    }
    dataFeeds.dataFeedExists(...);
```

`assocAuthentifiers` comes directly from `objAuthor.authentifiers`, which is attacker-controlled JSON in the posted unit. The only guard is a truthiness check (`!assocAuthentifiers[path]`), which passes for any truthy value including numbers, arrays, booleans, and objects — not just strings.

`merkle.deserializeMerkleProof()` immediately calls `.split("-")` on the value: [2](#0-1) 

```
function deserializeMerkleProof(serialized_proof){
	var arr = serialized_proof.split("-");
	...
}
```

If `serialized_proof` is, e.g., a number (`42`), a boolean (`true`), an array, or an object, `.split` does not exist on it and a `TypeError: serialized_proof.split is not a function` is thrown synchronously. This throw happens inside the `evaluate()` callback chain of `validateAuthentifiers`, which (unlike the `is_valid_merkle_proof` formula opcode in `formula/evaluation.js:1788`, which wraps a similar call in `bPostPemCurvesFix`-gated array checks and a `try/catch` around `verifyMerkleProof`) has no type validation and no surrounding `try/catch` at this call site.

This code path is reached from ordinary unit validation: `validation.js` → `validateAuthors` → `validateAuthor` → `Definition.validateAuthentifiers`, which is invoked for every posted unit whose author uses an address definition containing `in merkle`. [3](#0-2) 

### Impact Explanation
An uncaught synchronous exception thrown from deep inside the async validation call stack is not caught by any `ifUnitError`/`ifJointError` callback in `network.js`'s `handleJoint`. It propagates up as an uncaught exception, which is handled process-wide by: [4](#0-3) 

```
process.on('uncaughtException', (err) => {
	...
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```

Since the crashing unit is a normally broadcastable joint (posted by any unprivileged unit author who defines their address with an `in merkle` clause), every full node that receives and attempts to validate this unit will crash identically. This is a network-wide denial of service: nodes cannot confirm new units while repeatedly crashing on the same malicious unit, matching the "network unable to confirm new units" impact bar.

### Likelihood Explanation
Any unprivileged unit poster can create a fresh address whose definition is `["in merkle", [[oracle_address], "feed_name", "element"]]` (this definition is accepted by `validateDefinition`'s syntactic checks, which never inspect the authentifier value) and post a unit that includes the crafted address as an author providing a non-string authentifier at that path (e.g. a number or a nested object instead of a serialized proof string). No compromised keys, hubs, or special permissions are needed — a single one-shot unit exploits this deterministically across every node that validates it.

### Recommendation
In `definition.js`'s `in merkle` case (and in `merkle.deserializeMerkleProof`), validate that `assocAuthentifiers[path]` is a non-empty string before calling `deserializeMerkleProof`, returning `cb2(false)` otherwise; additionally, harden `deserializeMerkleProof`/`verifyMerkleProof` to defensively type-check their inputs and never throw synchronously outside of a caught context, mirroring the type checks already present for `is_valid_merkle_proof` in `formula/evaluation.js`.

### Proof of Concept
1. Choose any oracle address and construct definition `D = ["in merkle", [["SOME_ORACLE_ADDR"], "feed", "element"]]`; compute `addr = chash160(D)`.
2. Build a unit authored by `addr`, with `definition: D` and `authentifiers: { "r": 12345 }` (a number instead of a serialized proof string).
3. Broadcast the unit to the network. During validation, `validateAuthentifiers` reaches the `in merkle` case, `assocAuthentifiers["r"]` is `12345` (truthy, passes the only check), and `merkle.deserializeMerkleProof(12345)` throws `TypeError: serialized_proof.split is not a function`, which is uncaught and crashes every receiving node's process via the global `uncaughtException` handler.

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

**File:** validation.js (L1128-1146)
```javascript
function validateAuthors(conn, arrAuthors, objUnit, objValidationState, callback) {
	if (objValidationState.bAA && arrAuthors.length !== 1)
		throw Error("AA unit with multiple authors");
	if (arrAuthors.length > constants.MAX_AUTHORS_PER_UNIT) // this is anti-spam. Otherwise an attacker would send nonserial balls signed by zillions of authors.
		return callback("too many authors");
	objValidationState.arrAddressesWithForkedPath = [];
	var prev_address = "";
	for (var i=0; i<arrAuthors.length; i++){
		var objAuthor = arrAuthors[i];
		if (objAuthor.address <= prev_address)
			return callback("author addresses not sorted");
		prev_address = objAuthor.address;
	}
	
	objValidationState.unit_hash_to_sign = objectHash.getUnitHashToSign(objUnit);
	
	async.eachSeries(arrAuthors, function(objAuthor, cb){
		validateAuthor(conn, objAuthor, objUnit, objValidationState, cb);
	}, callback);
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
