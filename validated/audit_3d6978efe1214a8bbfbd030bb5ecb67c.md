## Analog Found

### Title
Missing validation of `in merkle` authentifier proof causes uncaught exception and node crash - (File: definition.js)

### Summary
The `DeleteSessionTensor` bug assumed an attacker-controlled tensor had a specific shape (scalar) without validating it, causing a `CHECK`-failure crash. The analogous pattern in ocore is in the `'in merkle'` authentifier-evaluation branch of `validateAuthentifiers`, which takes an attacker-controlled authentifier string straight from the unit and feeds it into `merkle.deserializeMerkleProof()`/`merkle.verifyMerkleProof()` without validating its type or internal structure first.

### Finding Description
When an address definition contains an `'in merkle'` clause, the authentifier supplied by the unit's author for that path is read directly from `assocAuthentifiers[path]` and passed to the merkle-proof deserializer with no format/shape check: [1](#0-0) 

Compare this to the `'sig'` and `'hash'` branches in the same function, which at least check `typeof assocAuthentifiers[path] !== 'string'` before use: [2](#0-1) 

The only upstream constraint on `author.authentifiers[path]` is that it is a non-empty string within a length limit — there is no check that it is a validly-formatted serialized merkle proof: [3](#0-2) 

`validateAuthentifiers` is invoked from unit validation (`validateAuthor` → `Definition.validateAuthentifiers`), which is on the path that runs for every posted unit whose author uses a definition containing `'in merkle'`: [4](#0-3) 

If `merkle.deserializeMerkleProof()` (or `verifyMerkleProof()`) throws on malformed/adversarial input — e.g. a string that doesn't match the expected `root:op:hash|op:hash...` structure — that exception is not caught anywhere in this call chain (unlike the `try/catch` wrapper `signed_message.js` uses around `validateAuthentifiers`, this code path is invoked from `validation.js` without an equivalent guard around this specific branch). An uncaught exception during unit processing is fatal: `network.js` installs a global handler that deliberately re-throws and kills the process to avoid inconsistent state: [5](#0-4) 

This is the same class of bug as the TensorFlow advisory: production code assumes untrusted external data has a specific internal structure, and the lack of validation lets an attacker-supplied malformed value reach a code path that throws a hard failure rather than returning a controlled validation error.

### Impact Explanation
Any address whose definition includes an `'in merkle'` clause can be triggered by an attacker who authors (or co-authors, or is impersonated via inner/nested `'address'` definitions) a unit and supplies a malformed value for that authentifier path. If the deserializer/verifier throws on malformed input instead of failing gracefully, the exception propagates uncaught out of the validation pipeline and crashes the node process handling the unit. Because unit validation runs on every full node (and potentially light-vendor/hub nodes) that receives the joint, a single crafted unit can be broadcast to the network and crash any node that attempts to validate it — a "network unable to confirm new units" scenario if repeated broadcasts keep crashing recovering nodes, or a node-disagreement scenario if some nodes crash before advancing stability while others do not receive/process the unit.

### Likelihood Explanation
Exploitability depends on whether `merkle.deserializeMerkleProof`/`verifyMerkleProof` actually throw (rather than return an error value) on malformed input — this could not be fully confirmed because the merkle.js implementation body was not available in the indexed context for this session. The structural gap is nonetheless clear: unlike `'sig'` and `'hash'`, the `'in merkle'` branch performs no type/format check on the authentifier value before using it, and no `try/catch` wraps this specific call in `validation.js`'s unit-validation flow. Given ocore's demonstrated defensive-coding pattern elsewhere (explicit `typeof`/length checks on every other authentifier type), this is very likely an oversight rather than an intentional design decision.

### Recommendation
- Add explicit validation of `assocAuthentifiers[path]` before calling `merkle.deserializeMerkleProof()` in the `'in merkle'` branch, mirroring the `typeof ... !== 'string'` guard used for `'hash'`/`'sig'`.
- Wrap the deserialization/verification call in a `try/catch` and convert any thrown error into `fatal_error`/`cb2(false)` instead of letting it propagate.
- Add fuzz/unit tests that submit malformed merkle-proof authentifiers to confirm the deserializer fails safely rather than throwing.

### Proof of Concept
1. Define an address whose spending condition includes `['in merkle', [['<oracle_address>'], 'feed_name', 'expected_element']]` and register it (chash matches).
2. Compose and broadcast a unit spending from/authenticating with this address, providing an authentifier value at the corresponding path (`r` or nested path) that is a syntactically-invalid "serialized merkle proof" string (not matching the expected root:op:hash delimited format) but still passes the `isNonemptyString` / length checks in `signed_message.js`/`validation.js`.
3. When any node runs `Definition.validateAuthentifiers` → the `'in merkle'` branch → `merkle.deserializeMerkleProof(serialized_proof)`, if the implementation throws (e.g. from failed `.split()` indexing or `JSON.parse`), the exception is uncaught, hits the global `uncaughtException` handler, and crashes the node process.

*Note: full confirmation that `merkle.deserializeMerkleProof` throws (versus returning a benign error) requires inspecting `merkle.js` directly, which could not be retrieved in this session; a Devin session with full repository access should verify this before treating the PoC as conclusive.*

### Citations

**File:** definition.js (L756-772)
```javascript
			case 'hash':
				// ['hash', {algo: 'sha256', hash: 'base64'}]
				if (!assocAuthentifiers[path] || typeof assocAuthentifiers[path] !== 'string')
					return cb2(false);
				arrUsedPaths.push(path);
				var algo = args.algo || 'sha256';
				if (algo === 'sha256'){
					var res = (args.hash === crypto.createHash("sha256").update(assocAuthentifiers[path], "utf8").digest("base64"));
					if (!res)
						fatal_error = "bad hash at path "+path;
					cb2(res);
				}
				else {
					fatal_error = "unsupported hash algo at path "+path;
					return cb2(false);
				}
				break;
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

**File:** definition.js (L1454-1465)
```javascript
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
		if (err)
			return cb(err);
		//console.log("eval def");
		evaluate(arrDefinition, 'r', function(res){
			if (fatal_error)
				return cb(fatal_error);
			if (!bAssetCondition && arrUsedPaths.length !== Object.keys(assocAuthentifiers).length)
				return cb("some authentifiers are not used, res="+res+", used="+arrUsedPaths+", passed="+JSON.stringify(assocAuthentifiers));
			cb(null, res);
		});
	});
```

**File:** signed_message.js (L173-180)
```javascript
		if (!ValidationUtils.isNonemptyObject(author.authentifiers))
			return handleResult("no authentifiers");
		for (let path in author.authentifiers) {
			if (!ValidationUtils.isNonemptyString(author.authentifiers[path]))
				return handleResult("authentifiers must be nonempty strings");
			if (author.authentifiers[path].length > constants.MAX_AUTHENTIFIER_LENGTH)
				return handleResult("authentifier too long");
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
