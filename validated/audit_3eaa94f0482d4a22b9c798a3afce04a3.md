## Analysis

The Kestra CVE is about a fast, unsalted, single-round hash (SHA-512) used to protect a credential, allowing an attacker with read access to the stored hash to brute-force it offline and escalate privileges. The matching bug class in `ocore--002` is the `hash` authentifier operator in address/asset definitions, which serves the same role — a secret gates a spending/authentication condition — but is protected only by a single unsalted, unstretched SHA-256 digest.

### Title
Weak Unsalted Single-Round SHA-256 "hash" Authentifier Enables Offline Brute-Force Theft of Hash-Locked Funds - (File: definition.js)

### Summary
Address and asset definitions in ocore support a `['hash', {algo: 'sha256', hash: 'base64'}]` authentifier operator, which lets a unit author satisfy a spending condition by revealing a preimage whose SHA-256 digest matches the value embedded in the definition [1](#0-0) . Verification is performed with a single, unsalted `crypto.createHash("sha256")` call over the raw secret string [2](#0-1) . Because the target hash becomes public as soon as the owning address's definition is disclosed on the DAG (e.g., on first use as an `author.definition`, as an inner address referenced via the `['address', ...]` op, or shared as part of a multi-condition contract such as `["and", [["sig", ...], ["hash", ...]]]`), any unprivileged party who observes it can attempt an offline dictionary/brute-force attack using commodity SHA-256 hashing hardware, with no salt or iteration count to slow the attacker down.

### Finding Description
The `hash` op is validated the same way whether used inside a normal address definition or an asset transfer condition [3](#0-2) . During spend validation the supplied authentifier string is hashed once with plain SHA-256 and compared to the on-chain `args.hash` [4](#0-3) . This is functionally a password/secret-verification mechanism analogous to BasicAuth password storage in the reported CVE, but it uses an even weaker construction than the vulnerable SHA-512 case: a single pass of SHA-256 with no salt and no configurable work factor (unlike a KDF such as scrypt/Argon2/bcrypt). GPUs/ASICs can compute billions of SHA-256 hashes per second, so any secret with less than very high entropy (a passphrase, PIN, or human-memorable phrase — which is exactly the kind of value users are likely to pick for this feature, mirroring how the CVE's admin chose a crackable password) can be recovered from the exposed hash quickly.

The hash value is not confidential once the definition is revealed: `validateAuthentifiers`/`evaluateAssetCondition` are invoked from ordinary unit validation and from `is_valid_signed_package` in oscript formulas [5](#0-4) , and definitions get persisted and re-served through `readJointDirectly`/`authentifiers` queries for any full node [6](#0-5) . Any node (unprivileged, no special access required — merely a synced full node or light client requesting the joint) can read the `hash` argument from a definition once it appears in any historical unit, satisfying the "unprivileged poster/observer" threat model.

### Impact Explanation
If a user, AA author, or wallet-based tool constructs an address or asset-transfer condition using `['hash', ...]` with an insufficiently high-entropy secret (which the API does nothing to discourage — there is no minimum-entropy check, no salt, no iteration count), an attacker who has merely observed a previously-broadcast unit revealing that hash can brute-force the secret offline and then race to submit a spending unit with the recovered preimage as the authentifier, stealing the funds gated by that condition before the legitimate owner claims them. This is concrete unauthorized spending / fund theft, matching the "double-spend of a stable output"/"unauthorized spending" bar required by scope.

### Likelihood Explanation
Exploitability depends on secret entropy chosen by the definition creator, so it is not universally exploitable, but the protocol provides no safeguard (no minimum length/entropy enforcement, no salting, no slow KDF) comparable to what password-storage best practice requires — exactly the gap flagged in the CVE. Given SHA-256's extreme speed (billions of hashes/sec on consumer GPUs), any moderately weak secret (common in human-chosen passphrases for hash-lock/bounty-style definitions) is crackable within a practical timeframe once exposed.

### Recommendation
- For the `hash` authentifier op, require a minimum entropy/length for hashed secrets, or replace/complement single-round SHA-256 with a salted, memory-hard KDF (e.g., scrypt/Argon2) for cases where the "secret" is meant to be a human-chosen value rather than a high-entropy random token.
- Alternatively, restrict/deprecate `hash`-only-gated definitions (i.e., disallow `hash` as a sole authenticator without an accompanying `sig` from a keypair) and document strongly that only high-entropy random secrets (≥128 bits) should ever be used with this op.
- Consider allowing `algo` to specify a slow hash function and reject overly short authentifier strings (currently only length ≤ `MAX_AUTHENTIFIER_LENGTH` is checked, no minimum) [7](#0-6) .

### Proof of Concept
1. Attacker (or the definition creator's compromised counterparty) waits for a unit to reveal a definition of the form `["hash", {"hash": "BASE64_SHA256_OF_SECRET"}]` (alone or combined via `and`/`or` with a `sig` op), e.g. as demonstrated in the test fixture `["and", [["sig", {pubkey}], ["hash", {hash: validHash}]]]` [8](#0-7) .
2. Attacker extracts `args.hash` from the public definition (retrievable from any synced node's `definitions`/`authentifiers` tables) [9](#0-8) .
3. Attacker performs an offline brute-force/dictionary attack: for candidate secrets `s`, compute `sha256(s)` and compare base64 output to `args.hash`, exactly mirroring the verification logic in `definition.js` [4](#0-3) , using GPU-accelerated SHA-256 (billions of attempts/sec).
4. Once the secret is recovered, attacker crafts a unit whose `author.authentifiers[path]` is set to the recovered plaintext secret, satisfying the `hash` condition, and (if `sig` is also required and separately compromised, or if `hash` is the sole/`or`-combined condition) broadcasts it to spend the funds before the legitimate party, achieving unauthorized fund theft.

### Citations

**File:** definition.js (L252-267)
```javascript
			case 'hash':
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["algo", "hash"]))
					return cb("unknown fields in "+op);
				if (args.algo === "sha256")
					return cb("default algo must not be explicitly specified");
				if ("algo" in args && args.algo !== "sha256")
					return cb("unsupported hash algo");
				if (!ValidationUtils.isValidBase64(args.hash, constants.HASH_LENGTH))
					return cb("wrong base64 hash");
				return cb();
```

**File:** definition.js (L641-643)
```javascript
function evaluateAssetCondition(conn, asset, arrDefinition, objUnit, objValidationState, cb){
	validateAuthentifiers(conn, null, asset, arrDefinition, objUnit, objValidationState, null, cb);
}
```

**File:** definition.js (L645-646)
```javascript
// also validates address definition
function validateAuthentifiers(conn, address, this_asset, arrDefinition, objUnit, objValidationState, assocAuthentifiers, cb){
```

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

**File:** storage.js (L245-283)
```javascript
				function(callback){ // authors
					conn.query("SELECT address, definition_chash FROM unit_authors WHERE unit=? ORDER BY address", [unit], function(rows){
						objUnit.authors = [];
						async.eachSeries(
							rows, 
							function(row, cb){
								var author = {address: row.address};

								function onAuthorDone(){
									objUnit.authors.push(author);
									cb();
								}

								if (bVoided)
									return onAuthorDone();
								author.authentifiers = {};
								conn.query(
									"SELECT path, authentifier FROM authentifiers WHERE unit=? AND address=?", 
									[unit, author.address], 
									function(sig_rows){
										for (var i=0; i<sig_rows.length; i++)
											author.authentifiers[sig_rows[i].path] = sig_rows[i].authentifier;

										// if definition_chash is defined:
										if (row.definition_chash){
											readDefinition(conn, row.definition_chash, {
												ifFound: function(arrDefinition){
													author.definition = arrDefinition;
													onAuthorDone();
												},
												ifDefinitionNotFound: function(definition_chash){
													throw Error("definition "+definition_chash+" not defined");
												}
											});
										}
										else
											onAuthorDone();
									}
								);
```

**File:** signed_message.js (L176-179)
```javascript
			if (!ValidationUtils.isNonemptyString(author.authentifiers[path]))
				return handleResult("authentifiers must be nonempty strings");
			if (author.authentifiers[path].length > constants.MAX_AUTHENTIFIER_LENGTH)
				return handleResult("authentifier too long");
```

**File:** test/formula.test.js (L6301-6313)
```javascript
test.cb('is_valid_signed_package with bad hash authentifier', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = {};
	var pubkey = crypto.randomBytes(33).toString('base64');
	var validHash = crypto.createHash('sha256').update('test', 'utf8').digest('base64');

	var maliciousDefinition = ["and", [
		["sig", {pubkey: pubkey}],
		["hash", {hash: validHash}],
		["seen address", 'I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT'],
	]];

```
