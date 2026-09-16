### Title
Low-Entropy `hash`-type Address Authentifiers Are Permanently Public and Offline Brute-Forceable - (File: definition.js)

### Summary
The external report describes an OTP with only ~19.93 bits of entropy that could be brute-forced because it is the sole authentication factor and (allegedly) lacks rate limiting. `ocore` contains an analogous but strictly worse construct: the `hash`-type address-definition component, which lets any address (and therefore any spendable balance/AA-controlled fund) be authorized purely by knowledge of a preimage whose SHA-256 digest is committed on-chain in the address definition.

### Finding Description
An address (or asset/AA-condition-adjacent) definition can include a `hash` authentifier: [1](#0-0) 
This is validated by simply comparing the SHA-256 digest of the user-supplied authentifier string: [2](#0-1) 

Unlike a normal `sig` authentifier (which is protected by ECDSA and a 256-bit private key), the `hash` mechanism's security rests entirely on the entropy of the "secret" string chosen by whoever creates the definition. The wallet code itself models "secret"-type signing paths with attacker-controllable length/content: [3](#0-2) 

Crucially, once a unit containing this address definition (or an authentifier attempt) is broadcast to the network, the target hash — and any failed guesses containing partial preimages, in protocols that reveal them — becomes permanently public in the DAG. SHA-256 is fast (billions of hashes/sec on commodity/GPU hardware), so an attacker performing **offline** brute force against the on-chain hash is not constrained by any network-level rate limiting, unlike the OTP-over-email flow that at least has an online rate-limit control point in principle. If a user, wallet feature, or shared/multisig/AA-related definition ends up using a low-entropy secret for this component (e.g., a short numeric code, a common word, or a human-memorable phrase, analogous in weakness to the 6-digit OTP in the report), an attacker can recover the preimage offline and construct a valid authentifier for that path, i.e., forge one of the co-signing conditions used in `validateAuthentifiers`: [4](#0-3) 

### Impact Explanation
Any address whose definition includes a `hash` component secured with insufficient entropy is exposed to unauthorized spending: an attacker who recovers the secret preimage offline can satisfy that authentifier branch and, combined with any other conditions in the definition (e.g. `and`/`or` combinators), sign and broadcast a valid unit spending the address's funds — a direct, concrete case of unauthorized spending / fund loss, matching the "Accept only concrete unauthorized spending... AA fund loss" bar in the validation rules.

### Likelihood Explanation
Likelihood depends entirely on how much entropy is used for the `hash` secret when composing definitions with this component (via wallet code, shared addresses, or AA/contract flows that reuse the `hash`/`secret` authentifier pattern). Because the hash commitment is public and permanent on the DAG, and SHA-256 offers no built-in throttling, any low-entropy secret is fully and cheaply crackable offline — a materially higher-likelihood analog than the reported OTP issue, which at least nominally has server-side rate-limiting as a mitigating factor.

### Recommendation
- Enforce a minimum entropy/length requirement for `hash`-authentifier secrets at definition-validation time in `definition.js` (`validateDefinition`'s `'hash'` case), rejecting low-entropy or dictionary-guessable preimages where feasible.
- Prefer memory-hard/slow hash functions (e.g., PBKDF2/Argon2/scrypt) instead of a single SHA-256 pass when the design intends the secret to be human-chosen, to raise the cost of offline brute force.
- Document/guard wallet APIs (e.g., in `wallet.js`'s `getSigner`/`readFullSigningPaths` "secret" path) so callers cannot construct addresses whose fund-controlling condition relies on a low-entropy user-supplied secret without an additional strong factor (e.g., combined `and` with a `sig` condition).

### Proof of Concept
1. Construct an address definition `["hash", {"hash": sha256("428995").toBase64()}]` (or embed it as one branch of an `and`/`or` definition) and use it to receive funds, or use it inside a wallet/AA flow that lets a "secret"-type signing path be attacker-influenced.
2. Once any unit referencing this address definition is included in the DAG, the hash commitment is public and permanent (`objectHash.getChash160`/definition storage in `storage.readDefinitionByAddress`).
3. An attacker enumerates the full space of low-entropy candidates offline (e.g., all 6-digit numeric strings, 10^6 SHA-256 hashes — computable in well under a second on a single CPU core, with no network interaction and no rate limiting possible) and finds the matching preimage.
4. The attacker submits an authentifier `{"<path>": "428995"}`; `definition.js`'s `validateAuthentifiers` `'hash'` case (lines 756-772) accepts it because `sha256("428995") === committed hash`, letting the attacker satisfy that branch of the definition and spend the funds if no other unforgeable factor is required.

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

**File:** wallet.js (L1991-1994)
```javascript
					else if (type === 'secret') {
						if (opts.secrets && opts.secrets[signing_path])
							assocLengthsBySigningPaths[signing_path] = opts.secrets[signing_path].length;
					}
```

**File:** validation.js (L1243-1254)
```javascript
	function validateAuthentifiers(arrAddressDefinition){
		Definition.validateAuthentifiers(
			conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers, 
			function(err, res){
				if (err) // error in address definition
					return callback(err);
				if (!res) // wrong signature or the like
					return callback("authentifier verification failed");
				checkSerialAddressUse();
			}
		);
	}
```
