## Analog Found

### Title
Non-constant-time comparison of the `hash` authentifier secret allows timing side-channel recovery of hash-lock preimages - (File: definition.js)

### Summary
The external report describes a covert timing channel in comparing an MD5 password hash during PostgreSQL authentication, which lets an attacker recover credentials byte-by-byte through response-time measurements. ocore has a structurally identical pattern: the `hash` authentifier type, used to protect addresses/spending conditions with a SHA-256 preimage secret, is verified with a plain JavaScript `===` string comparison instead of a constant-time comparison.

### Finding Description
An Obyte address (or asset spending condition) can require a `hash` authentifier, defined as `['hash', {algo: 'sha256', hash: 'base64_digest'}]`, validated in `validateDefinition` [1](#0-0)  and enforced during spend validation in `validateAuthentifiers`: [2](#0-1) 

The critical line is:
```js
var res = (args.hash === crypto.createHash("sha256").update(assocAuthentifiers[path], "utf8").digest("base64"));
```
This compares the computed digest of the attacker-supplied preimage against the target digest using JavaScript's native `===` operator on strings, which in V8 short-circuits on the first mismatching byte rather than comparing in constant time. A `crypto.timingSafeEqual`-based comparison is never used anywhere in the codebase for this or any other secret/authentication comparison (`sig` verification at line 745 similarly relies on `ecdsaSig.verify`, which is not the concern here — the concern is specifically string/hash equality checks that gate authorization).

This mirrors the reported bug class precisely: a security-critical secret comparison performed with a data-dependent, early-exit equality check that can leak information about the correct value through response-time variance, rather than via a constant-time comparison.

### Impact Explanation
The `hash` authentifier is a legitimate ocore primitive for building hash-locked addresses (e.g., atomic-swap or HTLC-style contracts, or "hash of secret spends funds" schemes) — see its use tracked in `wallet_defined_by_addresses.js`'s `extractAddressPathsFromDefinition`, which explicitly special-cases `'hash'` paths as `'secret'` [3](#0-2) . Any unprivileged party can post a candidate unit spending from such an address with a guessed preimage as the authentifier; the node's validation of that unit (`validateAuthentifiers` → `validateAuthor`) performs the vulnerable comparison. If timing differences during large-scale unit submission/validation can be measured (even coarsely, via repeated probing and statistical averaging), an attacker could progressively narrow down the correct preimage byte-by-byte, faster than brute-forcing the full SHA-256 preimage space, ultimately recovering the secret and gaining the ability to spend funds from the hash-locked address — i.e., concrete unauthorized spending.

### Likelihood Explanation
Exploitation requires an attacker to repeatedly submit candidate units (or otherwise trigger `validateAuthentifiers`) and measure the validation response timing precisely enough to distinguish nanosecond/microsecond-level string-comparison differences amid node processing and network jitter. This is a real but difficult side channel — analogous to the original PostgreSQL finding, which was itself rated Medium severity (CVSS 6.5) despite requiring careful statistical timing measurement over the network. The likelihood is nontrivial because the vulnerable code path is directly reachable by any unprivileged unit poster with no special access, and hash-locked addresses are an intended, documented address-definition feature.

### Recommendation
Replace the `===` string comparison of the SHA-256 digest in `definition.js`'s `hash` case with a constant-time comparison, e.g. using `crypto.timingSafeEqual` on the raw digest buffers (after ensuring equal length) instead of comparing base64-encoded strings directly.

### Proof of Concept
1. Attacker observes (or already knows) an address definition of the form `['hash', {hash: 'TARGET_DIGEST'}]` used as a spending condition.
2. Attacker crafts a unit spending from that address with an authentifier value `guess_i` at the corresponding path.
3. Node validation calls `crypto.createHash("sha256").update(guess_i,"utf8").digest("base64") === args.hash` in `definition.js` line 763.
4. Attacker measures validation response time across many submitted guesses that share a common prefix vs. guesses that don't, using the `===` short-circuit timing differential to infer which prefix bytes of the digest match, iteratively refining a preimage that hashes to `TARGET_DIGEST`.
5. Once a valid preimage is found, attacker submits a real spending unit using it as the authentifier, achieving unauthorized spending from the hash-locked address. [2](#0-1)

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

**File:** wallet_defined_by_addresses.js (L365-367)
```javascript
			case 'hash':
				result[path] = 'secret';
				break;
```
