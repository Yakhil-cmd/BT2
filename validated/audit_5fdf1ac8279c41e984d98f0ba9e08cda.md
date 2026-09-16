### Title
Hash-lock address definitions (`["hash", {...}]`) allow pass-the-preimage fund theft because the authentifier is never bound to the spending unit - (File: definition.js)

### Summary
Obyte address definitions support a `hash` authentifier op that lets funds be spent by revealing a SHA-256 preimage instead of (or in addition to) a signature. Unlike the `sig` op, which is cryptographically bound to the specific unit being authorized via `unit_hash_to_sign`, the `hash` op only checks that the presented authentifier string hashes to the stored value — it has no relationship whatsoever to the unit's content, outputs, or author. Anyone who observes a revealed preimage (which is necessarily public once used, since units and their authentifiers are broadcast in the clear) can immediately reuse that exact string as a valid authentifier in a completely different, self-authored unit, and race to have that unit accepted instead of the legitimate one. This is structurally identical to the "pass-the-hash" bug class in the report: a value derived from (or literally being) the credential itself is treated as sufficient proof of authorization without being tied to the transaction/session it was meant for.

### Finding Description
In `definition.js`, `validateAuthentifiers`'s `evaluate` function handles the two "leaf" authentication primitives very differently: [1](#0-0) 

For `sig`, the presented signature is verified against `objValidationState.unit_hash_to_sign`, which is derived from the full unit content (`objectHash.getUnitHashToSign`), so a signature is valid for one and only one unit.

For `hash`, however: [2](#0-1) 

the check is simply `args.hash === sha256(assocAuthentifiers[path])`. There is no reference to `objValidationState.unit_hash_to_sign`, no reference to the unit's outputs, and no reference to the author's address context beyond the address whose definition contains the hash. The preimage supplied in one unit's `authentifiers` is therefore a bearer credential: whoever learns it (by simply observing any broadcast unit, even before it is stable, since all unit content including authentifiers is public) can supply the identical string in the `authentifiers` of an entirely different, self-composed unit that spends from the same address to a different output set.

This is confirmed by the definition-validation code, which explicitly allows `hash` to be used as a definition op on its own, with no policy requiring it to be combined with a `sig`: [3](#0-2) 

and by `wallet_defined_by_addresses.js`'s `extractAddressPathsFromDefinition`, which explicitly recognizes stand-alone hash conditions (marking them `'secret'`) as a normal, expected pattern for shared/multi-party addresses: [4](#0-3) 

So the protocol both permits and, via wallet infrastructure, actively supports single-hash-condition addresses (e.g., for atomic-swap/HTLC-style or escrow constructions between an unprivileged unit poster and a counterparty), yet provides no unit-binding for the `hash` authentifier the way it does for `sig`.

### Impact Explanation
Any address whose spending condition is (or includes, via `or`) a bare `["hash", {...}]` leaf is vulnerable to preimage front-running: the first time the legitimate owner (or a protocol such as an atomic swap, arbiter/prosaic contract, or private payment counterparty) reveals the preimage in a broadcast unit, any third party who observes that unit before it stabilizes can extract the preimage and immediately compose and broadcast a competing unit spending the same output(s) to an address of the attacker's choosing, with equal or higher fee/priority. Depending on which unit gets included as "good" by the DAG/witness ordering, this results in concrete unauthorized redirection/theft of funds and a double-spend contest over the hash-locked output — i.e., unauthorized spending and potential node disagreement about which of the two conflicting units is the valid one.

### Likelihood Explanation
Any unprivileged party that can observe the p2p network or simply query a node/hub for pending units can extract the authentifier value from a broadcast (not-yet-stable) unit and immediately construct a colliding unit. No special privileges, node compromise, or malicious peer/hub behavior are required — this is reachable purely from processing normal public unit broadcasts, consistent with the required "single posted unit" reachability. The main constraint is winning the ensuing double-spend race, which is a timing/fee competition rather than a cryptographic one.

### Recommendation
Bind the `hash` authentifier to the specific unit being authorized, analogous to how `sig` is bound via `unit_hash_to_sign`. For example, require that `hash` authentifiers be computed over `preimage || unit_hash_to_sign` (or equivalent unit-specific context) rather than the preimage alone, or mandate (at validation time) that any address definition containing a `hash` leaf be combined with an `and`-ed `sig` covering the same or a parent path so that redirecting the payload always requires the legitimate owner's private key as well as the preimage. At minimum, documentation/wallet tooling should strongly discourage stand-alone `hash` conditions and warn users composing HTLC-like definitions about preimage front-running risk.

### Proof of Concept
1. Wallet A creates an address definition `["hash", {"hash": H}]` where `H = sha256(P)`, intended to be redeemable only by whoever knows secret `P` (e.g., set up as one leg of an atomic swap/arbiter escrow, matching `wallet_defined_by_addresses.js`'s recognized `'secret'` pattern).
2. When the time comes to spend, Wallet A composes and broadcasts unit `U1` with `authors: [{address: A, authentifiers: {r: P}}]`, paying itself (or the intended counterparty).
3. Attacker M, monitoring the network/hub for broadcast (unstable) units, reads `U1.authors[0].authentifiers.r` and recovers `P` in plaintext — this is normal, non-privileged unit content, not any secret channel.
4. M immediately composes and broadcasts a conflicting unit `U2` with `authors: [{address: A, authentifiers: {r: P}}]` (same preimage), spending the same output(s) of `A` to M's own address, using `validateAuthentifiers`'s `hash` branch (`definition.js` lines 756-772) which passes because `sha256(P) === H`, with no check tying `P` to `U1` versus `U2`.
5. Depending on network propagation/fee/witness ordering, `U2` may be selected as the "good" unit instead of `U1`, resulting in the funds being redirected to the attacker instead of the intended recipient — an unauthorized spend enabled purely by observing public unit data, i.e., "pass-the-preimage" analogous to the reported "pass-the-hash" bypass.

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

**File:** definition.js (L734-754)
```javascript
			case 'sig':
				// ['sig', {algo: 'secp256k1', pubkey: 'base64'}]
				//console.log(op, path);
				var signature = assocAuthentifiers[path];
				if (!signature)
					return cb2(false);
				arrUsedPaths.push(path);
				var algo = args.algo || 'secp256k1';
				if (algo === 'secp256k1'){
					if (objValidationState.bUnsigned && signature[0] === "-") // placeholder signature
						return cb2(true);
					var res = ecdsaSig.verify(objValidationState.unit_hash_to_sign, signature, args.pubkey);
					if (!res)
						fatal_error = "bad signature at path "+path;
					cb2(res);
				}
				else {
					fatal_error = "unsupported sig algo at path "+path;
					return cb2(false);
				}
				break;
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

**File:** wallet_defined_by_addresses.js (L362-371)
```javascript
			case 'address':
				result[path] = args;
				break;
			case 'hash':
				result[path] = 'secret';
				break;
			case 'in merkle':
				result[path] = ''; // empty address
				break;
		}
```
