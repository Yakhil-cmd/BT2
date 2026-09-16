I have enough evidence to produce the analog finding now.

### Title
Address `hash` authentifier stores a cleartext unsalted SHA-256 digest that enables offline brute-forcing of low-entropy secrets - (File: definition.js)

### Summary
Like the Ente 2of3 card format that embedded a cleartext FNV-1a checksum of the secret, ocore's `['hash', {algo:'sha256', hash:'base64'}]` address-definition primitive embeds a plain, unsalted, single-round SHA-256 digest of a spending secret directly in the address definition. Any unprivileged party who obtains that definition — which is routinely shared between paired devices *before* the protecting secret is ever revealed on-chain (e.g. when proposing a shared/multisig address) — can test candidate low-entropy secrets offline at very high speed, defeating the secrecy the hash-lock is meant to provide.

### Finding Description
The `hash` operator is validated in two places:
- Definition syntax check: [1](#0-0) 
- Authentifier check, which recomputes `sha256(secret)` and compares it to the stored `args.hash`: [2](#0-1) 

The `hash` value (`args.hash`) is stored as plain cleartext inside the address definition array. That definition is committed into the address via `objectHash.getChash160`, but the *definition itself* — including the plaintext hash target — is routinely transmitted between correspondent/paired devices well before the secret is ever revealed on-chain, for example when a shared address is proposed: [3](#0-2) 

Because SHA-256 is a fast, unsalted, single-iteration hash with no work-factor (unlike bcrypt/scrypt/Argon2), anyone who possesses this cleartext digest — a paired device, a cosigner, or anyone the definition was forwarded to — can perform unlimited offline guesses against the digest. If the user or contract designer picked a low-entropy secret (a short passphrase, PIN, word, or predictable string, which the protocol permits since `MAX_AUTHENTIFIER_LENGTH` only bounds the authentifier and there is no minimum-entropy enforcement) [4](#0-3) , the secret can be recovered entirely offline, well before the legitimate holder uses it to sign/spend. This is exactly the bug class in the Ente advisory: a cleartext, low-work-factor verifier of a possibly low-entropy secret enables offline guessing.

### Impact Explanation
Recovering the pre-image of a `hash` authentifier lets an attacker satisfy that branch of the address's spending/authorization condition. Where `hash` is combined with `and`/`or` in a definition (e.g., `['and', [['sig',...], ['hash',...]]]` or as a stand-alone escrow/HTLC-style branch), successful offline recovery of a low-entropy secret can allow an attacker to co-sign or satisfy the condition ahead of the intended party, leading to unauthorized spending or theft of funds locked behind that authentifier, and it also destroys the confidentiality assumption relied on by any protocol (shared addresses, prosaic/arbiter contracts, escrow schemes) that uses `hash` as a secret-knowledge proof between devices.

### Likelihood Explanation
The attack is fully offline and requires only possession of the address definition (i.e., the cleartext `hash` value), which is exchanged in normal, unprivileged flows such as shared-address proposals between paired devices — no privileged or malicious-node access is required. Whether the attack succeeds in practice depends entirely on the entropy of the secret chosen by the user/contract designer, since the protocol does not enforce or encourage high-entropy secrets, nor does it use a memory-hard/slow hash for this authentifier type.

### Recommendation
- Do not use a bare, unsalted SHA-256 digest as a standalone secret-knowledge authentifier for user-supplied or potentially low-entropy secrets.
- If a `hash`-based authentifier must be supported, require it be combined with a high-entropy, randomly generated value (not a user-chosen passphrase), or apply a memory-hard KDF (e.g. scrypt/Argon2) with a per-address salt before hashing, and document/enforce a minimum entropy for any secret used in this way.
- Avoid transmitting the plaintext `hash` target to parties who do not need to verify it prior to the secret being consumed, and consider commit-then-reveal schemes where the hash target itself is only disclosed together with, or immediately before, the authorized spend.

### Proof of Concept
1. A user (or wallet feature) creates a shared/definition address using `['hash', {hash: sha256("1234")}]` as (part of) the spending condition, intending "1234" to be revealed later as proof-of-knowledge.
2. The definition (containing the plaintext `hash` value) is sent to a cosigner/correspondent device via `handleNewSharedAddress` [5](#0-4)  before "1234" is ever posted on-chain.
3. The correspondent (or anyone else who obtains the definition) iterates over a dictionary of low-entropy candidate secrets, computing `crypto.createHash("sha256").update(candidate).digest("base64")` for each and comparing to the stored hash — exactly the comparison performed in `definition.js` line 763 — and recovers "1234" offline in negligible time.
4. The attacker now can supply the correct authentifier for the `hash` branch, potentially before the legitimate secret holder ever uses it, satisfying that portion of the spending condition. [2](#0-1)

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

**File:** wallet_defined_by_addresses.js (L377-401)
```javascript
// {address: "BASE32", definition: [...], signers: {...}}
function handleNewSharedAddress(body, callbacks){
	if (!ValidationUtils.isArrayOfLength(body.definition, 2))
		return callbacks.ifError("invalid definition");
	if (typeof body.signers !== "object" || Object.keys(body.signers).length === 0)
		return callbacks.ifError("invalid signers");
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: " + JSON.stringify(signerInfo.address));
	}
	const assocDefinitionAddresses = extractAddressPathsFromDefinition(body.definition);
	for (let signing_path in body.signers) {
		const signerInfo = body.signers[signing_path];
		if (assocDefinitionAddresses[signing_path] !== signerInfo.address)
			return callbacks.ifError("signer address at path " + signing_path + " doesn't match definition");
	}
```

**File:** constants.js (L151-151)
```javascript
exports.TEXTCOIN_ASSET_CLAIM_MESSAGE_FEE = 201 + 98;
```
