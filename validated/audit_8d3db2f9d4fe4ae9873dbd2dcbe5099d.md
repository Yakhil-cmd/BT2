Based on my investigation, `ocore` does contain an on-chain analog of the exact bug class described (a public "reveal" of a secret that anyone can then front-run), via the `hash` authentifier type used in address definitions.

### Title
Hash-authentifier ("commit-reveal") branches in address definitions allow anyone to front-run the revealed secret and steal the funds - (File: definition.js)

### Summary
`ocore` lets an address be defined with a `["hash", {algo, hash}]` leaf, which is satisfied by anyone who can produce a string whose SHA-256 matches the stored hash — no signature is required. Definitions built as `["or", [["address", A], ["hash", {hash:H}]]]` are the standard way to build "claim-with-secret"/atomic-swap style shared addresses in this codebase, as shown by `wallet_defined_by_addresses.js` treating the `hash` op specially (`result[path] = 'secret'`) when extracting signer paths for shared addresses.

### Finding Description
When a party spends funds from such an address, they must place the raw secret (the preimage) into the unit's `authentifiers` at the corresponding path so that `validateAuthentifiers` can verify it against the SHA-256 hash embedded in the definition: [1](#0-0) 

Because units are broadcast to the P2P network as soon as they are composed/signed — before they become stable and irrevocably confirmed — the secret becomes publicly visible to anyone observing the unstable/pending unit the instant it is revealed. Any of the "hash" op only checks that the SHA-256 of the revealed string matches; it grants spending authority to whoever presents the secret, with no binding to a specific address, pubkey, or the original revealer's unit: [2](#0-1) 

This is functionally identical to the RLN commit-reveal bug: revealing a secret on-chain (the "reveal" step) exposes it to anyone monitoring pending transactions, who can then immediately construct and post their own competing unit that satisfies the same `hash` condition — routing the funds to an address of their choosing — and get it included/stabilized ahead of (or instead of) the original revealer's unit. The `extractAddressPathsFromDefinition` helper explicitly acknowledges `hash` as a distinct, secret-based signing mechanism separate from address-bound signatures: [3](#0-2) 

There is no mechanism in `definition.js`/`validation.js` that ties a `hash` authentifier reveal to a specific claimant address, a nonce that invalidates competing spends, or any precedence/locking rule protecting the original revealer once the secret becomes visible in the DAG.

### Impact Explanation
Any AA, payment channel, atomic-swap, or custom multisig-with-secret contract in `ocore` that relies on a `["hash", ...]` branch to gate spending is vulnerable: an unprivileged network observer who sees the secret revealed in a pending/unstable unit can immediately compose and broadcast their own transaction reusing that secret to redirect the locked funds to themselves. This results in concrete unauthorized spending/theft of the value locked behind the hash branch, since whoever's competing unit gets stabilized on the main chain wins the funds regardless of who revealed the secret first in wall-clock time.

### Likelihood Explanation
Any unprivileged node connected to the network can reach this: it only requires watching newly gossiped joints (a normal wallet/light-client operation) for a `hash` authentifier value and racing a new unit against the original. No special node privileges, hub control, or private key leakage of the honest party is needed — the "leak" is by design, since the secret is deliberately embedded in the unit's `authentifiers` payload to prove authorization. This is a straightforward mempool/frontrunning race analogous to public preimage reveals in HTLC schemes on other chains.

### Recommendation
- Avoid using bare `["hash", ...]` authorization for value transfer without also binding the claim to the original revealer's address/signature (e.g., require `["and", [["address", claimant], ["hash", {...}]]]` where `claimant` is fixed at definition time, not chosen freely by whoever reveals the secret).
- For patterns that genuinely need "first person to reveal wins" semantics (as in atomic swaps), document and enforce that the `outputs` are hard-coded in the definition (as already partially done in `arbiter_contract.js`'s `has output` conditions) so that revealing the secret cannot be repurposed to redirect funds to an arbitrary address.
- Consider adding a linting/validation warning when a `hash` op is combined in an `or` branch without a fixed destination address, since this pattern is inherently frontrunnable.

### Proof of Concept
1. Alice and Bob create a shared address with definition `["or", [["address", Alice], ["hash", {hash: H}]]]`, where `H = sha256(secret)`, intended so that whoever knows `secret` (e.g., the counterparty of an atomic swap) can claim the funds by putting `secret` in the `hash` authentifier path.
2. Bob, who legitimately knows `secret`, composes and broadcasts a unit spending the shared address to his own address, placing `secret` in the authentifier at the `hash` path (per `validateAuthentifiers` case `'hash'`, `definition.js:756-772`).
3. Mallory, monitoring gossiped/unstable joints on the network, extracts `secret` from Bob's pending (not-yet-stable) unit's `authentifiers`.
4. Mallory immediately composes her own unit spending the same shared address (before Bob's unit is included on the main chain / stabilizes), reusing `secret` at the `hash` authentifier path, but directing the outputs to her own address.
5. Whichever unit gets included and becomes part of the "good" sequence spends the output; Mallory can craft hers to propagate faster or exploit witness/parent selection to win the race, resulting in loss of Bob's expected funds.

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

**File:** wallet_defined_by_addresses.js (L362-367)
```javascript
			case 'address':
				result[path] = args;
				break;
			case 'hash':
				result[path] = 'secret';
				break;
```
