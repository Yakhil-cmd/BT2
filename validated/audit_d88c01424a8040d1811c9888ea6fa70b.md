I have sufficient evidence to write up the finding.

### Title
Timing side-channel in `hash` authentifier comparison allows preimage brute-forcing to unlock hash-locked address definitions - (File: `definition.js`)

### Summary
The `hash` op inside `validateAuthentifiers()` in `definition.js` verifies a hash-lock authentifier by computing SHA-256 of the attacker-supplied preimage and comparing it to the address-definition-committed hash using JavaScript's native `===` string equality operator on base64-encoded digests. `===` on strings is a byte-by-byte, early-exit comparison, not constant-time, mirroring the exact bug class in RELATE's `check_sign_in_key()` (CVE-2026-41588), where a non-constant-time comparison of a secret token allowed remote timing-based recovery.

### Finding Description
`definition.js` `validateAuthentifiers()` implements the `hash` authentifier as: [1](#0-0) 

```
case 'hash':
    if (!assocAuthentifiers[path] || typeof assocAuthentifiers[path] !== 'string')
        return cb2(false);
    ...
    var res = (args.hash === crypto.createHash("sha256").update(assocAuthentifiers[path], "utf8").digest("base64"));
```

`args.hash` is the committed digest embedded in an address's public definition (e.g. an atomic-swap/hash-timelock style spending condition where the definer commits to `['hash', {hash: 'BASE64_DIGEST'}]` and later reveals the preimage in `assocAuthentifiers[path]` to unlock funds). Any unprivileged party who wants to spend from such an address (or unlock an AA/asset condition using the same authentifier mechanism) must supply the preimage as an authentifier on a posted unit; a full/witness node then performs this comparison during standard unit validation, which is directly reachable by any unit poster.

The comparison `args.hash === computed_digest` uses JS's default string equality, which short-circuits on the first differing character. Repeatedly submitting candidate preimages (or observing validation/rejection timing across many broadcasted probe units to a target node) leaks incremental information about how many leading bytes of the computed digest match the target, in the same way `==`/`===` comparisons of secrets are the canonical timing side-channel bug class illustrated by CVE-2026-41588's `check_sign_in_key()`.

This is architecturally identical to the RELATE bug class: a secret-dependent branch decision (`cb2(res)` → unit valid/invalid) is derived from a non-constant-time string comparison, and the outcome (validation success/failure, propagation, or measurable node processing time) is externally observable to an unprivileged actor who fully controls the guessed input.

### Impact Explanation
If exploitable with sufficient precision, this allows an attacker to progressively recover the preimage protecting a hash-locked spending condition without having been given it, and then move funds out of that address — i.e., unauthorized spending from a hash-locked address/AA condition that relies on `['hash', ...]` for authorization. This matches the "concrete unauthorized spending" impact bar.

### Likelihood Explanation
Exploitability is constrained by network jitter and the coarse-grained nature of unit validation (full digest comparison of a 44-byte base64 string, executed once per candidate unit, with validation results observed indirectly through propagation/acceptance rather than a fine-grained RPC timer). This makes practical, remote exploitation significantly harder than a typical local HTTP-request timing oracle (such as RELATE's login flow), and the number of samples needed to reliably distinguish sub-microsecond timing differences over the P2P/hub network layer is large. It is a genuine architectural bug-class match, but real-world exploitability is speculative and non-trivial to demonstrate compared to the original CVE.

### Recommendation
Replace the `===` comparison with a constant-time comparison, e.g. Node's `crypto.timingSafeEqual()` on fixed-length buffers (after decoding both operands from base64), for the `hash` authentifier check in `definition.js`, and audit other identical `===` secret-comparisons in the codebase (e.g., in `wallet_defined_by_addresses.js` / `wallet_defined_by_keys.js`, which contain equivalent `case 'hash':` blocks) for the same pattern.

### Proof of Concept
Conceptual (no working remote timing exploit demonstrated, consistent with the nature of timing side-channel classes):
1. Attacker identifies an address whose definition contains `['hash', {hash: 'TARGET_DIGEST'}]` guarding spendable funds (e.g., an atomic-swap contract).
2. Attacker crafts many candidate units, each with a different guessed preimage string as the `hash` authentifier at the relevant path, and submits them to a witness/full node for validation.
3. Attacker measures per-unit validation latency (or observable side effects of the `args.hash === computed_digest` branch in `definition.js:763`) across repeated trials to statistically infer which candidate preimages produce longer-matching digest prefixes.
4. Iterating this process converges on the correct preimage without the attacker ever being given it, after which the attacker posts a spending unit using the recovered preimage to move funds. [1](#0-0)

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
