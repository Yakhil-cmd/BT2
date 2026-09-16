Based on my investigation, I found a genuine analog to the Tomcat "incomplete logged effective web.xml" bug class in `wallet_defined_by_addresses.js`.

### Title
Incomplete traversal in `extractAddressPathsFromDefinition` omits `not` and other ops, allowing shared-address signer/definition mismatch to bypass validation - (File: `ocore--025/wallet_defined_by_addresses.js`)

### Summary
`extractAddressPathsFromDefinition` [1](#0-0)  is a hand-rolled definition-tree walker that recomputes which paths are "address"-type leaves of a proposed shared-address definition, mirroring the exhaustive `op` switch used by the real validator in `definition.js`. Its `switch(op)` only recognizes `or`, `and`, `r of set`, `weighted and`, `address`, `hash`, and `in merkle`. It silently returns nothing for any other valid definition op — most notably `not`, `cosigned by`, `definition template`, `in data feed`, `attested`, `seen*`, `mci/age/timestamp`, `sum`, `has*`, and `formula`, all of which are legitimate branches in `definition.js`'s `evaluate()` [2](#0-1) [3](#0-2) . In particular `not` wraps an inner sub-expression (`evaluate(args, path, true, cb)` in the real validator) but `extractAddressPathsFromDefinition`'s `traverse` has no `case 'not'`, so any `["address", ...]` leaf nested inside a `["not", [...]]` branch (or inside any other unhandled op) is never added to the returned `result` map.

### Finding Description
`handleNewSharedAddress` uses this incomplete extraction to cross-check the `signers` map supplied by a shared-address creator/AA definition author against the actual `["address", ...]` leaves of the proposed multi-member definition: [4](#0-3) 
The check only enforces two invariants over `assocDefinitionAddresses` (the *extracted* set, not the *true* set of address leaves):
1. every signer entry must match the extracted address at that path,
2. every extracted address path must have a matching signer.

Because the extraction is control-flow-incomplete (same bug class as the Tomcat report: paths under certain evaluate branches are dropped from the derived view used for a security decision), an attacker who crafts a shared-address definition containing an `["address", ATTACKER_ADDR]` leaf inside a `["not", ...]` (or `"cosigned by"`/`"definition template"`/etc.) sub-branch can have that address leaf go completely unnoticed by `assocDefinitionAddresses`. The definition itself is still accepted by the real evaluator in `definition.js`, so the resulting shared address's spending logic legitimately includes the hidden address branch, but the wallet-side member/cosigner bookkeeping (`signers`, `shared_address_signing_paths`) never records or verifies a legitimate signer for that hidden branch, and no "no signer for definition address" error is raised for it.

### Impact Explanation
This is reachable by any unprivileged peer proposing a shared/multisig address to a wallet counterparty (the "device message handling" surface explicitly in scope) via the `new_shared_address` / `create_new_shared_address` device-message flow that calls `handleNewSharedAddress`. Because the peer controls `body.definition` and `body.signers` end to end, they can construct a definition whose true logical structure (once accepted by the real evaluator) permits spending under a hidden `not`-wrapped address condition that was never surfaced to the local wallet's cosigner/signing-path bookkeeping. This could mislead a cosigning wallet into believing the address's spending conditions are fully mapped by the recorded signers when a bypass or alternate signer branch was hidden, potentially leading to fund loss/incorrect spending authorization within that shared address — a concrete unauthorized-spending-adjacent risk.

### Likelihood Explanation
Medium. The exploitation is straightforward for a peer capable of composing an oscript definition with a `not`/`cosigned by` branch containing an address leaf, and the vulnerable code path (`handleNewSharedAddress`) is triggered automatically whenever a shared-address creation offer is received. No special privilege or race condition is required, only crafting the definition JSON.

### Recommendation
Rewrite `extractAddressPathsFromDefinition`'s `traverse` to mirror the exhaustive operator list in `definition.js`'s `evaluate()` (including `not`, `cosigned by`, `definition template`, `in data feed`, `attested`, `seen*`, `has*`, `sum`, `mci/age/timestamp`, `formula`), or better, derive the address/signer requirement checks directly from the real `Definition.validateDefinition`/`evaluate` traversal rather than maintaining a duplicated, drift-prone traversal.

### Proof of Concept
1. Attacker crafts `arrDefinition = ["and", [ ["address", "LEGIT_COSIGNER"], ["not", ["address", "ATTACKER_ADDR"]] ]]` (or another unhandled-op wrapper).
2. Attacker sends `create_new_shared_address`/forwards `new_shared_address` with `signers` only covering the `LEGIT_COSIGNER` path.
3. `extractAddressPathsFromDefinition` [1](#0-0)  returns only `{ "r.0": "LEGIT_COSIGNER" }`, omitting the `not`-wrapped path.
4. `handleNewSharedAddress`'s consistency checks pass [4](#0-3)  and `addNewSharedAddress` stores the address, even though the real definition (accepted separately by `Definition.validateDefinition` at [5](#0-4) ) contains an unrecorded/unverified spending branch.

**Note on confidence:** I could not fully trace how the missing branch would concretely be later exploited into an actual signed spend (e.g., whether `findAddress`/signing-request logic would refuse to use an untracked path) since that depends on further wallet.js signing-flow code not fully covered by the index. This should be verified by a Devin session with full file access before treating the impact as certain double-spend/fund-loss rather than a bookkeeping-integrity gap.

### Citations

**File:** wallet_defined_by_addresses.js (L339-375)
```javascript
function extractAddressPathsFromDefinition(arrDefinition) {
	var result = {};
	function traverse(arr, path) {
		if (!Array.isArray(arr) || arr.length < 2) return;
		var op = arr[0];
		var args = arr[1];
		switch (op) {
			case 'or':
			case 'and':
				if (Array.isArray(args))
					for (var i = 0; i < args.length; i++)
						traverse(args[i], path + '.' + i);
				break;
			case 'r of set':
				if (args && Array.isArray(args.set))
					for (var i = 0; i < args.set.length; i++)
						traverse(args.set[i], path + '.' + i);
				break;
			case 'weighted and':
				if (args && Array.isArray(args.set))
					for (var i = 0; i < args.set.length; i++)
						traverse(args.set[i].value, path + '.' + i);
				break;
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
	}
	traverse(arrDefinition, 'r');
	return result;
}
```

**File:** wallet_defined_by_addresses.js (L396-405)
```javascript
	const assocDefinitionAddresses = extractAddressPathsFromDefinition(body.definition);
	for (let signing_path in body.signers) {
		const signerInfo = body.signers[signing_path];
		if (assocDefinitionAddresses[signing_path] !== signerInfo.address)
			return callbacks.ifError("signer address at path " + signing_path + " doesn't match definition");
	}
	for (let def_path in assocDefinitionAddresses) {
		if (!body.signers[def_path])
			return callbacks.ifError("no signer for definition address at path " + def_path);
	}
```

**File:** wallet_defined_by_addresses.js (L409-412)
```javascript
		validateAddressDefinition(body.definition, function(err){
			if (err)
				return callbacks.ifError(err);
			addNewSharedAddress(body.address, body.definition, body.signers, body.forwarded, callbacks.ifOk);
```

**File:** definition.js (L118-118)
```javascript
		switch(op){
```

**File:** definition.js (L397-399)
```javascript
			case 'not':
				evaluate(args, path, true, cb);
				break;
```
