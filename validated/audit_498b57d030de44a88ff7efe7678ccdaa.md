### Title
Asset Attestor List Can Be Redefined by Definer, Freezing Funds of Already-Attested Holders - (File: validation.js)

### Summary
For `spender_attested` assets, the asset definer can unilaterally replace the trusted-attestor list at any time via an `attestor_list` message, with no on-chain check of whether existing coin holders were relying on the previous attestor set. This mirrors the `setRarityWeights()` pattern: a privileged party mutates a configuration array that downstream validation logic consults by content/identity, and holders who legitimately obtained state (attestation / staked position) under the old configuration can be left unable to satisfy the new configuration, freezing their funds.

### Finding Description
`spender_attested` assets require that whoever spends the asset be attested by one of the trusted attestors published for that asset. The initial attestor list is set in the `asset` definition message, and can later be replaced wholesale by the definer through `validateAttestorListUpdate`: [1](#0-0) 

The only checks performed are that the asset requires attestors, that the sender is the definer, and that the new list passes `checkAttestorList` (valid addresses, sorted, under `MAX_ATTESTORS_PER_ASSET`): [2](#0-1) 

There is no check on whether current holders of the asset (who received coins after being attested by the *old* attestor set) are still able to prove attestation under the *new* set. Just like `setRarityWeights()` in the reference report, the definer can submit an attestor-list replacement that is unrelated to the intent of any specific holder's already-completed attestation, and — because validation of "which addresses are currently trusted" is evaluated using the live `asset_attestors` table at spend time — a holder whose attestor is dropped from the list effectively loses the ability to spend the asset they already legitimately hold, with no recourse and no on-chain safeguard.

This is structurally the same flaw as the report: a mutable, privileged-controlled list is consulted by downstream logic (spend/reward eligibility) without any invariant preventing removal of entries that are still "in use" by existing state (staked NFTs / already-attested asset holders).

### Impact Explanation
If confirmed to gate spend eligibility for `spender_attested` assets, this allows the asset definer to freeze previously-issued/held coins for any holder whose attestation was granted under a now-removed attestor, without the holder's consent and without any transaction of their own. This is a fund-freezing issue reachable by the definer role acting on assets held by ordinary, unprivileged counterparties — comparable in class (though narrower in blast radius) to the "High" impact/"Low" likelihood rating of the original finding.

### Likelihood Explanation
Likelihood is Low: this requires the asset's definer to deliberately (or carelessly) publish a new attestor list, and it only affects holders whose spend eligibility depends on the specific attestor(s) being removed. Note: I was unable to fully verify, purely from static reading, whether spend-time validation of `spender_attested` assets re-checks attestation against the *current* `asset_attestors` table contents at the moment of spend versus only enforcing this off-chain (e.g., wallet-level warning) — the `'attested'` opcode in `definition.js` evaluates a literal attestor array embedded in the condition itself rather than dynamically reading `asset_attestors`, so the precise on-chain enforcement path for `spender_attested` deserves confirmation before treating this as a fully proven, on-chain-enforced freeze.

### Recommendation
If `spender_attested` enforcement does consult the live attestor list at spend time, add validation preventing removal of an attestor if doing so would leave existing, already-attested unspent outputs without any valid attestor path, or introduce a way for holders to spend coins attested under a prior, still-recognized attestor set (e.g., a grace/versioned attestor list rather than outright replacement).

### Proof of Concept
Not applicable — this is a code-level pattern analysis. A conceptual PoC: definer publishes asset with `spender_attested: true`, attestor A. Attestor A attests holder H, who receives coins. Definer then submits an `attestor_list` update removing A. If spend-time checks require current attestor membership, H can no longer produce a valid attestation proof and the coins become unspendable, despite H having done nothing wrong.

### Citations

**File:** validation.js (L2829-2848)
```javascript
function validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("attestor list must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("attestor update must be a non-empty object");
	if (hasFieldsExcept(payload, ['asset', 'attestors']))
		return callback("foreign fields in attestor list update");
	storage.readAsset(conn, payload.asset, objValidationState.last_ball_mci, false, function(err, objAsset){
		if (err)
			return callback(err);
		if (!objAsset.spender_attested)
			return callback("this asset does not require attestors");
		if (objUnit.authors[0].address !== objAsset.definer_address)
			return callback("attestor list can be edited only by definer");
		err = checkAttestorList(payload.attestors);
		if (err)
			return callback(err);
		callback();
	});
}
```

**File:** validation.js (L2850-2864)
```javascript
function checkAttestorList(arrAttestors){
	if (!isNonemptyArray(arrAttestors))
		return "attestors not defined";
	if (arrAttestors.length > constants.MAX_ATTESTORS_PER_ASSET)
		return "too many attestors";
	var prev="";
	for (var i=0; i<arrAttestors.length; i++){
		if (!isValidAddress(arrAttestors[i]))
			return "invalid attestor address: "+JSON.stringify(arrAttestors[i]);
		if (arrAttestors[i] <= prev)
			return "attestors not sorted";
		prev = arrAttestors[i];
	}
	return null;
}
```
