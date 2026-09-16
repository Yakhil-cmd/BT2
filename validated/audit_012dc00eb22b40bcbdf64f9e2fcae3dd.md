## Title
Asset `spender_attested` whitelist restriction is permanent and cannot be disabled by the definer, permanently freezing spendable output addresses if attestors become unavailable - (File: validation.js)

### Summary
An asset issuer (an unprivileged actor who can post an `asset` message) can define a token with `spender_attested: true`, which forces every future holder/output address of that asset to be attested by one of the listed attestor addresses before it can be spent or received. The definer can subsequently update *who* the attestors are via an `asset_attestors` message, but there is no mechanism anywhere in the protocol to turn the `spender_attested` requirement itself off. Once set, it is permanent for the life of the asset, exactly mirroring the reported bug class ("no way to remove whitelist restriction").

### Finding Description
The asset definition is validated once, at creation, in `validateAssetDefinition` in `validation.js`, which requires `spender_attested` to be an immutable boolean stored in the `assets` table [1](#0-0) . There is no message type that can flip this flag from `true` to `false` for an existing asset — the only related message, `asset_attestors`, is restricted to updating the attestor *list*, and explicitly rejects the update if the asset does not require attestors, but there's no inverse path to disable the requirement: [2](#0-1) 

`checkAttestorList` additionally enforces that the attestor list can never be emptied — it must always be a non-empty array — so "whitelisting via attestation" can never be relaxed to "no attestation required": [3](#0-2) 

Every subsequent payment of this asset is gated by the whitelist check for both authors (senders) and all output addresses (including change), with no bypass: [4](#0-3) [5](#0-4) 

The same permanent restriction is enforced independently in the wallet composer paths for divisible and indivisible assets: [6](#0-5) [7](#0-6) 

### Impact Explanation
If the entire attestor set for a `spender_attested` asset becomes unable or unwilling to attest addresses (e.g., attestor keys are lost, attestors go offline, or attestors simply refuse to attest new addresses), then no new address can ever satisfy `arrAttestedAddresses`, and every future transfer of that asset — including sending change back to the sender — fails validation. All coins of this asset become permanently unspendable/frozen for any address that isn't already on the attested list, and even already-attested addresses can never onboard new counterparties. The definer has no on-chain mechanism to relax or remove this restriction, unlike other asset properties, resulting in a class of freezing risk that is a direct architectural analog to "no way to remove whitelist restriction" in the reported bug.

### Likelihood Explanation
Reaching this state requires nothing beyond following normal, unprivileged token-issuance conventions: any user can issue an asset with `spender_attested: true`. Real-world causes of attestor unavailability (attestor operator ceasing operations, losing keys, or being an AA/service that simply stops responding) are plausible over the lifetime of a compliance-oriented token, making this a reasonably likely operational trap rather than a purely theoretical one, consistent with a Medium likelihood rating.

### Recommendation
Add an explicit, definer-authorized mechanism to disable the `spender_attested` requirement for an already-issued asset (analogous to the suggested `whitelistEnabled` flag pattern), for example by allowing an `asset_attestors` (or new) message from the definer to set `spender_attested` to `false`, with validation updated in `validateAttestorListUpdate` and `validatePaymentInputsAndOutputs`/`validatePayment` to honor the change going forward, while preserving existing history integrity.

### Proof of Concept
1. Issuer posts an `asset` message with `spender_attested: true` and an initial attestor list, per `validateAssetDefinition` (`validation.js:2725-2755`).
2. Token is distributed and used normally, gated by `filterAttestedAddresses` checks in `validatePayment`/`validatePaymentInputsAndOutputs`.
3. All attestor addresses on the list become unreachable/non-functional (their private keys are lost or the attestor entity stops attesting new addresses).
4. Any holder who needs to send or receive to a not-yet-attested address (including sending change to a new one-time change address) is permanently blocked by `"some output addresses are not attested"` / `"owner address is not attested"` checks (`validation.js:2432-2433`, `2506-2507`, `2637-2638`), with no on-chain message available to disable `spender_attested` and restore transferability.

### Citations

**File:** validation.js (L2115-2122)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
		}
```

**File:** validation.js (L2630-2641)
```javascript
				async.series([
					function(cb){
						if (!objAsset.spender_attested)
							return cb();
						storage.filterAttestedAddresses(
							conn, objAsset, objValidationState.last_ball_mci, arrOutputAddresses, 
							function(arrAttestedOutputAddresses){
								if (arrAttestedOutputAddresses.length !== arrOutputAddresses.length)
									return cb("some output addresses are not attested");
								cb();
							}
						);
```

**File:** validation.js (L2725-2733)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");
```

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

**File:** divisible_asset.js (L245-250)
```javascript
						if (!objAsset.is_transferrable && params.to_address !== objAsset.definer_address && arrAssetPayingAddresses.indexOf(objAsset.definer_address) === -1)
							return cb("the asset is not transferrable and definer not found on either side of the deal");
						if (objAsset.cosigned_by_definer && arrPayingAddresses.concat(params.signing_addresses || []).indexOf(objAsset.definer_address) === -1)
							return cb("the asset must be cosigned by definer");
						if (!conf.bLight && objAsset.spender_attested && objAsset.arrAttestedAddresses.length === 0)
							return cb("none of the authors is attested");
```

**File:** indivisible_asset.js (L752-757)
```javascript
				if (!objAsset.is_transferrable && params.to_address !== objAsset.definer_address && arrAssetPayingAddresses.indexOf(objAsset.definer_address) === -1)
					return onDone("the asset is not transferrable and definer not found on either side of the deal");
				if (objAsset.cosigned_by_definer && arrPayingAddresses.concat(params.signing_addresses || []).indexOf(objAsset.definer_address) === -1)
					return onDone("the asset must be cosigned by definer");
				if (objAsset.spender_attested && objAsset.arrAttestedAddresses.length === 0)
					return onDone("none of the authors is attested");
```
