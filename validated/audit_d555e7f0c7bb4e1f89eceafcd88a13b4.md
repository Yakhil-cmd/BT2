### Title
Asset definer can unilaterally replace the entire "trusted attestor" list at any time, retroactively re-authorizing colluding addresses - (File: validation.js)

### Summary
The reported bug class centers on a single privileged actor (`Owner`) being able to unilaterally add new "trusted" logic/contracts that other users implicitly rely on, with no safeguards against abuse. The closest reachable analog in ocore is the `asset_attestors` message: the definer (issuer) of a `spender_attested` asset can publish a brand-new list of "trusted attestors" at any time after the asset already has holders, and this list is trusted unconditionally by every node that validates payments and issuance of that asset.

### Finding Description
When an asset is created with `spender_attested=1`, spending and issuing that asset requires the author to be included in `arrAttestedAddresses`, which is derived from whatever `attestor_address` set is currently on file for that asset [1](#0-0) . The attestor list itself is *not* fixed at asset-definition time — it is a separate, mutable message (`asset_attestors`) that the definer can post whenever they want: [2](#0-1) 

The only checks performed on a new attestor list are structural (non-empty, valid addresses, sorted, under `MAX_ATTESTORS_PER_ASSET`) — there is no restriction preventing the definer from completely replacing the list, adding self-controlled addresses, or doing so long after third parties have already acquired and are holding the asset in reliance on the previously published attestor set: [3](#0-2) 

At payment-validation time, the current attestor list (whatever it happens to be as of `last_ball_mci`) is loaded and used to decide who is allowed to spend/issue the asset, with no historical pinning to the attestor set that existed when a holder acquired the coins: [4](#0-3) 

Because "attestation" itself is permissionless (`attested_address` can even attest itself — "it is also ok to attest oneself") [5](#0-4) , a definer can add an address they control as an attestor, then have that address self-attest, and instantly become (or re-become) an authorized spender/issuer under the compliance gate that other holders assumed was controlled by vetted, independent attestors — exactly the "administrator silently adding a new trusted entity to a trusted list" pattern from the source report, here reachable by an ordinary asset issuer rather than a privileged contract owner.

### Impact Explanation
Holders and counterparties of a `spender_attested` asset (e.g. a compliance/KYC-gated token) rely on the attestor list to guarantee that only vetted addresses can spend or issue the asset. Because the definer can swap this list at will and without any timelock or holder consent, the definer can:
- Retroactively grant spending/issuing rights to colluding addresses that were never vetted, undermining the asset's compliance guarantees for every existing holder.
- Combine this with `issued_by_definer_only=0` and `spender_attested=1` assets to funnel newly "attested" collaborator addresses into moving previously issued supply in ways not anticipated by holders who transacted based on the original attestor set.

This matches the "asset issuance and transfer conditions" and "trusted functionality can be modified by a privileged actor" impact class called out in the rules — it does not require a malicious node/hub, only a single asset-issuer-authored unit.

### Likelihood Explanation
This requires only posting a single, valid, single-authored `asset_attestors` unit — a normal, always-available action for any asset's definer. No special timing, race condition, or additional compromise is needed, making this trivially and repeatedly triggerable by the definer at any point in the asset's lifetime.

### Recommendation
Consider requiring attestor-list changes to be append-only (attestors can be added but not silently removed/replaced) or requiring some grace/notice period (e.g., only effective after N stable MCI) so holders and counterparties can react before a definer alters who is authorized to move the asset. Alternatively, document explicitly (and make discoverable to wallets/exchanges) that the attestor list is definer-controlled and can change at any time, so downstream tooling can warn users rather than silently trusting a mutable, definer-controlled list.

### Proof of Concept
1. Definer `D` issues asset `A` with `spender_attested=1`, `issued_by_definer_only=0`, and an initial `asset_attestors` message listing reputable attestor addresses `[X, Y]`.
2. Holders acquire and hold `A`, relying on `X`/`Y` as the vetting attestors.
3. At any later stable MCI, `D` posts a new single-authored `asset_attestors` unit for asset `A` listing only `[Z]`, where `Z` is an address controlled by `D`/an accomplice (`validateAttestorListUpdate` only checks `objUnit.authors[0].address === objAsset.definer_address`) [6](#0-5) .
4. `D` posts an `attestation` message where `Z` attests itself (`address: Z`) — permitted since self-attestation is allowed [7](#0-6) .
5. `Z` is now an "attested" address and can spend/issue asset `A` under the compliance gate, even though it was never independently vetted, and none of the existing holders consented to or were notified of the attestor-list change.

### Citations

**File:** validation.js (L2011-2024)
```javascript
		case "attestation":
			if (objUnit.authors.length !== 1)
				return callback("attestation must be single-authored");
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["address", "profile"]))
				return callback("unknown fields in "+objMessage.app);
			if (!isValidAddress(payload.address))
				return callback("attesting an invalid address");
			if (!isNonemptyObject(payload.profile))
				return callback("attested profile must be non empty object");
			// it is ok if the address has never been used yet
			// it is also ok to attest oneself
			return callback();
```

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

**File:** storage.js (L1977-1992)
```javascript
function loadAssetWithListOfAttestedAuthors(conn, asset, last_ball_mci, arrAuthorAddresses, bAcceptUnconfirmedAA, handleAsset){
	if (arguments.length === 5) {
		handleAsset = bAcceptUnconfirmedAA;
		bAcceptUnconfirmedAA = false;
	}
	readAsset(conn, asset, last_ball_mci, bAcceptUnconfirmedAA, function(err, objAsset){
		if (err)
			return handleAsset(err);
		if (!objAsset.spender_attested)
			return handleAsset(null, objAsset);
		filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAuthorAddresses, function(arrAttestedAddresses){
			objAsset.arrAttestedAddresses = arrAttestedAddresses;
			handleAsset(null, objAsset);
		});
	});
}
```
