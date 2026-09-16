### Title
Asset definer/AA can rewrite the trusted-attestor list of a `spender_attested` asset at any time after issuance, freezing or de-trusting existing holders - (File: validation.js)

### Summary
Ocore's analog of Sound Protocol's "editable supply/parameter after minting begins" flaw is the `asset_attestors` update mechanism for `spender_attested` assets. An asset's `spender_attested` flag conditions every future payment/issue of the asset on the payer/issuer being on the attestor-approved list. Unlike `editionMaxMintableUpper`, which is frozen once minting starts, the list of trusted attestors for an already-circulating asset can be replaced by the definer (a wallet address or an AA) at any later point, with no restriction tied to how much of the asset has already been issued or transferred to third parties.

### Finding Description
When an asset is defined with `spender_attested: true`, every payment or issue input from that asset must originate from an address in the *current* attestor-approved list, checked at validation time: [1](#0-0) 

The list of attestors is not fixed at asset-definition time; it can be updated later via a separate `asset_attestors` message, validated by `validateAttestorListUpdate`: [2](#0-1) 

The only checks are: single-authored message, `spender_attested` is set on the asset, and the sender is the asset's `definer_address`. There is **no check analogous to `_totalMinted() == 0`** — no restriction based on whether the asset has already been issued, transferred, or is held by third parties. `checkAttestorList` only verifies the new list is well-formed (nonempty, sorted, valid addresses): [3](#0-2) 

At read time, `readAsset` always resolves to the *latest* attestor list unit stable before the checked mci, meaning any subsequent payment of the asset is judged against whichever list the definer has most recently published, not the list disclosed when the asset was created or when a holder acquired it: [4](#0-3) 

Critically, this mechanism is explicitly available to Autonomous Agents as well — an AA acting as an asset's definer can emit an `asset_attestors` message from within `handleTrigger` at any point in its lifetime (including long after the asset has been issued and distributed to users), exactly as demonstrated in the test suite: [5](#0-4) [6](#0-5) 

This is the direct structural analog of the reported bug: just as `setSAM()` let a Sound edition owner turn on a hidden supply-inflation mechanism after users had already committed to mint under different disclosed rules, `asset_attestors` lets an ocore asset definer (regular address or AA) silently rewrite the access-control gate of an asset that is already circulating, at will, with no cutoff based on prior activity.

### Impact Explanation
Once holders acquire a `spender_attested` asset, they implicitly trust that spending remains gated by the attestor set that was in force when they acquired it (or by attestors they independently vetted, e.g. KYC providers). Because the definer can swap this list at any time:
- The definer can replace the attestor list with an attestor address controlled by/colluding with the definer, who then attests different addresses. Since only attested addresses can be an `issuer_address` or valid author of a payment of that asset, the definer can retroactively change who is allowed to move the asset, functionally freezing balances held by addresses that are no longer (or never) attested by the new attestor(s). This matches the "AA fund loss or freezing" and "node disagreement on validity" impact classes.
- Holders who relied on the disclosed vetting mechanism to judge counterparty risk in private/attested trades can be blindsided when the definer unilaterally changes who counts as "attested," undermining the entire trust assumption the asset was built on — the same "rug after the fact" pattern as the external report, just expressed through an access-control list rather than a mint-supply parameter.

### Likelihood Explanation
This requires no special network position — any asset definer (a normal wallet address, or more powerfully an AA holding significant assets under management) can post an `asset_attestors` unit at any time; validation imposes no timing or activity-based restriction. The action is a single, ordinary transaction type already fully supported by consensus/validation code, making it trivially reachable by any single poster who is the asset's definer — precisely the "unprivileged... asset issuer" actor class in scope.

### Recommendation
Introduce a restriction analogous to the fix applied to `setSAM()`: either (a) disallow `asset_attestors` updates once the asset has any confirmed issuance/transfer (i.e., only allow attestor-list changes while `total issued/transferred == 0`), or (b) require the attestor list to be fixed and disclosed atomically with the asset definition (in the same `asset` message) rather than mutable afterward, so downstream holders can rely on an immutable trust assumption once they acquire the asset.

### Proof of Concept
1. Definer address (or AA) `D` posts an `asset` definition message with `spender_attested: true` and an initial `attestors` list `[A1]` that appears trustworthy (e.g. a reputable KYC attestor) — see the `asset` payload validation logic: [7](#0-6) .
2. Users acquire and hold balances of this asset, trusting that only addresses attested by `A1` can spend it, per the check in `validatePayment`: [1](#0-0) .
3. After adoption, `D` posts a new `asset_attestors` message replacing the attestor list with `[A2]`, where `A2` is controlled by or colludes with `D`. This message passes validation solely by satisfying `validateAttestorListUpdate` (single author = definer, well-formed nonempty sorted list) — no check on prior issuance/circulation: [2](#0-1) .
4. All future payments now resolve against the new list (`readAsset`/`addAttestorsIfNecessary` fetches the latest attestor unit): [4](#0-3) . Existing holders who are not attested by `A2` can no longer move their balances (frozen funds), while `D`/colluding addresses attested by `A2` gain exclusive ability to transact the asset going forward — a unilateral post-hoc change of the rules users transacted under.

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

**File:** storage.js (L1917-1946)
```javascript
		function addAttestorsIfNecessary(byAA = false){
			if (!objAsset.spender_attested)
				return handleAsset(null, objAsset);

			// find latest list of attestors
			const before_last_ball_cond = byAA ? "" : `AND main_chain_index<=${+last_ball_mci} AND is_stable=1`;
			conn.query(
				"SELECT unit FROM asset_attestors CROSS JOIN units USING(unit) \n\
				WHERE asset=? " + before_last_ball_cond + " AND sequence='good' ORDER BY "+ (conf.bLight ? "units.rowid" : "level") + " DESC LIMIT 1",
				[asset],
				function (latest_rows) {
					if (latest_rows.length === 0)
						throw Error("no latest attestor list");
					var latest_attestor_list_unit = latest_rows[0].unit;

					// read the list
					conn.query(
						"SELECT attestor_address FROM asset_attestors CROSS JOIN units USING(unit) \n\
						WHERE asset=? AND unit=? " + before_last_ball_cond + " AND sequence='good'",
						[asset, latest_attestor_list_unit],
						function (att_rows) {
							if (att_rows.length === 0)
								throw Error("no attestors?");
							objAsset.arrAttestorAddresses = att_rows.map(function (att_row) { return att_row.attestor_address; });
							handleAsset(null, objAsset);
						}
					);
				}
			);
		}
```

**File:** test/aa.test.js (L249-271)
```javascript
			{
				app: 'asset',
				payload: {
					cap: "{trigger.output[[asset=base]]}",
					is_transferrable: true,
					is_private: false,
					auto_destroy: "{trigger.data.auto_destroy}",
					fixed_denominations: false,
					issued_by_definer_only: true,
					cosigned_by_definer: false,
					spender_attested: false,
				}
			},
			{
				app: 'asset_attestors',
				payload: {
					asset: "{trigger.output[[asset!=base]].asset}",
					attestors: [
						"{trigger.data.attestor1}",
						"{trigger.data.attestor2 ? trigger.data.attestor2 : ''}",
					]
				}
			},
```

**File:** composer.js (L123-125)
```javascript
function composeAssetAttestorsJoint(from_address, asset, arrNewAttestors, signer, callbacks){
	composeContentJoint(from_address, "asset_attestors", {asset: asset, attestors: arrNewAttestors}, signer, callbacks);
}
```

**File:** aa_validation.js (L225-242)
```javascript
				case 'asset':
					if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations", "init"]))
						return cb2("unknown fields in asset definition in AA");
					if (payload.fixed_denominations === true && !isNonemptyArray(payload.denominations))
						return cb2("denominations not defined");
					if ("cap" in payload) {
						if (typeof payload.cap === 'number') {
							if (!(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
								return cb2("invalid cap: " + payload.cap);
						}
						else if (typeof payload.cap === 'string') {
							var f = getFormula(payload.cap);
							if (f === null)
								return cb2("bad formula in cap: " + payload.cap);
						}
						else
							return cb2("wrong cap: " + JSON.stringify(payload.cap));
					}
```
