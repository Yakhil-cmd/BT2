## Title
Asset issuer (definer) can weaponize `spender_attested` to freeze users' asset holdings and later selectively unfreeze only their own address - (File: `validation.js`, `writer.js`, `storage.js`)

## Summary
The reported Popcorn issue is a class of bug where a privileged, unaudited configuration value (`feeRecipient == 0x0`) controlled solely by the vault operator makes every reward-claim transaction revert, permanently trapping user funds, while the operator alone can flip the switch later to reclaim value for themselves. ocore has a structurally identical mechanism at the protocol level: the `spender_attested` asset flag combined with the `asset_attestors`/`attestation` messages. The asset definer alone controls whether any address is ever "attested," and every payment involving such an asset unconditionally fails validation until the definer chooses to attest a spender - giving the definer the same "lure users in, freeze funds, unlock only for myself when convenient" capability.

## Finding Description
When an asset is defined with `spender_attested: true`, the definer must supply an initial `attestors` list at creation time ( [1](#0-0) ), but nothing forces those attestors to ever actually attest any address. Attestation only happens when the attestor posts a separate `attestation` unit, and that update is entirely under the sole control of the definer / attestor's own free will.

Every payment of such an asset is gated by the attestation set:
- On issuance/holding checks, if none of the authors is attested, the payment is rejected outright: [2](#0-1) 
- When spending an existing output, the owning address must be individually attested, otherwise `"owner address is not attested"` is returned: [3](#0-2) 
- Even the resulting output addresses must be attested to receive the asset: [4](#0-3) 

Only the definer can edit the attestor list at all (`validateAttestorListUpdate`), and `checkAttestorList` only validates the *shape* of the list, not that anyone will ever be attested: [5](#0-4) 

The actual "is this address attested" check is derived purely from `attestation` units posted by the definer-chosen attestor address(es), matched against the address's most recent `address_definition_change`: [6](#0-5) 

This exact primitive (`spender_attested` + `attestors` fully controlled by trigger data) is directly reachable from an ordinary AA trigger sender or asset issuer, as shown in the shipped sample AA that lets a triggering address define an asset with arbitrary attestors: [7](#0-6)  AAs themselves are also allowed to define `spender_attested` assets with formula-driven attestor lists: [8](#0-7) 

## Impact Explanation
An asset issuer (or an AA author who lets a trigger define such an asset, e.g. as a "share"/"receipt" token for deposits, similar to the vault-share pattern in the Popcorn report) can:
1. Advertise the asset as freely transferrable/redeemable to attract deposits or swaps (analogous to the "high APY, low fee" lure).
2. Never post any `attestation` unit, so `arrAttestedAddresses` stays empty for every holder and every transfer of the asset permanently fails validation (`"none of the authors is attested"` / `"owner address is not attested"`), freezing all depositors' holdings of that asset indefinitely - matching the original bug's "reward-claim always reverts" behavior.
3. At a time of their choosing (e.g., once liquidity/backing value has accumulated or after depositors give up and stop watching), post a single `attestation` attesting only their own (or a colluding) address, letting them alone move/redeem the asset (or whatever collateral it represents) while everyone else remains frozen - mirroring the vault creator's ability to "decide when is the right time to open the rewards up" and reclaim funds.

This is a concrete AA/asset fund-freezing and selective-unlock vulnerability rather than a low-severity or resource-only issue, since it can permanently strand user-held value with no recourse other than the definer's discretion.

## Likelihood Explanation
This does not require any consensus flaw - it is achievable with standard, fully-valid `asset`, `asset_attestors`, and `attestation` messages that pass all current validation rules. Any asset issuer, or any AA whose oscript exposes an asset-definition case driven by trigger data (a documented and sample-supported pattern, see `create_an_asset.oscript`), can implement this pattern today. The only "cost" to the attacker is initial credibility to attract deposits, exactly as in the original report.

## Recommendation
- Discourage/flag asset designs where `spender_attested` assets are used as freely-tradable "receipt"/"share" tokens without a mechanism forcing timely, or definer-independent, attestation.
- Consider requiring/encouraging AAs that mint `spender_attested` assets as internal accounting tokens to also auto-attest recipients within the same trigger response (so the AA, not a human definer, controls attestation deterministically), and audit any AA templates offering `asset`+arbitrary `attestors` to depositors.
- At minimum, document this attestor-freeze pattern prominently as a known "escrow zero-address"-class risk for asset issuers and AA authors, so wallets/explorers can warn users before they acquire a `spender_attested` asset whose attestor set has never attested anyone.

## Proof of Concept
1. Issuer posts an `asset` definition message: `{is_transferrable: true, spender_attested: true, attestors: [issuer_address]}` (validated per [9](#0-8) ).
2. Issuer advertises/sells this asset to depositors in exchange for bytes (e.g., via the pattern shown in `test/samples/sell_asset_for_bytes.oscript` or `create_an_asset.oscript`).
3. Issuer never posts an `attestation` unit for any depositor address.
4. Any depositor who tries to transfer or redeem the asset gets their unit rejected with `"none of the authors is attested"` ( [2](#0-1) ) or `"owner address is not attested"` ( [3](#0-2) ) — funds are frozen exactly like the reward claims reverting when `feeRecipient == 0x0`.
5. When the issuer decides the timing is favorable, they post a single `attestation` unit attesting only their own address (allowed exclusively by them, per [10](#0-9) ), letting them alone move the asset/value while other depositors remain permanently frozen.

### Citations

**File:** validation.js (L2115-2121)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
```

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
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

**File:** validation.js (L2725-2750)
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

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");

	if (objValidationState.bAA) {
		if (payload.cosigned_by_definer !== false)
			return callback("cosigned_by_definer must be false because AAs can't cosign");
		if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
			return callback("assets issued by AA definer cannot be private or fixed denominations");
	}

	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");
```

**File:** validation.js (L2829-2864)
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

**File:** storage.js (L1959-1992)
```javascript
// filter only those addresses that are attested (doesn't work for light clients)
function filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAddresses, handleAttestedAddresses){
	conn.query(
		"SELECT DISTINCT address FROM attestations CROSS JOIN units USING(unit) \n\
		WHERE attestor_address IN(?) AND address IN(?) AND main_chain_index<=? AND is_stable=1 AND sequence='good' \n\
			AND main_chain_index>IFNULL( \n\
				(SELECT main_chain_index FROM address_definition_changes JOIN units USING(unit) \n\
				WHERE address_definition_changes.address=attestations.address AND main_chain_index<=? AND is_stable=1 AND sequence='good' ORDER BY main_chain_index DESC LIMIT 1), \n\
			0)",
		[objAsset.arrAttestorAddresses, arrAddresses, last_ball_mci, last_ball_mci],
		function(addr_rows){
			var arrAttestedAddresses = addr_rows.map(function(addr_row){ return addr_row.address; });
			handleAttestedAddresses(arrAttestedAddresses);
		}
	);
}

// note that light clients cannot check attestations
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

**File:** test/samples/create_an_asset.oscript (L1-30)
```text
{
	bounce_fees: { base: 11000 },
	messages: {
		cases: [
			{
				if: "{trigger.data.define}",
				messages: [
					{
						app: 'asset',
						payload: {
							cap: "{trigger.data.cap otherwise ''}",
							is_private: false,
							is_transferrable: true,
							auto_destroy: "{!!trigger.data.auto_destroy}",
							fixed_denominations: false,
							issued_by_definer_only: "{!!trigger.data.issued_by_definer_only}",
							cosigned_by_definer: false,
							spender_attested: "{!!trigger.data.attestor1}",
							attestors: [
								"{trigger.data.attestor1 otherwise ''}",
								"{trigger.data.attestor2 otherwise ''}",
								"{trigger.data.attestor3 otherwise ''}",
							]
						}
					},
					{
						app: 'state',
						state: "{ var[response_unit] = trigger.address; }"
					}
				]
```

**File:** aa_validation.js (L293-322)
```javascript
					if ("transfer_condition" in payload) {
						if (!isArrayOfLength(payload.transfer_condition, 2))
							return cb2("wrong transfer condition: " + JSON.stringify(payload.transfer_condition));
					}
					if (payload.cosigned_by_definer !== false)
						return cb2("cosigned_by_definer must be false because AA can't cosign");
					if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
						return cb2("asset issued by AA definer cannot be private or fixed denominations");
					async.eachSeries(
						["is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested"],
						function (field, cb3) {
							if (typeof payload[field] === 'boolean')
								return cb3();
							if (typeof payload[field] === 'string') {
								var f = getFormula(payload[field]);
								if (f === null)
									return cb3("bad formula for " + field + " in asset");
								return cb3();
							}
							cb3(field + " is missing or of wrong type");
						},
						function (err) {
							if (err)
								return cb2(err);
							async.series([
								function (cb3) {
									if (!("attestors" in payload))
										return cb3();
									validateFieldWrappedInCases(payload, 'attestors', validateAttestors, cb3);
								},
```
