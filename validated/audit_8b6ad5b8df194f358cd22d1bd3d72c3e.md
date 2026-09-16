## Analog Vulnerability Found

### Title
Asset `spender_attested` mechanism lets the asset definer permanently freeze all holders' funds by installing a non-functional attestor list - ([File: validation.js])

### Summary
The external report describes a pattern where a critical function (`deposit`/`withdraw`/`swap`) is hard-restricted to only be callable by a single trusted address (`router`) that is chosen once, at creation time, by a party (the pool creator) other than the users who will later depend on it. If that trusted address turns out to be broken or malicious, users' funds become permanently locked with no way to bypass the restriction. The same structural pattern exists in ocore's `spender_attested` asset feature: once an asset is created with `spender_attested: true`, every subsequent spend (input owner *and* output recipient) must be an address attested by an attestor list that is entirely controlled by the asset's `definer_address`, with no validation that the chosen attestors are trustworthy, live, or will ever attest anyone.

### Finding Description
When an asset is defined with `spender_attested: true`, `validateAssetDefinition` only checks that the initial `attestors` array is well-formed (`checkAttestorList`), not that the attestors are meaningful or reachable: [1](#0-0) 

The definer can later replace the attestor list at will via an `asset_attestors` message. The only check is that the message is single-authored by the current `definer_address`: [2](#0-1) [3](#0-2) 

Once `spender_attested` is set, every payment enforces the attestation check unconditionally on **both** the spending input owner and **all** output addresses, with no special exemption for the definer address itself: [4](#0-3) [5](#0-4) [6](#0-5) 

The attestor list is read fresh at validation time from `asset_attestors`/`attestations`, and `filterAttestedAddresses` requires an on-chain `attestation` message from one of the current attestor addresses for each spender/output address: [7](#0-6) 

Because the definer can set the attestor list to any valid address (there is no requirement that the address ever posts attestations, nor that it be reachable, nor that it be distinct from a dead/adversarial address), and because the check applies to every output address including the definer's own change output, a definer (or an AA acting as definer, if it issues an asset with `issued_by_definer_only`) can render the asset **permanently unspendable by anyone, including itself**, simply by pointing the attestor list at an address that will never issue attestations. This mirrors the DAOfi issue precisely: a security-critical gate (spend authorization / router call authorization) is delegated to a single externally chosen address that other participants are forced to trust, with no mechanism to fall back or override if that address is non-functional or malicious.

### Impact Explanation
If the attestor list is set (at issuance or via a later `asset_attestors` update) to an address that never attests anyone, every unit trying to spend or receive that asset will fail final validation ("owner address is not attested" / "some output addresses are not attested"), permanently freezing all holders' balances of that asset — including the definer's own funds if a bug or malicious action points the attestor list to a bad address. This is a concrete "AA fund loss or freezing" outcome: any AA that issues a `spender_attested` asset and update its attestor list (e.g., in response to a trigger) is one bad reference away from bricking its own token supply and users' balances with no possible recovery, since only the (possibly frozen-out) definer can issue a corrective `asset_attestors` update, and that update itself doesn't need to be a valid one.

### Likelihood Explanation
Any asset issuer (including an AA acting as issuer) can trigger this by mistake or intentionally: it requires only posting a normal `asset` definition message with `spender_attested: true` and a subsequently reachable `asset_attestors` update pointing to an unresponsive/incorrect address — no special privilege, hub, or network position is needed, matching the "unprivileged unit poster / asset issuer / AA trigger sender" reachable category from an ordinary unit.

### Recommendation
- Do not let the attestor-list update path silently accept attestor addresses with no validation that they can/will attest; at minimum, warn/require an explicit acknowledgment in tooling.
- Consider always exempting the `definer_address` from the attestation requirement on the output side so a botched attestor list cannot brick the definer's own recovery path.
- For AA-issued `spender_attested` assets, require extra safeguards (e.g., disallow parameterized/attacker-influenced `asset_attestors` payload fields, or require multiple attestors) so a single bad attestor list cannot cause an irrecoverable freeze.

### Proof of Concept
1. An address (or AA) issues an asset via `app: 'asset'` with `spender_attested: true`, `issued_by_definer_only: true`, and an initial attestor `X` [8](#0-7) .
2. Later, the same definer posts an `asset_attestors` message replacing the attestor list with an address `Y` that has never posted, and never will post, any `attestation` message [2](#0-1) .
3. Any subsequent attempt by any holder (including the definer) to spend or receive this asset is rejected during `validatePaymentInputsAndOutputs`/`validatePayment` because `filterAttestedAddresses` finds no attestation from `Y` for any address [6](#0-5) [7](#0-6) , permanently freezing all balances of the asset.

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

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

**File:** validation.js (L2630-2642)
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
					},
```

**File:** validation.js (L2725-2751)
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

**File:** storage.js (L1959-1974)
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
```
