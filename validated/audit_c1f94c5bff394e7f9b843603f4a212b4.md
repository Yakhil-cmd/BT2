## Title
Non-transferrable/auto-destroy assets can become permanently unspendable when `spender_attested` is required but the definer address is not attested - (File: `validation.js`)

### Summary
In `validation.js`, `validatePaymentInputsAndOutputs` enforces two independent constraints on divisible-asset outputs: (1) for non-transferrable assets, the *only* valid payment destination is the asset's `definer_address` (used as the "burn sink" for `auto_destroy` assets), and (2) for `spender_attested` assets, *every* output address — with no exception for the definer/burn address — must appear in the attested-addresses list. Because these two checks are combined without special-casing the definer address, an asset issuer who sets both `is_transferrable: false`/`auto_destroy: true` and `spender_attested: true` — but never has the definer address itself attested — permanently blocks all valid transfers/burns of that asset, mirroring the reported "zero address blacklist blocks burn" bug class, where a control-list gate (blacklist there, attestor whitelist here) inadvertently locks out the mandatory sink/burn address.

### Finding Description
For non-transferrable assets, the code only accepts a payment if the sole output is the `definer_address` (or the definer plus the payer's own change): [1](#0-0) 

This is the mechanism by which token holders "destroy"/burn a non-transferrable, `auto_destroy` asset by sending it back to the definer, and it is also enforced per-input for `auto_destroy` outputs already sent to the definer being un-spendable again: [2](#0-1) 

Separately, when the asset requires `spender_attested`, every output address in the payment (`arrOutputAddresses`), including the mandatory `definer_address` destination described above, must be present in the attested-address set, with no carve-out for the definer/burn address: [3](#0-2) 

`filterAttestedAddresses` performs a strict SQL match against the attestation table and does not special-case the asset's own `definer_address`: [4](#0-3) 

`validateAssetDefinition` allows an issuer to freely combine `is_transferrable: false`, `auto_destroy: true`, and `spender_attested: true` — there is no rule requiring the definer address to be included in (or exempted from) the attestor list, and the explicit comment "possible: definer is like black hole" shows this destination is deliberately treated as a special sink, yet the attestation gate does not treat it specially: [5](#0-4) 

Because the definer address is the *only* legal output for a non-transferrable asset, if the issuer's attestor(s) never attest the definer address itself (a very plausible oversight — attestors are typically expected to vet regular users, not the issuer's own black-hole address), then `filterAttestedAddresses` will always return a set smaller than `arrOutputAddresses`, and every payment message for that asset will fail with `"some output addresses are not attested"`.

### Impact Explanation
Any unprivileged unit poster who becomes a holder of such an asset is permanently unable to submit a valid payment for it, since the only allowed destination (the definer/burn address) can never pass the attestation check. This is not merely inability to "burn": for `is_transferrable: false` assets the definer output is the *only* legal payment path, so this is a total, permanent freeze of all outstanding balances of the asset with no recovery path (the definer would need to retroactively attest itself, which requires foreseeing this interaction). This matches the accepted impact category of AA/asset fund loss or freezing.

### Likelihood Explanation
Reachable by any ordinary user via a standard `asset` definition message (no special privilege required) — the definer just needs to set `is_transferrable: false`, `auto_destroy: true`, and `spender_attested: true` with an attestor list that does not include its own definer address, which is a natural configuration for a KYC-gated, single-use/burnable token where the issuer never expects to be a "spender" in the attested sense.

### Recommendation
Exempt the asset's `definer_address` from the `spender_attested` output check in `validatePaymentInputsAndOutputs` (and correspondingly in `filterAttestedAddresses`/`storage.js`), since it functions as a system-defined burn/black-hole sink rather than a normal spender that needs attestation. Alternatively, reject asset definitions at validation time (`validateAssetDefinition`) that combine `is_transferrable:false` + `spender_attested:true` unless the definer explicitly attests itself as part of the same or an earlier `asset_attestors` message.

### Proof of Concept
1. Issuer posts an `asset` definition unit with `is_transferrable: false`, `auto_destroy: true`, `spender_attested: true`, and an `asset_attestors` list containing only end-user attestor addresses (not the definer address itself) — accepted by `validateAssetDefinition` (`validation.js:2725-2827`) since no rule forbids this.
2. Issuer issues the asset to users; users are attested by the listed attestors (per `attested_fields`/attestations flow).
3. A user attempts to send the asset back to `definer_address` (the only legal destination per `validation.js:2616-2628`, and the intended burn path per `validation.js:2504-2506`).
4. `validatePaymentInputsAndOutputs` calls `storage.filterAttestedAddresses` on `arrOutputAddresses = [definer_address]` (`validation.js:2630-2641`); since `definer_address` was never attested, `arrAttestedOutputAddresses.length !== arrOutputAddresses.length`, and the unit is rejected with `"some output addresses are not attested"`.
5. Because this is the only legal output for a non-transferrable asset, no payment of this asset can ever validate — all holders' balances are permanently frozen.

### Citations

**File:** validation.js (L2504-2506)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
```

**File:** validation.js (L2616-2628)
```javascript
				if (!objAsset.is_transferrable){ // the condition holds for issues too
					if (arrInputAddresses.length === 1 && arrInputAddresses[0] === objAsset.definer_address
					   || arrOutputAddresses.length === 1 && arrOutputAddresses[0] === objAsset.definer_address
						// sending payment to the definer and the change back to oneself
					   || !(objAsset.fixed_denominations && objAsset.is_private) 
							&& arrInputAddresses.length === 1 && arrOutputAddresses.length === 2 
							&& arrOutputAddresses.indexOf(objAsset.definer_address) >= 0
							&& arrOutputAddresses.indexOf(arrInputAddresses[0]) >= 0
					   ){
						// good
					}
					else
						return callback("the asset is not transferrable");
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

**File:** validation.js (L2794-2812)
```javascript
	if (payload.is_private && payload.is_transferrable && !payload.fixed_denominations)
		return callback("if private and transferrable, must have fixed denominations");
	if (payload.is_private && !payload.fixed_denominations){
		if (!(payload.auto_destroy && !payload.is_transferrable))
			return callback("if private and divisible, must also be auto-destroy and non-transferrable");
	}
	if (payload.is_private && ("issue_condition" in payload || "transfer_condition" in payload) && (objValidationState.last_ball_mci >= constants.noPrivateAssetsWithConditionsUpgradeMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.noPrivateAssetsWithConditionsUpgradeMci))
		return callback("if private, cannot have issue or transfer conditions");
	if (payload.cap && !payload.issued_by_definer_only)
		return callback("if capped, must be issued by definer only");
	
	// possible: definer is like black hole
	//if (!payload.issued_by_definer_only && payload.auto_destroy)
	//    return callback("if issued by anybody, cannot auto-destroy");
	
	// possible: the entire issue should go to the definer
	//if (!payload.issued_by_definer_only && !payload.is_transferrable)
	//    return callback("if issued by anybody, must be transferrable");
	
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
