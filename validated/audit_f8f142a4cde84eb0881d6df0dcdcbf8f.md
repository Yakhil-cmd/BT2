### Title
Asset definer can dynamically deny individual holders via the spender-attestor list, freezing/blocking their specific outputs while leaving all other holders unaffected - (File: validation.js / storage.js)

### Summary
A custom `spender_attested` asset lets its definer publish/update the list of "attested" spender addresses at any time via an `asset_attestors` message. Every payment of such an asset is validated by requiring *all* output addresses (including a spender's own change output) to be on the current attestor list. Because the definer fully controls this list post-issuance, they can watch the DAG for a specific address holding or about to receive the asset and then remove just that address from the attestor list, causing any future payment that would leave the asset with (or send it back as change to) that address to fail validation - exactly mirroring the reported pattern of a pool/token owner selectively blocking one recipient's withdrawal without affecting anyone else.

### Finding Description
`validatePaymentInputsAndOutputs()` enforces attestation for `spender_attested` assets by checking that every output address of the payment is attested: [1](#0-0) 

The attestor list itself is fully mutable after asset creation: the definer alone can add/update it via the `asset_attestors` message, checked and stored independent of the original `asset` definition: [2](#0-1) [3](#0-2) 

Unlike `issue_condition`/`transfer_condition`, which are fixed once at asset definition time and validated only against the static definition, the attestor list is a live, definer-controlled allow-list that can be changed at will, at any time, for any address — this is the "custom reward token that reverts for specific addresses" analog: the definer inspects the chain for which address now holds units of the asset (or is about to receive some), and specifically removes that address from the attestor list. Any subsequent payment that would produce an output to that address (a normal transfer, or even the victim's own change output when trying to spend their balance) will fail validation with `"some output addresses are not attested"`, while payments among all other, still-attested addresses continue to work normally.

This directly parallels the C4 finding: the "withdraw"-equivalent operation (a payment/transfer of the asset) reverts only for the one, targeted address, and the party controlling the asset (the definer, analogous to the pool/token owner) can react reactively and repeatedly after observing on-chain who holds funds, without breaking functionality for any other holder.

### Impact Explanation
A victim holding a `spender_attested` asset can be selectively and repeatedly frozen out of using or receiving that asset merely because the definer sees their address and removes it from the attestor list. Because ALL outputs (including change back to the spender) must be attested, the victim can be locked out of transferring or even partially spending their balance (any output route requiring change back to themselves fails), effectively freezing their funds in that asset. This is a fund-freezing/griefing vector reachable by any ordinary asset holder (payment poster) interacting with an asset whose definer behaves maliciously — the definer needs no special network position, only control of the `asset_attestors` message for an asset they defined.

### Likelihood Explanation
Likelihood is high in practice for any asset that chooses to use `spender_attested`: the mechanism is a documented feature (meant for KYC/whitelisting use cases) but its unrestricted, live mutability by a single party (the definer) makes selective targeting trivial and requires no exploit of a bug in validation logic — it is a natural consequence of the current attestor-list design being unbounded and definer-controlled post-issuance.

### Recommendation
Consider mitigations similar to the one recommended in the source report — decouple "someone is temporarily not attested" from "the whole payment fails": e.g., allow spend of the victim's balance without requiring change to go back to the same address (permit sending unattested addresses' balances to any attested destination without needing a self-change output), or introduce a resolution/appeal mechanism, or require attestor-list changes to be time-delayed/committed in advance so they cannot be used reactively/targeted after observing specific holders. At minimum, document this risk clearly for `spender_attested` assets so wallets/AAs can treat them as inherently controllable by the definer.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true` and an initial attestor list including address `V` (victim) and others. [2](#0-1) 
2. Victim `V` receives units of asset `A` in a payment; this succeeds because `V` is attested at that time — validated per: [1](#0-0) 
3. Definer observes on-chain that `V` now holds asset `A`, and posts a new `asset_attestors` message that omits `V` from the attestor list (only definer is authorized to do this): [4](#0-3) 
4. `V` attempts to transfer/spend asset `A` (e.g., to pay a third party, needing standard change back to `V`, or simply to move balance): any output that includes address `V` now fails validation with `"some output addresses are not attested"` while transfers among all other still-attested addresses continue to succeed normally, leaving `V` selectively frozen without any other functionality being impacted — mirroring the reported "prevent withdrawal of specific receipts" pattern.

### Citations

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

**File:** writer.js (L244-251)
```javascript
						case "asset_attestors":
							var asset_attestors = message.payload;
							for (var j=0; j<asset_attestors.attestors.length; j++){
								conn.addQuery(arrQueries, 
									"INSERT INTO asset_attestors (unit, message_index, asset, attestor_address) VALUES(?,?,?,?)",
									[objUnit.unit, i, asset_attestors.asset, asset_attestors.attestors[j]]);
							}
							break;
```
