### Title
Spender-attested assets can permanently lock a holder's funds if the asset definer removes their address from the attestor-controlled allow-list - ([File: validation.js])

### Summary
Assets with `spender_attested: true` require every address that holds/spends the asset to be attested by one of the asset's designated attestors. The attestor list is a mutable allow-list that can be updated at any time by the asset's `definer_address` via an `asset_attestors` message. Just like a USDC-style blacklist, once an address's attestation is revoked (or simply not renewed), that address permanently loses the ability to spend, transfer, or receive the asset — with no fallback mechanism to recover the locked balance.

### Finding Description
When an asset is defined with `spender_attested: true`, ocore requires that:
1. Every input-owner address on a payment be currently attested (`validatePaymentInputsAndOutputs`): [1](#0-0) 
2. Every output address of a transfer/issue be currently attested (`validatePaymentInputsAndOutputs`): [2](#0-1) 
3. The issuer/author of a payment be currently attested (`validatePayment`): [3](#0-2) 

"Attested" is determined solely by `storage.filterAttestedAddresses`, which checks the *latest* attestor list published for the asset and any `attestation` messages issued by those attestors: [4](#0-3) 

Crucially, the attestor list itself is fully controlled by the single `definer_address` of the asset, and can be changed unilaterally at any later time via an `asset_attestors` message: [5](#0-4) 

There is no mechanism in `divisible_asset.js`, `indivisible_asset.js`, or `aa_composer.js` that lets a holder redirect or reclaim funds to a different, still-attested address once their own address falls out of the attestor's good graces — the payment composers simply refuse to include the address as payer or payee: [6](#0-5) [7](#0-6) 

This mirrors the reported bug class precisely: an "issuer" (here, the asset `definer_address`, one of the explicitly in-scope actors) can revoke an address's standing at any time, and any balance already held by that address in the asset becomes permanently unspendable — it cannot be transferred out, issued from, or received into, because both the source (`owner_address is not attested`) and destination (`some output addresses are not attested`) checks fail unconditionally with no recovery path.

### Impact Explanation
Any holder of a `spender_attested` asset (fungible token issued on ocore, including tokens issued by AAs for DeFi/vesting/DEX use cases) can have their entire balance of that asset permanently frozen if the definer/attestor removes or fails to renew their attestation. Because the check is enforced at the base validation layer (`validatePaymentInputsAndOutputs`), there is no way — via signature, multisig, or any on-chain workaround — to move the frozen balance to a different address or to the definer once locked out. This is a direct, permanent loss-of-funds condition for the affected address, matching the "AA fund loss or freezing" acceptance criterion.

### Likelihood Explanation
This requires a `spender_attested` asset to exist and its definer to change the attestor list (or simply not include a particular address in a list refresh) after the holder has acquired a balance. This is a normal, intended operation exposed to the definer via a plain `asset_attestors` message — no privileged network access or malicious peer/hub behavior is needed, only the asset issuer acting through the ordinary protocol path that any asset definer can invoke. Given how common attested-token designs are for KYC/compliance-oriented assets (the very use case `spender_attested` was built for), the likelihood of an address becoming legitimately-but-permanently locked out (analogous to blacklisting) is realistic.

### Recommendation
Provide a bounded recovery path for addresses that lose attestation while still holding non-zero balances of a `spender_attested` asset — for example, allow such balances to be reclaimed by (or forcibly redirected to) the `definer_address` similar to the existing `auto_destroy`-to-definer pattern, rather than leaving the funds permanently unspendable by anyone. Alternatively, document this as an explicit, intended design trade-off of `spender_attested` assets so wallet/AA developers can warn users before acquiring such assets.

### Proof of Concept
1. Definer publishes an `asset` message with `spender_attested: true` and an initial `attestors` list `[A]`.
2. Attestor `A` publishes an `attestation` for address `X`; `X` receives a transfer of the asset (validated fine since `X` is attested per `storage.filterAttestedAddresses`).
3. Definer later publishes an `asset_attestors` message removing `A` (or replacing it with attestor `B`, who never attests `X`) — this is permitted because the definer is the sole authority per `validateAttestorListUpdate` (`validation.js:2829-2848`).
4. Address `X` attempts to spend its existing balance: `validatePaymentInputsAndOutputs` rejects it with `"owner address is not attested"` (`validation.js:2506-2507`), and any attempt to send the balance to `X` as an output likewise fails with `"some output addresses are not attested"` (`validation.js:2637`).
5. `X`'s balance in the asset is now permanently unspendable with no recovery mechanism.

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
