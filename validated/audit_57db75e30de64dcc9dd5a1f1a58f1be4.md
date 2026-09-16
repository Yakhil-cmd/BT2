### Title
Asset definer can front-run pending transfers of a `spender_attested` asset by mutating the attestor list via `asset_attestors`, invalidating already-composed payments and freezing counterparty funds - (File: validation.js)

### Summary
Assets created with `spender_attested: true` restrict which addresses may hold/spend the asset to a definer-controlled attestor list. Unlike the `Swap`/`Aave` `owner` in the external report, the analogous privileged actor here — the **asset issuer/definer** — is an explicitly permitted actor per this scan's scope. The definer can unilaterally update the attestor list at any time via an `asset_attestors` message, and this update is checked using the state at *validation time* of a spending unit (i.e. as of `objValidationState.last_ball_mci` when the payment stabilizes), not at the time the payment was composed and handed to a counterparty. A malicious/compromised definer can therefore front-run an already-composed (and, in private-payment scenarios, already-delivered) transfer by publishing a new attestor list that excludes the intended recipient/issuer right before the transfer is included, causing the transfer to be rejected and the sender's coins to become unusable/stuck (they must re-spend, and any goods/service already delivered to the definer's counterparty based on the private payment is lost).

### Finding Description
The attestor list for an asset is defined only by the asset's `definer_address`, enforced in `validateAttestorListUpdate`: [1](#0-0) 

This message type (`asset_attestors`) can be posted at any point after the asset is defined — there is no restriction preventing the definer from changing it repeatedly, and it is a single independent message the definer alone authors: [2](#0-1) 

The persisted list is used later to validate every transfer/issue of that asset. The check happens against the attestor set as of `objValidationState.last_ball_mci`, which is evaluated when the spending unit is processed/stabilized — not when the payment was originally built and signed: [3](#0-2) 

For transfers, all *output* addresses must appear in the currently attested list, again resolved at validation time via `filterAttestedAddresses`: [4](#0-3) 

The write path shows the attestor list update is a simple, unconditioned INSERT keyed by the message's own unit — nothing links the update to (or blocks it from invalidating) any pending, already-signed transaction relying on the previous list: [5](#0-4) 

Because a payment (particularly a private payment, whose chain a sender may hand to a recipient off-DAG before it is broadcast/stabilized) references `last_ball_mci` at composition time but is re-checked with the *live* attestor state at inclusion time, the definer can:
1. Wait for a user to compose/send a private payment to a recipient who is currently on the attestor list (or wait for an issuer to have valid issuance rights).
2. Front-run by broadcasting a new `asset_attestors` unit dropping the recipient (or the issuer) from the list, timed so it stabilizes before the target payment.
3. The pending payment now fails `validatePayment`'s attestation check when it is finally posted/stabilized, so the sender's committed inputs become unusable in that shape and must be reconstructed — while any real-world consideration already handed over based on the (private) payment is lost.

This mirrors the report's bug class: a privileged, unprivileged-reachable "owner"-like role (the asset definer) can mutate configuration state that other unprivileged parties (senders, private-payment counterparties) rely on, front-running their already-issued transaction to cause fund loss/freezing.

### Impact Explanation
Impact is High for affected counterparties: a definer of a `spender_attested` asset can grief/freeze any pending transfer or issuance by racing an attestor-list update against it, and in private-payment workflows this can result in outright loss of value for the counterparty who already released goods/services or a private-payment chain based on the (soon to be invalidated) transaction. It does not directly mint or steal on-chain balances, but it reliably blocks/expropriates the economic value that depended on timely, predictable settlement.

### Likelihood Explanation
Likelihood is Low-to-Medium, consistent with the original report: it requires a malicious or compromised asset definer, which is a privileged (but unprivileged-reachable, since anyone can define such an asset and market it) role. Any dApp or user accepting a `spender_attested` asset from an untrusted definer, or engaging in private payments contingent on a stable attestor set, is exposed.

### Recommendation
- Bind attestation checks for a given payment to the attestor list state as of the payment's own `last_ball_mci` snapshot at composition time (already recorded), rather than re-resolving the "current" attestor list at stabilization time, or
- Require a cooldown/timelock on `asset_attestors` updates (e.g., not effective until N mci after posting) so senders/recipients have a predictable window, and/or
- Document explicitly to wallet/AA developers that `spender_attested` assets carry this settlement-time risk and that private-payment chains should not be treated as final until the attestor list is confirmed unchanged up to stabilization.

### Proof of Concept
1. Definer `D` issues asset `A` with `spender_attested: true` and posts an initial attestor list `[R]` including recipient `R` (via the `asset` + `asset_attestors` messages, validated per `validateAssetDefinition`/`validateAttestorListUpdate`).
2. Sender `S`, observing `R` attested, composes and (for a private asset) hands `R` a private payment of `A` with output to `R`, referencing a `last_ball_unit`/`last_ball_mci` where `R` is attested.
3. Before `S`'s payment unit stabilizes, `D` posts a new `asset_attestors` unit removing `R` (adding, e.g., `D`'s own address instead) — see `validateAttestorListUpdate` (validation.js:2829-2848), which allows this unconditionally as long as `D` is `objAsset.definer_address`.
4. `D`'s update stabilizes first (front-run). When `S`'s payment is subsequently validated at its own inclusion mci, `validatePaymentInputsAndOutputs`'s `filterAttestedAddresses` check (validation.js:2630-2641) now fails because `R` is no longer attested — the payment is rejected as invalid, `S`'s inputs remain committed to a now-invalid unit, and `R` never receives usable funds despite `S` having already delivered the private payment chain/consideration to `R` off-DAG.

### Citations

**File:** validation.js (L2033-2042)
```javascript
		case "asset_attestors":
			if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
				return callback("invalid asset in attestor list update");
			if (!objValidationState.assocHasAssetAttestors)
				objValidationState.assocHasAssetAttestors = {};
			if (objValidationState.assocHasAssetAttestors[payload.asset])
				return callback("can be only one asset attestor list update per asset");
			objValidationState.assocHasAssetAttestors[payload.asset] = true;
			validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback);
			break;
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
