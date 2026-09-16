### Title
Asset `spender_attested` denial-of-attestation lets a definer/attestor freeze counterparty funds in an AA — same bug class as "lender refuses to be repaid" - (File: `validation.js`, `storage.js`)

### Summary
An asset can be defined with `spender_attested: true`, in which case both sender and recipient addresses of every transfer must be attested by the asset's `attestors` list, and this attestor list can be freely rewritten at any time by the asset's `definer` via an `asset_attestors` message. Exactly like a USDC-style blacklist, a party that controls the attestor list (e.g., the "lender" side of an AA-based lending/escrow/collateral contract denominated in this asset) can simply refuse to attest, or later de-attest, the counterparty's address. Because output-address attestation is enforced only at final unit validation and is not checked/guaranteed by the AA composer when it builds a payment, an AA that tries to pay back collateral/funds to that address will always fail validation with "some output addresses are not attested", permanently blocking repayment/refund while the attestor-controlling party can go on to claim the collateral/funds — mirroring the Cooler USDC-blacklist scenario.

### Finding Description
When an asset has `spender_attested = true`, `validatePaymentInputsAndOutputs` requires that every output address of a transfer be attested before the payment is accepted: [1](#0-0) 

Attestation is checked against the current attestor list, and the attestor list is fully mutable by the asset definer through the `asset_attestors` message, checked only against `objUnit.authors[0].address !== objAsset.definer_address`: [2](#0-1) 

`filterAttestedAddresses`/`loadAssetWithListOfAttestedAuthors` compute attestation dynamically from the live `attestations` table at validation time — so a previously-attested address can become "unattested" the moment the controlling attestor stops re-attesting or the definer swaps the attestor set: [3](#0-2) 

Critically, when composing a payment (including from an AA), the code checks only that the *sender/author* is attested — it never verifies the *recipient/output address* is attested before finalizing the payload: [4](#0-3) [5](#0-4) 

The AA composer's own payment-completion logic (`aa_composer.js`) likewise never consults `spender_attested`/attestation status of the destination address before assembling and signing the response unit: [6](#0-5) 

So an AA (e.g., a lending contract) that is supposed to unconditionally return collateral/repay a counterparty in a `spender_attested` asset will compose and sign a unit whose payment message the network will then reject at `validatePaymentInputsAndOutputs` because the recipient isn't attested — the AA has no way to detect this in advance and no fallback path other than the generic bounce logic, which only fires on synchronous formula errors, not on this after-the-fact unit-validation rejection.

### Impact Explanation
This reproduces exactly the "lender can liquidate/harm the borrower by refusing to be repaid" bug class from the Cooler report, but inside ocore's native asset system: a counterparty who is (or controls) the definer/attestor of a `spender_attested` asset used as the settlement currency of an AA (lending, escrow, marketplace, payment-channel, etc.) can unilaterally and irrevocably prevent that AA from ever paying them back their collateral, refund, or share of funds, by declining/removing their own attestation. This is a concrete "AA fund loss or freezing" — funds intended for the counterparty become permanently stuck in the AA (or subject to being claimed by the attestor-controlling party per the AA's own liquidation/expiry logic), with no recourse for the victim since attestation status is entirely at the discretion of the adversary and is re-evaluated fresh at every validation.

### Likelihood Explanation
Any AA author who builds a lending/escrow/marketplace-style contract can choose (or be tricked into using) a `spender_attested` asset, and any user/party who is also the asset's definer or one of its attestors can trigger this at will, at zero cost, at any time by omitting or revoking attestation for the victim's address. No special privileges beyond being definer/attestor of the asset are required — a role that's easy to reserve for oneself when creating an asset used inside a financial AA.

### Recommendation
- Do not treat `spender_attested` output-address checks as safe to skip during AA/wallet payment composition; if a recipient cannot be verified as currently attested, the composer should refuse to build the payment (fail fast) rather than let the AA sign and try to send funds it cannot successfully deliver.
- For AA-based financial contracts (documented example: lending/collateral, escrow, payment channels), warn/require that settlement assets not have `spender_attested = true` unless attestor governance is decentralized/immutable, since a definer-controlled attestor list is functionally equivalent to a token blacklist.
- Consider allowing an AA to detect and bounce cleanly (refunding via a fallback path, e.g. returning `base` fees or reverting all state) when a composed payment would fail attestation checks, instead of only handling formula-time bounces.

### Proof of Concept
1. Attacker defines an asset `X` with `spender_attested: true`, `attestors: [attackerAttestorAddr]`, and becomes the AA counterparty ("lender") in a lending/escrow AA that accepts `X` as collateral or repayment currency and is programmed to pay back `X` to the borrower on repayment/expiry.
2. Attacker (as attestor/definer) never attests the borrower's address, or attests it once and later publishes a new `asset_attestors` message via `validateAttestorListUpdate` removing the borrower (`validation.js:2829-2847`).
3. Borrower triggers the AA's repayment/refund logic; the AA composes a `payment` message sending `X` to the borrower's address without ever checking recipient attestation (`aa_composer.js:1323-1344`, `divisible_asset.js:245-250`).
4. The resulting unit is broadcast and rejected by every node during `validatePaymentInputsAndOutputs` with `"some output addresses are not attested"` (`validation.js:2630-2641`), so the payment never lands; the borrower's funds/collateral remain stuck in (or are later swept by) the AA, matching the impact of the original "lender refuses to be repaid" finding.

### Citations

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

**File:** validation.js (L2829-2847)
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

**File:** aa_composer.js (L1323-1344)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
					completePaymentPayload(payload, 0, function (err) {
						if (err)
							return cb(err);
						addOutputAddresses(payload.outputs);
						if (payload.outputs.length > 0) // send-all output might get removed while being the only output
							try {
								completeMessage(message);
							}
							catch (e) {
								return cb("completeMessage failed: " + e.toString());
							}
						cb();
					});
				});
```
