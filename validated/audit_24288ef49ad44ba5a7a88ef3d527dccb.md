### Title
AA-based lending/escrow contracts can be forced into permanent repayment failure via `spender_attested` asset output checks - (File: `validation.js`)

### Summary
Any oscript Autonomous Agent (AA) that implements a Cooler-style lending or escrow flow — accepting a debt/collateral asset and later paying it back to a lender-supplied address — is vulnerable to the same "receiver blacklists itself" attack described in the Cooler report if the debt asset is defined with `spender_attested: true`. A malicious lender can register (or later remove attestation for) the payout address they specify, causing every AA-generated repayment `payment` message to that address to permanently fail asset validation with `"some output addresses are not attested"`. Because the AA cannot complete the repayment, the loan can never be repaid, letting the lender force a default and seize the collateral, exactly mirroring the External report’s root cause (an uncontrollable, receiver-side condition on the transfer of the repayment asset).

### Finding Description
Assets with `spender_attested: true` require every address in a payment’s output set to be attested by one of the asset’s registered attestors, both for inputs (`validation.js` — output-owner check) and, most importantly, for outputs when the payment is finally validated: [1](#0-0) 

This check applies uniformly to any unit that spends the asset, including units that an AA composes as part of `handleTrigger`/`sendUnit` when it tries to send the asset back to a specific address (e.g. a lender): [2](#0-1) 

The AA composer only checks `spender_attested` for **its own** balance (the AA address) before building the message, and otherwise blindly forwards the payload to the network for full validation: [3](#0-2) 

It does not check that the *destination* address is (and will remain) attested. If it is not, the response unit fails `validatePaymentInputsAndOutputs`'s `spender_attested` output check and the AA response is discarded (the trigger bounces), so state changes (loan repayment bookkeeping) are never committed: [4](#0-3) 

Attestor lists for an asset are freely updatable at any time by the asset definer via `asset_attestors`, and per-address attestation itself is issued by the attestor and can simply never be (re-)granted for a given address: [5](#0-4) [6](#0-5) 

Because attestation status is checked at validation time against the *current* attestor list/attestation records (not fixed at loan creation time), a lender who is the asset's attestor (or who colludes with the attestor) can withhold or revoke attestation for their own designated payout address after receiving collateral, at will.

### Impact Explanation
For any AA-implemented lending/escrow scheme built on a `spender_attested` debt asset (a documented, supported asset feature in ocore), a dishonest lender/counterparty can:
1. Accept the loan/deposit, specifying (or later un-attesting) their own repayment address.
2. Ensure the address that must receive repayment is not attested.
3. Force every repayment attempt by the borrower to fail validation and bounce, since the AA cannot skip the transfer-condition check on its own outputs.
4. Trigger the AA’s deadline/default logic to seize the collateral, exactly as in the Cooler exploit — the borrower loses collateral through no fault of their own, while the lender pays nothing back.

This is a fund-loss/freezing vulnerability reachable by an ordinary AA trigger sender (the borrower) and an ordinary asset issuer/attestor/counterparty (the lender), without any privileged network role, matching the class of "AA fund loss or freezing" bugs in scope.

### Likelihood Explanation
Likelihood is contingent on AA authors choosing a `spender_attested` asset as the debt/settlement token for lending-style AAs, which is a legitimate, supported design ocore explicitly provides (`spender_attested`, `asset_attestors`). Given the identical Cooler precedent (in-scope real-world exploit pattern), any lending/escrow AA using such an asset for repayment is directly exposed. The attacker (lender) fully controls whether their receiving address is attested, requiring no privileged system access — only ordinary posting of `asset_attestors`/`attestation` messages, which any address can do for assets it controls.

### Recommendation
- AA framework enhancement: when composing AA payment messages, `aa_composer.js` should pre-check that all non-AA output addresses of a `spender_attested` asset payment are currently attested (similar to the existing self-balance check) and bounce with a clear, actionable error *before* committing any dependent state changes, so an AA author can detect and handle this condition explicitly (e.g., route to a fallback/dispute path) instead of silently failing to update loan state.
- Document the risk clearly for AA developers: never let a counterparty control (or later revoke) attestation of the specific address to which contractually-owed repayments must be sent; instead let the *payer* (borrower) choose a valid attested destination, or avoid combining `spender_attested` debt tokens with hard on-chain default/liquidation deadlines that are irreversible once triggered.
- Consider adding an oscript-level function (e.g., `is_spendable_by`/`is_attested`) that lets AA logic check attestation status of an address at message-build time so the AA can gracefully branch (refund vs. proceed) rather than unconditionally bouncing.

### Proof of Concept
1. Definer/lender `L` issues asset `A` with `spender_attested: true`, `attestors: [L]` (`L` acting as attestor), via an `asset` message validated per `validation.js:2725-2827` and `checkAttestorList`.
2. Borrower `B` triggers a lending AA, sending collateral and receiving debt asset `A` from `L` (or borrowing `A` directly) — normal flow succeeds because `L` attests `L`'s own address (or any address `L` wants to receive from) at loan-issuance time.
3. Before the repayment deadline, `L` (as definer of `A`) posts a new `asset_attestors` message removing/replacing the attestor list, or simply never attests the address `L` designates for receiving repayment (`validateAttestorListUpdate`, `validation.js:2829-2848`).
4. Borrower `B` triggers the lending AA’s `repay` message, which composes a `payment` message with asset `A` output to `L`’s address (`aa_composer.js:1312-1344`).
5. During validation of the generated response unit, `validatePaymentInputsAndOutputs` calls `storage.filterAttestedAddresses` on the output addresses and finds `L`’s address unattested, returning `"some output addresses are not attested"` (`validation.js:2630-2642`), so the unit is rejected and the AA response bounces, leaving the loan state unrepaid.
6. `B` can never successfully repay; once the AA’s deadline logic fires, `L` claims the collateral for free — reproducing the Cooler "loan defaults if lender is on debt token blacklist" impact on ocore’s AA/asset framework.

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

**File:** aa_composer.js (L1312-1344)
```javascript
				var payload = message.payload;
				if (payload.asset === 'base')
					delete payload.asset;
				var asset = payload.asset || null;
				if (asset === null) {
					if (objBasePaymentMessage)
						return cb("already have base payment");
					objBasePaymentMessage = message;
					// we'll add output addresses later, after possibly removing a send-all output
					return cb(); // skip it for now, we can estimate the fees only after all other messages are in place
				}
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
