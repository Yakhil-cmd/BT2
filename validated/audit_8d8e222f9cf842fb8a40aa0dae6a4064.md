I have sufficient evidence to construct the analog finding. The mapping is confirmed: `spender_attested` asset condition in `validatePaymentInputsAndOutputs` requires **all** output addresses to currently be attested at validation time — this is checked fresh every time a unit spends the asset (not just at issuance), and an AA's payout logic is immutable, so if an intended recipient loses attestation (e.g. via address key rotation invalidating prior attestation, or the attestor simply withdrawing/never renewing an attestation), any AA payment message sending that asset to that address will permanently fail validation and bounce — exactly analogous to the USDC-blacklist `recoverERC20` freeze in the report.

### Title
Autonomous Agent payouts of `spender_attested` assets permanently bounce and lock funds if the recipient address loses attestation - ([File: validation.js])

### Summary
An AA (Autonomous Agent) that pays out a `spender_attested` asset to a fixed/derived recipient address (e.g. `trigger.address`, or an address stored in AA state) has no fallback if that recipient's attestation is later invalidated. Attestation status is re-checked at validation time for every payment, not just once at issuance, so a previously-valid recipient can become permanently unable to receive the asset — freezing the AA's holdings of that asset with no way to redirect payment to another address, since the AA's oscript logic is immutable.

### Finding Description
When an asset is defined with `spender_attested: true`, every payment output of that asset must belong to an address currently attested by one of the asset's trusted attestors, verified via `storage.filterAttestedAddresses` inside `validatePaymentInputsAndOutputs`: [1](#0-0) 

Critically, `filterAttestedAddresses` only counts an attestation as valid if it was issued *after* the most recent address-definition change (key rotation) for that address: [2](#0-1) 

This means an address that was attested in the past becomes "unattested" the moment it changes its key (address definition), a perfectly normal, unprivileged, self-initiated action any wallet owner can perform for security hygiene. This is functionally equivalent to an address getting "blacklisted" for the asset: subsequent payments of that asset to this address fail validation with `"some output addresses are not attested"`, exactly as USDC-style blacklisting causes `IERC20.safeTransfer` to revert in the reported bug.

An AA (Autonomous Agent) that holds and is programmed to pay out such an asset — e.g. refunding `trigger.output[[asset=$asset]]` back to `trigger.address`, or paying a stored recipient address in state (a common pattern seen throughout the AA sample scripts, e.g. `test/samples/fundraising_proxy.oscript` and `test/samples/51_attack_game.oscript`) — composes and validates its response unit through `aa_composer.js`'s `sendUnit`, which relies on the same `validatePaymentInputsAndOutputs` check when the response unit is saved: [3](#0-2) 

If validation fails (`validateAndSaveUnit` returns an error), the AA response is bounced: [4](#0-3) 

Because AA bytecode/oscript logic is immutable and typically hardcodes the payout address as `trigger.address` or a state variable with no alternate-recipient parameter, there is no way for the AA (or anyone) to redirect the payout to a different, still-attested address. Every future trigger that attempts to pay this asset to the now-unattested address will bounce identically, permanently trapping the asset balance inside the AA — mirroring the described `recoverERC20`/USDC-blacklist freeze, where the recipient is fixed and unauthorizable to change.

### Impact Explanation
Any `spender_attested` asset balance held by an AA that is programmed to pay back to the depositor's address (or any other AA-selected address) can become permanently frozen if that recipient's attestation lapses due to a legitimate address-definition change (key rotation) or attestor non-renewal — an action fully outside the AA's or the depositor's control once triggered. This is a fund-freezing condition reachable by an ordinary, unprivileged party (the depositor themselves, by rotating their own keys after depositing but before withdrawal) with no recovery path, matching the "Medium" severity of the original finding (permanent lock of user funds in the contract/AA, no way to recover).

### Likelihood Explanation
This is straightforwardly reachable: any user can (1) send a `spender_attested` asset to an AA that promises to return/pay it back to `trigger.address` (a common, documented AA pattern), then (2) rotate their address's key (perfectly normal wallet operation, e.g. `address_definition_change`) before triggering the payout, invalidating the earlier attestation per the `main_chain_index > IFNULL(...)` check in `filterAttestedAddresses`. The subsequent payout trigger will then always bounce.

### Recommendation
For AAs (and the base `spender_attested` payment-validation logic more broadly), consider allowing/requiring bounced or failed asset payouts due to attestation loss to fall back to a re-triggerable/parameterized recipient, or documenting clearly that AA authors handling `spender_attested` assets must implement an alternate-recipient mechanism (analogous to the report's recommendation to let the recipient supply a beneficiary address) rather than hardcoding a single address that could lose eligibility to receive the asset after funds are already committed to it.

### Proof of Concept
1. Asset issuer defines asset `A` with `spender_attested: true` and an attestor `X`.
2. Attestor `X` attests address `U` (owned by user Alice).
3. Alice deposits asset `A` into an AA whose oscript pays the asset back to `trigger.address` on a later trigger (pattern used in `test/samples/fundraising_proxy.oscript` refund case, `test/samples/51_attack_game.oscript`, etc.).
4. Before triggering the payout, Alice issues an `address_definition_change` for `U` (key rotation) — a routine, unprivileged action.
5. Per `storage.filterAttestedAddresses`, `U`'s earlier attestation from `X` no longer counts because its `main_chain_index` is now `<=` the `address_definition_changes` MCI for `U`.
6. Alice triggers the AA's payout. `aa_composer.js` composes the response payment to `U`; at unit-save time `validatePaymentInputsAndOutputs` runs `filterAttestedAddresses` and finds `U` unattested, returning `"some output addresses are not attested"`.
7. The AA response bounces (`aa_composer.js` lines 1408-1411); the asset `A` balance remains stuck in the AA. Every subsequent trigger by Alice repeats the same bounce — the funds are permanently frozen with no alternate-recipient mechanism available.

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

**File:** aa_composer.js (L1405-1411)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```
