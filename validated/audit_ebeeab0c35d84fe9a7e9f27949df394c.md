### Title
Spender-attested assets can be permanently frozen once an issuer changes the attestor list or an attestor revokes attestation - ([File: validation.js])

### Summary
This is the same bug class as the reported `PayoutManager` issue: an eligibility check that was satisfied at the time funds were received is re-evaluated at spend time against externally-mutable state, and no recovery path exists if the check later fails. In ocore, the analog is the `spender_attested` asset feature: transfers of such an asset require every output address to currently be attested by the asset's *current* attestor list, checked fresh on every transfer, with no mechanism to release funds that become un-attestable.

### Finding Description
For assets defined with `spender_attested: true`, `validatePaymentInputsAndOutputs` re-checks attestation of the recipient(s) on **every** transfer, not just at issuance: [1](#0-0) 

The check relies on `storage.filterAttestedAddresses`, which verifies that the address has been attested by one of the asset's `arrAttestorAddresses` after any subsequent address-definition change: [2](#0-1) 

Critically, `arrAttestorAddresses` is not fixed at asset-issuance time — it is the *latest* attestor list found in the `asset_attestors` table as of `last_ball_mci`, i.e. the asset definer can change the attestor list at any time via a new `asset_attestors` message: [3](#0-2) 

Consequently, a holder who received the asset while validly attested by attestor A can lose the ability to move those funds if the definer later swaps the required attestor list (e.g., to attestor B), or if attestor A never issues (or later withdraws relevance of) an attestation recognized by the new list. Since the check is applied to `arrOutputAddresses` on the transfer itself — meaning the holder must be attested by the *current* list at the moment they try to spend — a holder whose attestation status becomes stale/invalid after receiving the asset has no way to move the funds anywhere, including back to themselves under a new definition, because every candidate output address is subject to the same current-attestor-list check. There is no analog of a "revoke and return to originator/definer" mechanism (as introduced in `PayoutManager`'s PR 36 `revokePayout`) in ocore to rescue funds under a `spender_attested` asset once attestor conditions can no longer be met.

### Impact Explanation
This causes concrete freezing of investor/holder funds: a legitimately-issued asset balance becomes permanently unspendable once eligibility (attestation) determined by the asset definer's mutable attestor list turns unfavorable for a given address, with no protocol-level recovery. This matches the "Medium Risk" impact category of the original report (loss/freezing of funds due to a point-in-time eligibility check being re-validated later against changed state), scoped here to `validatePaymentInputsAndOutputs` / `storage.filterAttestedAddresses` / `readAsset`'s attestor-list resolution rather than to a privileged actor.

### Likelihood Explanation
Likelihood is realistic in any deployment using `spender_attested` assets (a supported first-class feature of the protocol, exercised via `asset` and `asset_attestors` messages by any asset issuer) where the issuer rotates attestors or an attestor's attestation criteria change over time — a normal compliance/KYC-style operational pattern, exactly mirroring the AML-score-drift example in the source report.

### Recommendation
Consider one of:
- Freeze the attestor list used for spend-time re-validation to the list that was in effect when the specific outputs were created (so attestation is checked once, at receipt, not on every subsequent transfer), or
- Add a protocol-level fallback allowing the asset definer to recover/redirect balances of addresses that fail spender-attestation to a designated recipient (mirroring `PayoutManager`'s `revokePayout` semantics), instead of leaving the funds permanently unspendable.

### Proof of Concept
1. Definer issues asset `X` with `spender_attested: true` and attestor list `[A]`.
2. Attestor `A` attests holder `H`; `H` receives `X` and can transfer it (passes `filterAttestedAddresses` check in `validatePaymentInputsAndOutputs`, `validation.js#2630-2642`).
3. Definer posts a new `asset_attestors` message for asset `X` naming attestor list `[B]` (allowed at any time per `storage.js#1917-1946`, which always resolves to the latest list).
4. `H` was never attested by `B`. Any subsequent attempt by `H` to transfer their existing `X` balance to any address (including back to themselves) fails `filterAttestedAddresses`/`evaluateAssetCondition`, because `arrAttestorAddresses` now resolves to `[B]` and `H` is not in the attestations table under `B`.
5. `H`'s previously-valid balance of asset `X` is now permanently locked with no path in ocore to recover it.

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
