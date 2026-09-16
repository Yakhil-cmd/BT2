### Title
AA-based lending/escrow logic that pays a debt asset directly to a stored counterparty address can be permanently frozen if the asset is `spender_attested`/has a `transfer_condition` and the counterparty later fails that check - ([File: validation.js], [File: aa_composer.js])

### Summary
`ocore` lets an asset definer create assets that are gated by `spender_attested` (output address must be attested by a trusted attestor) or by an arbitrary `transfer_condition` formula. Both are compliance/whitelist mechanisms functionally equivalent to a "blacklist" token like USDC/Tether: a specific recipient address can be permanently disallowed from receiving the asset. Any AA that implements Cooler-style logic ("send the debt asset directly to the stored lender/counterparty address as part of a `repay`-like function") inherits the exact same failure mode as the reported bug: if the hard-coded recipient later fails the transfer check, the payment message — and therefore the whole AA response unit — is rejected, the AA bounces, and no state update (e.g., "loan repaid", "collateral released") ever happens.

### Finding Description
When a payment message spends a `spender_attested` asset, `validatePaymentInputsAndOutputs` requires **every output address** to be attested at validation time: [1](#0-0) 
and/or requires the asset's `transfer_condition` formula to evaluate true for the transfer: [2](#0-1) 

These checks are enforced unconditionally on the payment message and there is no way to skip or override them once posted — if they fail, `validatePaymentInputsAndOutputs` returns an error and the whole unit is rejected.

When an Autonomous Agent composes such a payment as part of its response (for example, an AA implementing a Cooler-like `repay` message that sends the debt asset straight to `var['lender_' + loan_id]`), the composer validates and saves the generated response unit here: [3](#0-2) 
If `validateAndSaveUnit` fails (which it will if the lender/counterparty address is not attested, or fails `transfer_condition`), the AA calls `bounce(err)`: [4](#0-3) 
`bounce()` discards the pending state-variable and balance changes for that trigger: [5](#0-4) 
so any accounting update that was supposed to record the repayment / release collateral is rolled back, exactly like the external report's `repay()` reverting entirely because `debt.transferFrom(msg.sender, loan.lender, repaid)` fails.

Crucially, attestation status is not static: it is evaluated against `attestations` as of `last_ball_mci`, and is invalidated once the address's definition changes after the attestation: [6](#0-5) 
So a lender/counterparty address that was validly attested when a loan/escrow was created can later become "un-attested" (attestor revokes, or the recipient rotates its address definition), permanently blocking any AA logic that hard-codes payment to that specific address.

### Impact Explanation
Because AAs have no way to catch a downstream payment failure other than bouncing the entire trigger, and bouncing discards all intended state changes, any borrower/user trying to complete a "repay"-like action in an AA built on a `spender_attested` or `transfer_condition`-restricted debt asset can be permanently unable to complete that action once the payee address stops satisfying the condition. Collateral or other value already committed/locked in the AA's state can never be released through the normal code path, resulting in AA fund freezing — matching the accepted "AA fund loss or freezing" impact category.

### Likelihood Explanation
This requires an asset issuer to create a `spender_attested` or `transfer_condition`-gated asset (a supported, first-class asset feature) and an AA author to build lending/escrow-style logic that pays that asset directly to a stored counterparty address instead of using a pull/withdraw pattern. Given `spender_attested`/`transfer_condition` assets are explicitly designed for KYC/compliance-style tokens (the direct analog of USDC/Tether blacklists), and direct-push payment to a stored address is a natural, common implementation pattern for AA authors replicating lending protocols, the likelihood of this pattern being used is realistic, though it depends on specific AA design choices rather than being exploitable in the base protocol without an AA.

### Recommendation
- Document, for AA authors building lending/escrow/repay-style contracts, that payments in restrictable assets (`spender_attested`, `transfer_condition`) must not be sent unconditionally to a hard-coded counterparty address inside a single atomic AA response.
- Prefer a pull-based accounting pattern: credit the counterparty's balance in AA state variables and let them withdraw via their own trigger (mirroring the standard smart-contract mitigation of "store to a withdrawable balance instead of push-transferring"), so a single recipient's compliance failure cannot bounce/roll back the whole operation or permanently freeze the payer's collateral.
- Consider allowing AA logic to test transferability/attestation of a target address before attempting the payment (e.g., via a getter/oscript primitive) so the AA can branch to a fallback path instead of unconditionally bouncing.

### Proof of Concept
1. Attestor `A` attests lender address `L` for asset `X` (`spender_attested: true`).
2. An AA `Cooler` is deployed that, on trigger `repay`, looks up `var['lender']` = `L` and sends asset `X` to `L` as repayment, then updates state (`var['loan_amount'] -= repaid`, releases collateral in bytes to the borrower) in the same response unit.
3. Later, `L`'s address definition changes (e.g., key rotation) or attestor `A` stops attesting `L`. Per `filterAttestedAddresses`, `L` is no longer considered attested as of the new `last_ball_mci`.
4. A borrower posts a `repay` trigger to `Cooler`. The AA composes the payment message paying `X` to `L`, then `validateAndSaveUnit` fails with `"some output addresses are not attested"` (from `validatePaymentInputsAndOutputs`).
5. `aa_composer.js` calls `bounce(err)`, discarding all state changes; the loan is not marked repaid and collateral is not released. Every subsequent `repay` trigger fails identically, permanently freezing the borrower's collateral in the AA.

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

**File:** validation.js (L2643-2658)
```javascript
					function(cb){
						var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
						if (!arrCondition)
							return cb();
						Definition.evaluateAssetCondition(
							conn, payload.asset, arrCondition, objUnit, objValidationState, 
							function(cond_err, bSatisfiesCondition){
								if (cond_err)
									return cb(cond_err);
								if (!bSatisfiesCondition)
									return cb("transfer or issue condition not satisfied");
								console.log("validatePaymentInputsAndOutputs with transfer/issue conditions done");
								cb();
							}
						);
					}
```

**File:** aa_composer.js (L910-925)
```javascript
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
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
