### Title
Payments to a non-attested output address permanently freeze AA state and funds for `spender_attested` assets - ([File: aa_composer.js])

### Summary
The external report describes an ETH-recovery function that unconditionally pushes funds to a recipient address; if that address is "blacklisted" by an external token/contract, the push reverts and the funds (and any logic depending on that transfer succeeding) become permanently stuck — a DoS/loss-of-funds bug rooted in an unconditional payment to an address whose "eligibility" is controlled by a third party outside the sender's control.

The closest reachable analog in `ocore` is an Autonomous Agent (AA) that pays out a `spender_attested` asset to `trigger.address` (or any other address it doesn't fully control, e.g. an order-book counterparty, a withdrawal recipient, etc.). Whether an address is "attested" is controlled entirely by the asset's designated attestor(s), exactly like an ERC-20 blacklist is controlled by the token issuer. If the attestor never attests the recipient (the on-chain equivalent of a "blacklisted" address), the whole response unit fails atomic validation and the AA permanently cannot deliver that payment — while all of the AA's other unrelated state changes in the same message array are rolled back too, because AA response units are validated/saved atomically.

### Finding Description
When an AA composes a `payment` message for a `spender_attested` asset, `validatePaymentInputsAndOutputs` requires **every output address** to be attested by the asset's attestor list: [1](#0-0) 
This check is unconditional and outside the AA's control — attestation is granted only by the addresses listed in `objAsset.arrAttestorAddresses`/`asset_attestors`, which the AA author cannot force: [2](#0-1) 

After an AA's trigger handling assembles its response messages, they are turned into a real unit and passed through full protocol validation (`validateAndSaveUnit` → `validation.validate`). Any failure there (e.g. "some output addresses are not attested") is surfaced as `ifUnitError`, which propagates back up and forces the AA to `bounce()`/`revert()` instead of completing: [3](#0-2) [4](#0-3) 

Because AA execution is atomic — a failed response causes a full `revert()` that rolls back all state changes made in that trigger, and re-runs as a `bounce()` that can only return the originally received asset back to `trigger.address` minus fees — any AA logic that unconditionally pays a `spender_attested` asset out to an address that will never be attested can never successfully deliver that asset. Every attempt costs bounce fees and reverts state, exactly mirroring the reported bug class: an output-address property that the sender doesn't control (blacklist vs. non-attestation) unconditionally blocks a push payment and DoS's the flow that depends on it.

### Impact Explanation
Any AA design that pays a `spender_attested` asset to a user-supplied or counterparty address (common in AA marketplaces, escrows, order-book exchanges, or asset-distribution AAs) can have its withdrawal/payout logic permanently frozen for any address the attestor doesn't attest. Because the failure is atomic, it doesn't just block that single output — it reverts the entire response unit, including any other unrelated state updates bundled in the same trigger response (e.g., balance bookkeeping, fee collection, order matching state), so legitimate users interacting through the same trigger chain can also be blocked. This matches the "AA fund loss or freezing" impact bar: funds credited to a particular internal balance can become permanently unwithdrawable if the intended recipient is never attested, and repeated attempts burn bounce fees without resolving the freeze.

### Likelihood Explanation
This requires an AA to use a `spender_attested` asset and unconditionally send it to an externally-influenced address (e.g., `trigger.address`) without checking attestation status first. This is a realistic and even encouraged pattern for restricted/whitelisted-asset AAs (KYC'd tokens, regulated assets) — the asset type exists specifically to support such use cases, and the ojson samples in this repo show AAs freely forwarding to `trigger.address` without any attestation pre-check (e.g. `test/samples/order_book_exchange.oscript`, `test/samples/create_an_asset.oscript`). Any AA author combining `spender_attested` assets with such a pattern is exposed; the attestor (a third party) fully controls whether the DoS is triggered, with no way for the AA or the user to force delivery.

### Recommendation
- AAs that pay out `spender_attested` assets should first verify attestation of the payout address via a getter/state check before committing to the payment, and provide an alternative recovery path (e.g., allow the balance to be claimed to a different, attested address) if attestation is missing.
- Consider decoupling delivery from state transition so that a failed attestation check does not roll back unrelated state (e.g., record a "pending payout" and let the recipient claim once attested, instead of unconditionally pushing).
- Document for AA authors that `spender_attested` assets can render unconditional output-address payments un-deliverable indefinitely, requiring escrow/pull-based patterns rather than push-based transfers to arbitrary trigger addresses, mirroring the "pull over push" mitigation recommended in the original report.

### Proof of Concept
1. Issuer defines asset `A` with `spender_attested: true` and attestor `X`.
2. An AA is deployed whose payout logic (analogous to `test/samples/order_book_exchange.oscript`'s "withdraw funds" case) sends asset `A` directly to `trigger.address` on request:
```
{
  app: 'payment',
  payload: {
    asset: "{trigger.data.asset}",
    outputs: [{ address: "{trigger.address}", amount: "{trigger.data.amount}" }]
  }
}
``` [5](#0-4) 
3. A user's internal balance is credited with asset `A` (e.g., via a swap or deposit), but attestor `X` never attests that user's address.
4. When the user triggers the withdrawal, `validatePaymentInputsAndOutputs` rejects the output with `"some output addresses are not attested"`: [1](#0-0) 
5. `validateAndSaveUnit`'s `ifUnitError` fires, the AA calls `bounce()`, and the user's credited balance can never be withdrawn — permanently frozen unless the attestor changes their mind, which the AA/user cannot compel: [3](#0-2)

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

**File:** aa_composer.js (L1759-1798)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
		/*
		conn.query("ROLLBACK", function () {
			conn.query("BEGIN", function () {
				// initial AA balances were rolled back, we have to add them again
				if (!fPrepare)
					fPrepare = function (cb) { cb(); };
				fPrepare(function () {
					updateInitialAABalances(function () {
						console.log('done revert: ' + err);
						bounce(err);
					});
				});
			});
		});*/
	}
```

**File:** aa_composer.js (L1800-1837)
```javascript
	function validateAndSaveUnit(objUnit, cb) {
		var objJoint = { unit: objUnit, aa: true, aa_mci: mci };
		validation.validate(objJoint, {
			ifJointError: function (err) {
				throw Error("AA validation joint error: " + err);
			},
			ifUnitError: function (err) {
				console.log("AA validation unit error: " + err);
				return cb(err);
			},
			ifTransientError: function (err) {
				throw Error("AA validation transient error: " + err);
			},
			ifNeedHashTree: function () {
				throw Error("AA validation unexpected need hash tree");
			},
			ifNeedParentUnits: function (arrMissingUnits) {
				throw Error("AA validation unexpected dependencies: " + arrMissingUnits.join(", "));
			},
			ifOkUnsigned: function () {
				throw Error("AA validation returned ok unsigned");
			},
			ifOk: function (objAAValidationState, validation_unlock) {
				if (objAAValidationState.sequence !== 'good')
					throw Error("nonserial AA");
				validation_unlock();
				objAAValidationState.bUnderWriteLock = true;
				objAAValidationState.conn = conn;
				objAAValidationState.batch = batch;
				objAAValidationState.initial_trigger_mci = mci;
				objAAValidationState.bDryRun = trigger_opts.bDryRun;
				writer.saveJoint(objJoint, objAAValidationState, null, function(err){
					if (err)
						throw Error('AA writer returned error: ' + err);
					cb();
				});
			}
		}, conn);
```

**File:** test/ojson.test.js (L1256-1279)
```javascript
					cases: [
						{ // withdraw funds
							if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND trigger.data.amount <= var[$key]
				}`,
							messages: [
								{
									app: 'payment',
									payload: {
										asset: "{trigger.data.asset}",
										outputs: [
											{address: "{trigger.address}", amount: "{trigger.data.amount}"}
										]
									}
								},
								{
									app: 'state',
									state: `{
							var[$key] = var[$key] - trigger.data.amount;
						}`
								}
							]
						},
```
