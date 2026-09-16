### Title
Payment to a single non-attested (or de-attested) output address causes an entire multi-recipient payment message — and, in an AA chain, the whole trigger response — to be rejected, freezing funds intended for unrelated, legitimate recipients - (File: validation.js)

### Summary
`ocore` supports `spender_attested` assets, whose transfer rule requires that **every** output address of a payment message be currently attested by a trusted attestor. This check is enforced atomically for the whole payment message: if any single output address in the message is not attested, the entire message (and therefore the entire unit) is rejected, not just the transfer to that one address. [1](#0-0) 

### Finding Description
`validatePaymentInputsAndOutputs` collects all `arrOutputAddresses` in a payment message and, for `spender_attested` assets, calls `storage.filterAttestedAddresses` to check which of them are currently attested. If the count of attested addresses does not equal the total number of output addresses, the **whole payment message fails validation** with `"some output addresses are not attested"`: [1](#0-0) 

Attestation status is not permanent: an address is considered attested only if there is an `attestations` row from a trusted attestor **after** its most recent `address_definition_changes` entry. [2](#0-1) 

This means an address that was previously attested can lose attested status (e.g., after rotating its address definition, or simply because it was never (re-)attested), effectively becoming "blacklisted" from receiving that asset — directly analogous to a USDC/USDT-style blacklist in the reported issue.

The impact of this design becomes a batching hazard in Autonomous Agents (AAs). An AA composes a single response unit that can bundle payment outputs to many unrelated addresses in one `payment` message: [3](#0-2) 
If that message pays a `spender_attested` asset to multiple recipients (e.g., a payout/liquidation/distribution AA), and **just one** recipient is not attested, `validateAndSaveUnit` fails for the whole unit, `sendUnit` calls `bounce(err)`: [4](#0-3) 

Because the AA composer processes triggers atomically and can chain to secondary AAs, a bounce deep in the chain causes the **entire chain of state changes to be rolled back** via `revert()`, not just the offending message: [5](#0-4) [6](#0-5) 

This is architecturally the same bug class as the reported Solidity issue: a batch/loop operation that distributes funds to multiple parties fails entirely because of one party's transfer-blocking condition (blacklist vs. non-attestation), penalizing all the other, unrelated, legitimate recipients in the same operation.

### Impact Explanation
An AA author (or a protocol built on ocore, e.g. a lending/distribution/liquidation AA) that uses a `spender_attested` asset and pays multiple recipients (creditors, LPs, users) in a single payment message is exposed to a denial-of-service: if any one recipient's attestation lapses (attestor revokes/changes list, or the recipient rotates its address definition without being re-attested), the AA response bounces and none of the other, unaffected recipients receive their funds either. Depending on how the AA is written, this can:
- Freeze funds for all recipients in that batch until the blocked address becomes attested again or is removed from the payout list (which the AA may not be able to do autonomously, since it cannot exclude the recipient on the fly without a redesign),
- Cause repeated bounces / lost bounce fees each time the same trigger or scheduled payout attempts to execute, or
- Cascade a revert up a chain of secondary AAs, undoing unrelated state changes and freezing funds/logic across a multi-AA workflow.

This matches the "AA fund loss or freezing" impact category.

### Likelihood Explanation
This requires the ocore ecosystem's `spender_attested` asset feature to be in use by an AA that batches distributions to multiple recipients in a single payment message — a plausible and even encouraged pattern for gas/size efficiency. No adversarial validator or node behavior is needed; a normal attestor rotating its trust list, or a normal user rotating their address definition without immediately re-attesting, is sufficient to trigger the freeze. The trigger conditions are entirely within reach of unprivileged users and asset issuers/attestors, matching the required "unprivileged unit poster / AA trigger sender / asset issuer" reachability.

### Recommendation
- Document and strongly discourage batching payouts to multiple independent recipients of a `spender_attested` asset within a single AA payment message; instead, AAs should split such payouts into per-recipient messages/units (or per-recipient triggers) so that one address's attestation failure cannot block payouts to others.
- Consider changing the protocol-level validation to allow partial success for non-critical distributions, or provide an explicit mechanism (e.g., a "skip malformed output, redirect to fallback address" pattern) so that oscript AA authors can defensively guard against a single blocked recipient poisoning an entire batch, similar to the report's suggested escrow/failsafe pattern.
- At minimum, expose to AA authors (via getters, e.g. an `is_attested` check) the ability to pre-check each output address's attestation status before constructing the payment message, so the AA logic itself can exclude/queue non-attested recipients rather than relying on validation to reject the whole message.

### Proof of Concept
1. Define an asset `A` with `spender_attested: true` and attestor `X`. [7](#0-6) 
2. Deploy an AA `Distributor` whose response, on trigger, sends asset `A` to a fixed list of output addresses `[R1, R2, R3]` in a single `payment` message (this is a normal oscript pattern, see `messages.cases[].messages[].payload.outputs`). [3](#0-2) 
3. `R1`, `R2`, `R3` are attested by `X` initially, so payouts succeed.
4. `R3` rotates its address definition (e.g., changes keys) without asking attestor `X` to re-attest the new definition. Per `filterAttestedAddresses`, `R3` no longer counts as attested because its attestation predates the latest `address_definition_changes` entry. [2](#0-1) 
5. On the next trigger, `Distributor`'s payment message to `[R1, R2, R3]` fails validation entirely (`"some output addresses are not attested"`), even though `R1` and `R2` are still attested and would otherwise receive valid payouts. [1](#0-0) 
6. `sendUnit` receives the validation error and calls `bounce(err)`, discarding the entire response, including payouts owed to `R1` and `R2`. [4](#0-3)

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

**File:** validation.js (L2725-2750)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");

	if (objValidationState.bAA) {
		if (payload.cosigned_by_definer !== false)
			return callback("cosigned_by_definer must be false because AAs can't cosign");
		if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
			return callback("assets issued by AA definer cannot be private or fixed denominations");
	}

	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");
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

**File:** aa_composer.js (L1259-1279)
```javascript
			if (message.app !== 'payment')
				continue;
			var payload = message.payload;
			if (!isNonemptyObject(payload))
				return bounce("payload must be nonempty object");
			if (ValidationUtils.hasFieldsExcept(payload, ['asset', 'outputs']))
				return bounce("unknown fields in payment payload");
			if (!Array.isArray(payload.outputs))
				return bounce("outputs must be array"); // empty array is okay
			if (!payload.outputs.every(o => ValidationUtils.isValidAddress(o.address)))
				return bounce("invalid addresses in outputs");
			if (payload.outputs.some(o => ValidationUtils.hasFieldsExcept(o, ['address', 'amount'])))
				return bounce("unknown fields in outputs");
			if ('asset' in payload && !(payload.asset === 'base' || ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH)))
				return bounce("asset must be a string or omitted");
			// negative or fractional
			if (!payload.outputs.every(function (output) { return (isNonnegativeInteger(output.amount) || output.amount === undefined); }))
				return bounce("negative or fractional amounts");
			// filter out 0-outputs
			payload.outputs = payload.outputs.filter(function (output) { return (output.amount > 0 || output.amount === undefined); });
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

**File:** aa_composer.js (L1743-1757)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
					saveStateVars();
					addUpdatedStateVarsIntoPrimaryResponse();
					onDone(objUnit, bBouncing ? error_message : false);
				}
			);
		});
	}
```

**File:** aa_composer.js (L1759-1783)
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
```
