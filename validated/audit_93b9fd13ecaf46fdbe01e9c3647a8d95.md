### Title
AA payments to a `spender_attested` asset can permanently freeze user funds if the recipient's attestation is revoked - (File: `aa_composer.js`, `validation.js`)

### Summary
When an Autonomous Agent (AA) responds to a trigger by sending a `spender_attested` custom asset back to the trigger address (e.g. returning collateral, closing a position, refunding a deposit), the AA composer builds and commits the response unit's state changes *before* checking whether the destination address is currently on the asset's attestor whitelist. The attestation check for output addresses is only enforced deep in unit validation. If the recipient's attestation has since been revoked by the asset's attestors, the composed unit fails validation, the entire trigger is reverted/bounced, and the user is left permanently unable to retrieve the asset from the AA — with no way for the AA logic itself to route around the block, mirroring the "blacklisted ERC20 recipient can't close position" bug class.

### Finding Description
Custom assets in ocore can be defined with `spender_attested: true`, requiring all senders **and receivers** to be on a whitelist maintained via `asset_attestors`/`attestation` units, and enforced at validation time: [1](#0-0) 

This check operates on `arrOutputAddresses` — i.e., every address that is the destination of a transfer of this asset, including AA response outputs — and is only evaluated when the unit is validated with `storage.filterAttestedAddresses`, not earlier.

However, when an AA composes its response payment for such an asset, `sendUnit`/`completePaymentPayload` in `aa_composer.js` only loads the asset info via `loadAssetWithListOfAttestedAuthors` (which filters attested *authors*, i.e. the AA itself as sender) and never validates that the recipient output address is attested: [2](#0-1) 

The AA then proceeds to build the full response unit, calls `validateAndSaveUnit`, and only if that fails does it call `bounce(err)`/`revert(err)`, which rolls back *all* state changes for the trigger: [3](#0-2) [4](#0-3) 

Because the bounce fully reverts state (`ROLLBACK TO SAVEPOINT initial_balances`, cleared `stateVars`), an AA holding a user's `spender_attested` asset balance (e.g. as collateral/deposit tracked in AA state vars) can never successfully pay it back to that user once the user's attestation is revoked — every attempt to trigger a withdrawal/close-position response will bounce with "some output addresses are not attested", and the funds remain stuck inside the AA. Unlike the manual wallet composer path in `divisible_asset.js`/`indivisible_asset.js`, which pre-checks `objAsset.spender_attested && objAsset.arrAttestedAddresses.length === 0` for the sender only, there is no equivalent pre-check (or recipient-address parametrization) for AA-composed outputs, and AA oscript logic has no visibility into "will this payment revert due to attestation" before attempting it — it only discovers the failure via a full bounce.

### Impact Explanation
Any AA that uses a `spender_attested` asset for value custody (collateral vaults, lending positions, subscription/escrow AAs) is exposed: if the asset's attestors revoke a user's attestation after the user deposited funds, that user's assets become permanently frozen inside the AA. There is no recovery path via the AA's own logic, since every payment attempt to the user's address will fail the same way and the whole trigger (including any accompanying state bookkeeping) is reverted. This matches the Medium severity of the original report — user funds become inaccessible due to an externally-controlled allow/deny-list mechanism acting on the recipient address, with no fallback recipient mechanism available.

### Likelihood Explanation
This requires an asset defined with `spender_attested: true` being used by an AA to hold user value, and the user's attestation being revoked (a legitimate, expected admin action by the asset's attestors, not an attack) after the AA has already accepted the deposit. Given that `spender_attested` is a documented, commonly available asset feature intended for compliance/KYC-gated assets, and many AA-based financial primitives (vaults, lending, subscriptions) are designed to be asset-agnostic, this scenario is realistic whenever an AA author accepts caller-supplied assets or a compliance-gated asset as collateral.

### Recommendation
- Have the AA composer (`aa_composer.js`, in `completePaymentPayload`/`sendUnit`) proactively check attestation status of every payment output address for `spender_attested` assets before committing state changes, and bounce early with a clear, actionable error rather than deep inside `validateAndSaveUnit` after state has already been computed.
- Expose an oscript-callable check (e.g. extend the existing `attestation[[...]]` formula usage patterns) so AA authors can branch logic (e.g. redirect funds to an alternate address, or keep them queued) when the intended recipient is not attested, instead of unconditionally bouncing the whole trigger.
- Consider allowing partial-success responses (i.e., only the affected payment message fails while other state updates and payments still commit), or documentation/best-practice guidance urging AA authors accepting `spender_attested` assets to record a fallback withdrawal address, analogous to the recommended fix in the original report of allowing a user-specified recipient.

### Proof of Concept
1. Attestor(s) define asset `A` with `spender_attested: true` and initially attest address `U`.
2. AA `Vault` accepts deposits of asset `A` from any attested address and tracks a per-address balance in its state vars, allowing withdrawal via a `withdraw` trigger that sends the balance back to `trigger.address` (standard payment message pattern shown in `test/aa_composer.test.js` deposit/withdraw-style AAs).
3. User `U` deposits asset `A` into `Vault`; `Vault`'s state records `U`'s balance.
4. The asset's attestors revoke `U`'s attestation (publish a new `asset_attestors` list without `U`, or simply never re-attest `U` — attestation is a positive whitelist, so lack of a fresh attestation for `U` in the current list is enough).
5. `U` sends a `withdraw` trigger to `Vault`. `Vault`'s oscript composes a `payment` message with output `{address: trigger.address, amount: balance}` for asset `A`.
6. In `aa_composer.js`, `completePaymentPayload` builds this payload without checking `U`'s current attestation (`aa_composer.js:1323-1344`), the unit is submitted to `validateAndSaveUnit`.
7. `validatePaymentInputsAndOutputs` (`validation.js:2630-2642`) finds `U` is not in `arrAttestedOutputAddresses` and returns `"some output addresses are not attested"`.
8. `sendUnit`'s error handler calls `bounce(err)` (`aa_composer.js:1346-1348`), the whole trigger's state changes revert (`revert`/`bounce`, `aa_composer.js:1759-1783`), and `Vault`'s internal balance for `U` is left unchanged.
9. Every subsequent `withdraw` attempt by `U` will bounce identically for as long as `U` remains unattested — `U`'s asset `A` balance is permanently stuck in `Vault` with no way for the AA logic to reroute the funds.

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

**File:** aa_composer.js (L1671-1688)
```javascript
	function finish(objResponseUnit) {
		if (bBouncing && bSecondary) {
			if (objResponseUnit)
				throw Error('response_unit with bouncing a secondary AA');
			if (!bAddedResponse && objValidationState.logs) // add the logs from the final bouncing unit
				arrResponses.push({ logs: objValidationState.logs });

			if (typeof error_message === 'string') {
				error_message = { message: error_message };
			}

			let errorObj = { address };
			if (error_message.address) {
				errorObj.next = error_message;
			} else {
				errorObj = { ...errorObj, ...error_message };
			}
			return onDone(null, errorObj);
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
