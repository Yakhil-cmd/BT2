### Title
AAs holding a `spender_attested` asset can be permanently unable to pay it out once the recipient's attestation becomes stale via `address_definition_change` - (File: `validation.js`)

### Summary
The external report describes an ERC-20 style blacklist that makes a mandatory refund transfer permanently revert, locking a shared pool's liquidity forever with no fallback claim mechanism. The reachable analog in `ocore` is `spender_attested` assets: an AA (or user) holding such an asset can be permanently blocked from paying it to a specific address once that address's attestation is invalidated by an `address_definition_change`, with no way to recover or reroute the payout, since the validation rule is unconditional and there is no claims/escrow fallback.

### Finding Description
When an asset is defined with `spender_attested: true`, every payment output (and the sender) of that asset must currently be "attested" by one of the asset's attestors, checked in `validatePaymentInputsAndOutputs`: [1](#0-0) 

The "attested" status is computed by `filterAttestedAddresses`, which explicitly invalidates any attestation that predates the address's most recent `address_definition_change`: [2](#0-1) 

This means that if address A was attested at some point, then later posts an `address_definition_change` (e.g. rotates keys, changes to a multisig, or any routine definition update — an entirely normal, single-party, non-malicious action), A's attestation instantly becomes void for that asset. This is the direct analog of "the borrower enters the blacklist": a previously-eligible payee becomes permanently ineligible to receive the asset, and the condition is checked unconditionally on every output at validation time (`validation.js:2632-2641`).

Because this check is enforced deep inside `validatePaymentInputsAndOutputs`/`validatePayment` (also duplicated in the composer helpers for divisible/indivisible assets), any unit — including an AA response unit — that tries to pay this asset to such an address will fail unit validation. For an AA, this failure surfaces as `sendUnit()`'s call into `validateAndSaveUnit` returning an error, which is caught and converted into `bounce(err)`: [3](#0-2) 

`bounce()` discards `objStateUpdate`/any pending state changes for `bAir` runs and, for real triggers, only refunds the *trigger's own* payment (minus bounce fees) back to the trigger address — it does not, and cannot, move the AA's already-held asset balance to anyone else: [4](#0-3) 

So if an AA's business logic (e.g. an escrow/vault/lending-style AA that must return a `spender_attested` collateral/share asset to a specific counterparty address as part of closing out a position, analogous to `closePosition()`/`refundWithCheck()` in the report) is forced to construct that payout, and the recipient's attestation has gone stale due to an `address_definition_change`, then:
- every attempt to trigger that closing logic will validate the response unit, hit "some output addresses are not attested", fail, and bounce;
- the AA's held balance of that asset (belonging economically to the counterparty, analogous to the "LP liquidity") remains stuck in the AA forever, since there is no alternate payout path, no claims[] ledger, and no way for the counterparty to re-attest an address whose definition already changed (the invalidation is retroactive and irreversible for that specific attestation event).

This mirrors the report's root cause precisely: a mandatory, unconditional transfer-eligibility check that can turn permanently false for one specific counterparty after funds are already committed, with the only exit path (a state-changing payout) being unconditionally gated by that check, and no fallback claim/escrow mechanism.

### Impact Explanation
Funds (the `spender_attested` asset balance) held by the AA on behalf of a counterparty become permanently unrecoverable through the AA's normal logic once that counterparty's attestation is invalidated by their own `address_definition_change`. Depending on the AA design, this can freeze a genuine liability of the AA (e.g., collateral, shares, escrowed value) with no recovery path, which is the same class of impact as the original finding — AA fund loss/freezing for the counterparty, and no automatic remediation exists at the protocol layer.

### Likelihood Explanation
This does not require a malicious third party (no "blacklist operator" needed) — it can be triggered by the counterparty's own single, unprivileged, entirely legitimate action: posting an `address_definition_change` for their own address (e.g. routine key rotation) after having been attested and after an AA has already accepted/held the `spender_attested` asset on their behalf. Any AA design that (a) accepts a `spender_attested` asset from users and (b) must later pay that same asset back to the specific triggering/owning address as part of its core state machine (escrow/vault/lending/marketplace patterns) is exposed. This requires no cooperation from the attestor and no unusual conditions beyond normal address-definition management, making it a realistic, low-effort scenario rather than a rare edge case.

### Recommendation
- For AA patterns that hold `spender_attested` assets on behalf of specific addresses, avoid unconditionally gating the *only* payout path on the live attested status of the original owner; instead, allow the AA to route the payout to whatever address is currently controlling the position (which will generally be attested again once accounted for), or maintain an internal `balances`/`claims` ledger in AA state so that a failed automatic payout degrades to a claimable balance rather than causing the whole state transition to bounce.
- Alternatively/additionally, consider not retroactively invalidating attestations across `address_definition_change` for purposes unrelated to double-attestation abuse, or provide attestors/users a straightforward way to re-attest without losing pending entitlements, and document clearly to AA authors that a stale attestation can permanently block state-changing payments so they design an explicit fallback ("claim" message/state) rather than relying on the payment message succeeding unconditionally.

### Proof of Concept
1. Attestor `T` attests address `B` for asset `X` (`spender_attested: true`), stable and before `last_ball_mci`.
2. User `B` sends a unit containing asset `X` (as `spender_attested` output) to AA `V`, where `V`'s logic is designed to eventually pay this exact asset back to `B` (e.g. via a `close`/`withdraw` trigger from `B`), consistent with `validatePaymentInputsAndOutputs`'s output-attestation check.
3. `B` posts an `address_definition_change` for their own address (e.g., routine key rotation), stable and included in a later `last_ball`.
4. Per `filterAttestedAddresses` (`storage.js:1960-1974`), `B`'s earlier attestation from `T` no longer counts because its `main_chain_index` is not greater than that of the `address_definition_change`.
5. `B` (or anyone) sends the trigger to `V` to close out/withdraw the position, causing `V`'s AA logic to build a `payment` message sending asset `X` back to `B`.
6. `sendUnit()` constructs and attempts to save this response unit; `validatePaymentInputsAndOutputs` rejects it with "some output addresses are not attested" (`validation.js:2634-2638`); `validateAndSaveUnit`'s callback error routes into `bounce(err)` (`aa_composer.js:1405-1411`), discarding the state change and leaving `V`'s held balance of `X` untouched.
7. Since `B` cannot retroactively make the old attestation valid again (the invalidation condition is tied to the historical `address_definition_change` MCI), every future retry of step 5 fails identically — `B`'s asset `X` remains permanently stuck in AA `V` with no alternate recovery mechanism in the AA's `messages`/`bounce` logic.

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

**File:** storage.js (L1960-1974)
```javascript
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

**File:** aa_composer.js (L909-945)
```javascript
	var bBouncing = false;
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
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
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
