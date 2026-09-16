## Title
AA reward/refund distribution to multiple recipients in one payment message can be permanently griefed if any single recipient loses attestation for a `spender_attested` asset - (File: `validation.js`)

### Summary
Autonomous Agents (AAs) that distribute rewards, refunds, or payouts to several addresses often do so by adding a single `payment` message with multiple `outputs` to their response unit (this is a standard oscript pattern, e.g. `send_all.oscript` / `51_attack_game.oscript`). When the asset being distributed has `spender_attested: true`, `validatePaymentInputsAndOutputs` requires that *every* output address in that payment message be currently attested, otherwise the entire message — and therefore the entire response unit — is rejected.

### Finding Description
In `validation.js`, when a payment moves a `spender_attested` asset, all output addresses must simultaneously pass attestation: [1](#0-0) 

This check is all-or-nothing over the full set of `arrOutputAddresses` in the message — there is no way to partially satisfy it by paying only the still-attested addresses.

When an AA composes its response unit in `aa_composer.js`, all payment outputs for a given asset in a trigger's response are merged into as few messages as possible via `mergeMessagesAndOutputs`, and then the whole unit is validated in one shot with `validateAndSaveUnit`: [2](#0-1) 

If validation fails (e.g. because one of the several reward/refund recipients is no longer attested for the asset — the functional equivalent of a blacklisted USDC address), the AA takes the `bounce(err)` path: [3](#0-2) 

Bouncing discards the computed `objStateUpdate`, reverts to `originalStateVars`, and never calls `updateFinalAABalances`/`addResponse` for the intended payout — instead it (at best) refunds the raw trigger amount back to `trigger.address`. The game-specific state that would normally record "distribution complete" is never written. Because the AA logic is deterministic and re-triggering the same distribution logic reproduces the same set of winner outputs, every subsequent attempt to finalize/distribute produces the same all-or-nothing payment message and bounces the same way as long as any one recipient remains unattested.

### Impact Explanation
This mirrors the reported bug class: a single "poisoned" recipient (here, an address whose attestation was revoked/never granted for a `spender_attested` asset) can permanently block an AA's payout/finalization logic that pushes funds to multiple addresses in one payment message. Since AA state changes are atomic with the response unit, the state never advances past the failing step, and the funds held by the AA for that game/round become stuck — unable to be distributed and unable to let a new round begin if the AA's logic gates further activity on completing the current distribution. This is an AA fund-freezing condition reachable by any ordinary trigger sender/participant, matching the medium-severity impact described in the reference report.

### Likelihood Explanation
This requires the AA to use a `spender_attested` asset for pooled/collective payouts (a recognized oscript pattern for compliance-gated assets) and one recipient to lose attestation between joining/being selected and payout time — plausible for any AA-managed game or pool whose asset issuer can revoke attestation for regulatory/compliance reasons. No special privileges are needed by the address that triggers the AA; the vulnerability is purely a consequence of the all-or-nothing attestation check applied per payment message.

### Recommendation
AA authors distributing funds to multiple parties in assets with `spender_attested`/similar all-or-nothing conditions should avoid merging all payouts into a single payment message that can be blocked by one recipient. Where possible:
- Split payouts into separate payment messages/units per recipient (pull-based claim pattern) so one recipient's condition failure cannot block others.
- At the protocol level, consider allowing partial satisfaction of `spender_attested`/condition checks per-output rather than failing the whole message when any single output address fails attestation, or provide oscript primitives to check attestation status before adding an output so the AA can route around failing recipients instead of bouncing the entire unit.

### Proof of Concept
1. Asset `X` is defined with `spender_attested: true` and an attestor list. [4](#0-3) 
2. An AA-based game accumulates asset `X` from participants and, on finalization, sends a single `payment` message with `outputs` to all N winners.
3. One winner's attestation for asset `X` is revoked (or was never issued) before finalization is triggered.
4. `validatePaymentInputsAndOutputs` computes `arrAttestedOutputAddresses` via `storage.filterAttestedAddresses` and finds its length `!== arrOutputAddresses.length`, returning `"some output addresses are not attested"`. [5](#0-4) 
5. `validateAndSaveUnit` in `aa_composer.js` fails, triggering `bounce(err)`, discarding the finalize-state update. [6](#0-5) 
6. Any subsequent trigger that re-attempts finalization computes the identical set of winner outputs and bounces identically, permanently blocking distribution while the unattested address remains among the winners.

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

**File:** validation.js (L2745-2750)
```javascript
	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");
```

**File:** aa_composer.js (L909-928)
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
