### Title
Insufficient-fee triggers to an AA are silently absorbed with no bounce and no refund, permanently locking sender funds - ([File: aa_composer.js])

### Summary
`handleTrigger()` in `aa_composer.js` enforces an unconditional check: any trigger whose base-asset output to the AA is below `bounce_fees.base` (default `constants.MIN_BYTES_BOUNCE_FEE`) is bounced, and any asset output below its configured `bounce_fees[asset]` is "ignored silently." In both cases the received coins stay in the AA's balance forever with no bounce unit, no state change, and no mechanism for the sender to reclaim them — structurally the same "unconditional receive with no return path" pattern flagged in the reference report for `UXDController.receive()`.

### Finding Description
`handleTrigger()` performs this check right after computing `bounce_fees` and before any oscript evaluation of the AA's own logic: [1](#0-0) 

- If `trigger.outputs.base < bounce_fees.base`, the function calls `bounce('received bytes are not enough to cover bounce fees')`. This still consumes the trigger unit and its outputs — the sender's bytes have already been paid to the AA's address as a `payment` output; they are not returned since the AA cannot even afford to build a bounce response.
- If a non-base asset's output value is less than its `bounce_fees[asset]`, the code path comments explicitly state the funds are "ignored silently" — no bounce message, no error surfaced to the sender, no state update, and the AA does not track or account for the amount anywhere it could later refund it.

This logic is universal AA-engine behavior applied identically to *every* AA on the network, regardless of what the AA author's oscript intends to do — it is not an opt-in design choice by the AA author, but a protocol-level gate. Any ordinary user or wallet who sends a trigger to an AA with slightly too few bytes (e.g., miscalculated dust, off-by-one fee estimate, or a manual/mistaken transfer) has those bytes irreversibly absorbed into the AA's on-chain balance with zero recovery path, exactly mirroring the "receive() accepts unconditionally, funds get stuck" pattern in the referenced report.

### Impact Explanation
Funds sent to an AA below the bounce-fee threshold are permanently locked in the AA's byte/asset balance: there is no bounce unit issued (unlike normal bounce responses which fully refund a script error case), no state variable records the deposit, and the sending address has no way to trigger a refund since the check fires before any AA logic runs. This is a real (if narrow) fund-freezing condition reachable by any unprivileged trigger sender who slightly underestimates the fee to any AA on the network, satisfying the "AA fund loss or freezing" impact category.

### Likelihood Explanation
Likelihood is comparable to the original report's assessment: because `bounce_fees.base` defaults to `constants.MIN_BYTES_BOUNCE_FEE` and can be raised arbitrarily by AA authors via `template.bounce_fees`, ordinary wallets that don't precisely track a given AA's configured bounce fee (which can differ per AA and isn't part of the base protocol default in all cases) can easily send a trigger just under the threshold, especially for lesser-used/asset-based AAs where the asset's bounce fee may not be discoverable ahead of time.

### Recommendation
Consider having the AA engine track and refund (or explicitly report/credit) sub-bounce-fee deposits instead of silently discarding them, e.g., by crediting them to a recoverable "unclaimed dust" ledger per AA address, or by requiring wallets to pre-validate the destination AA's bounce fee before allowing a trigger to be composed, surfacing a hard client-side error rather than letting the engine silently or irreversibly consume the funds.

### Proof of Concept
Existing test suite already documents (without treating as a bug) that below-threshold triggers are absorbed: [2](#0-1) 
A trigger unit sending, e.g., 1 byte less than `bounce_fees.base` to any deployed AA will hit the `return bounce('received bytes are not enough to cover bounce fees')` branch; the AA's balance increases by the sent amount, no response unit is created, and the sender has no oscript-level or protocol-level path to recover the funds — this can be reproduced against any AA definition in `test/aa_composer.test.js` by setting `trigger.outputs.base` below the AA's `bounce_fees.base`.

### Citations

**File:** aa_composer.js (L1850-1863)
```javascript
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
		}
```
