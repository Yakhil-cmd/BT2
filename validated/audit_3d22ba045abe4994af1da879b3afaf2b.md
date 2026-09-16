### Title
Single non-attested output address blocks an entire merged AA payment message, freezing payouts to all other recipients in the batch - (File: `validation.js`)

### Summary
When an asset has `spender_attested: true`, `validatePaymentInputsAndOutputs` requires that *every* output address in a payment message be on the attested list, or the whole message (and therefore the whole unit) is rejected. Because `aa_composer.js` merges all `payment` messages/outputs for the same asset issued by an AA response into a single payment message (`mergeMessagesAndOutputs`), a single unattested (i.e. "blacklisted"-equivalent) recipient placed in a multi-recipient AA payout will cause the entire response unit to bounce, blocking payment to every other legitimate recipient bundled in that same batch — the same "one bad actor blocks everyone in the queue" pattern as the reported Solidity finding.

### Finding Description
`validatePaymentInputsAndOutputs` enforces the `spender_attested` restriction for the asset's output addresses as an all-or-nothing check: [1](#0-0) 

```
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

If even one address among `arrOutputAddresses` is not attested, `cb("some output addresses are not attested")` is returned, invalidating the whole payment message — regardless of how many *other* addresses in the same message are perfectly valid, attested recipients.

The reachable attack surface is the AA composer, which — when constructing an AA's response unit — merges all `payment` messages for the same asset into a single payment message with a combined `outputs` array: [2](#0-1) 

An AA that pays out to a set of beneficiaries in one trigger response (e.g., a dividend/airdrop/queued-withdrawal-style AA, similar in spirit to `AccountingManager.executeWithdraw`'s queue) will therefore have its individual per-user payment messages merged into one combined message before being validated. Because addresses used as beneficiaries in such an AA are frequently derived from trigger data, an unprivileged AA trigger sender can typically influence which addresses are queued/paid in an AA response.

### Impact Explanation
If the payout asset requires `spender_attested` (a legitimate, protocol-supported asset feature used for compliance-gated assets) and the AA batches multiple recipients' payouts into a single response unit, then a single recipient address that is not attested causes `validatePaymentInputsAndOutputs` to reject the entire merged payment message, bouncing the whole AA response. This denies payout to every other, otherwise-eligible recipient bundled in that same trigger response, and — because the AA state changes for the trigger are rolled back on bounce — can also freeze/undo any related bookkeeping (e.g., decrementing a withdrawal queue, marking shares as redeemed) for all users in the batch, not just the offending one. This is directly analogous to the reported High-severity `executeWithdraw` DoS: an unprivileged party can grief a shared batch of payouts by ensuring one of the batch members fails a global (not per-recipient) validation rule.

### Likelihood Explanation
Exploitability depends on an AA implementation choosing to combine multiple beneficiaries' payouts of a `spender_attested` asset into a single trigger response, and on the trigger sender being able to influence which addresses land in that batch (e.g., by triggering the AA at the right time so an unattested address is queued alongside attested ones). This is a real, supported combination in the protocol (attested assets + AA composer's automatic merging of same-asset outputs), so any AA developer implementing a "queued/batched payout" pattern with an attested asset is exposed. Likelihood is Medium-to-High for AAs that use this specific combination, though it requires a specific AA design choice (batch payouts + attested asset) rather than being universal to all AAs.

### Recommendation
- In `aa_composer.js`, before merging outputs for `spender_attested` assets, pre-filter/validate output addresses against the attestor list and either skip/queue non-attested outputs separately (so they don't poison the whole message) or bounce early with a clear, isolated error that does not entangle unrelated recipients.
- Alternatively, in `validation.js`'s `validatePaymentInputsAndOutputs`, avoid an all-or-nothing check for `spender_attested`; instead, AA-authored payment messages could be discouraged from merging outputs across independent beneficiaries when the target asset is `spender_attested`, or the composer could be changed to keep such outputs unmerged if any single message app-layer semantics depend on address-level authorization.
- Document this composer behavior clearly for AA authors so that queued/batched payout designs perform their own attestation checks per-recipient (e.g., via `is_aa_attested`-style formula checks) before adding a beneficiary to the outputs array, rather than relying on the low-level payment validation to reject the whole batch atomically.

### Proof of Concept
Conceptual PoC (cannot be executed without a running Devin session against the ocore test harness):
1. Define an asset with `spender_attested: true` and register attestors.
2. Deploy an AA that, on trigger, batches payouts to multiple addresses read from data feeds/state vars into separate `payment` app messages for that asset within one response (e.g., a "distribute dividends to all registered holders" AA).
3. Ensure the address list contains N attested addresses and 1 address that was never attested (or whose attestation lapsed).
4. Trigger the AA. `aa_composer.js`'s `mergeMessagesAndOutputs` combines the N+1 outputs into a single `payment` message.
5. During validation, `storage.filterAttestedAddresses` returns fewer attested addresses than `arrOutputAddresses.length`, triggering `cb("some output addresses are not attested")` in `validation.js` (lines 2632-2641), bouncing the entire AA response and denying payout to all N legitimate, attested recipients in the same batch.

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

**File:** aa_composer.js (L1287-1296)
```javascript
		if (mci >= constants.pemCurvesFixMci)
			messages = mergeMessagesAndOutputs(messages);
		var objBasePaymentMessage;
		var arrOutputAddresses = [];
		const addOutputAddresses = (outputs) => {
			outputs.forEach(function (output) {
				if (output.address !== address && arrOutputAddresses.indexOf(output.address) === -1)
					arrOutputAddresses.push(output.address);
			});
		};
```
