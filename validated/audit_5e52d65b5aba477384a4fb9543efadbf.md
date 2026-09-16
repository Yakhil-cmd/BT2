Found a concrete analog: the `objAsset.cap` handling in `aa_composer.js#issueAsset` (used by `sendUnit`/`completePaymentPayload`) reproduces the same "fixed limit blocks legitimate spend/claim" bug class as the C4 finding.

### Title
AA capped-asset issuance uses a fixed `cap` regardless of the amount actually owed, permanently freezing any payout that exceeds the cap - (File: `aa_composer.js`)

### Summary
When an AA needs to make a payment in a custom asset and lacks sufficient existing UTXOs, it falls back to `issueAsset()`. For assets defined with a fixed `cap`, the code always issues exactly `objAsset.cap`, once, forever — mirroring the C4 report's pattern of a hardcoded ceiling (`spend_limit`) on a payout mechanism that a smart-contract-like actor cannot exceed or adjust per-claim.

### Finding Description
In `handleTrigger`'s `sendUnit` → `completePaymentPayload` → `issueAsset`, the issue amount for a capped asset is computed as: [1](#0-0) 
```
var issue_amount = objAsset.cap || (target_amount - total_amount);
...
if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
    conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
        if (rows.length > 0) // already issued
            return cb2('already issued');
        addIssueInput(1);
    });
}
```
If `target_amount` (what the AA needs to pay out to satisfy the trigger/payment message, e.g. a growing reward/claim balance tracked in a state var) exceeds `objAsset.cap`, the AA still only issues `cap` units. `total_amount` (now equal to `cap`) will be less than `target_amount`, `change_amount` will be negative (no change output added), and the AA ends up short of funds for the requested output — the transaction bounces with "not enough funds ... of asset" (see the caller in `issueAsset`'s consumer): [2](#0-1) 
This is enforced consensus-side too: for a capped, non-fixed-denomination asset, validation requires `input.amount === objAsset.cap` exactly, so an AA can never legally issue more than the cap even if its internal accounting says it owes more: [3](#0-2) 
Because the "already issued" check makes issuance a one-time event per asset (`SELECT 1 FROM inputs WHERE type='issue' AND asset=?`), once the cap has been issued, the AA can never mint additional units — permanently limiting the pool it can pay claimants from to `cap`, no matter how the AA's internal reward/claim accounting grows over the AA's continued operation. This is structurally identical to the C4 report: a fixed limit configured at definition time on a payout/mint mechanism causes users' otherwise-valid claims to permanently fail once the accounting logic in the calling AA legitimately calls for more than that limit.

### Impact Explanation
An AA design that issues a capped asset to back growing claims (e.g., a rewards/vault AA that mints wrapped-asset receipts equal to accumulated deposits/rewards, similar to the mAssets/vault pattern in the original report) can silently and permanently break: once the running total owed to users exceeds the asset's `cap`, subsequent trigger-driven payments requiring `issueAsset` bounce with "not enough funds", freezing legitimate claims/withdrawals for any user whose payout pushes the AA past the cap. There is no way to raise the cap post-issuance (issuance is single-shot and validated to equal `cap` exactly), so the loss of user funds/claims is permanent, analogous to the Medium-severity finding in the original report ("loss of yield/inability to claim once a threshold is exceeded").

### Likelihood Explanation
This requires only a single trigger unit sent to an ordinary user-deployed AA whose author chose (or was forced into, e.g. by growing yield) to define a capped custom asset used for ongoing payouts — no privileged or malicious actor is needed; it's triggered purely by normal usage volume growing beyond the AA author's original `cap` estimate, which is exactly the practical scenario judged Medium severity in the source report.

### Recommendation
For AA-issued assets intended to back an open-ended/growing claim balance, avoid `cap` (use uncapped assets, which are re-issuable per `max_serial_number+1`), or have `issueAsset` bounce with an actionable/reversible error and let AA logic queue/partial-pay rather than silently failing once cumulative claims exceed `objAsset.cap`. Documentation/tooling should warn AA authors that a capped asset cannot mint more than `cap` even if internal AA state implies a larger obligation.

### Proof of Concept
1. Deploy an AA that defines a custom asset with `cap: 1000` via an `asset` message, then on every subsequent trigger accumulates a state var `var['owed'] += trigger.output[[asset=base]]` and attempts `{app: 'payment', payload: {asset: '{var[definer]}', outputs: [{address: trigger.address, amount: '{var[owed]}'}]}}`.
2. First trigger: AA has no asset balance yet, calls `issueAsset`, issues exactly `1000` units (the cap) via the single allowed issue input, per [4](#0-3) , and pays out.
3. Continue sending triggers such that `var['owed']` cumulative payouts exceed `1000` (e.g., because the AA is meant to reward each depositor proportionally and total deposits legitimately exceed the cap).
4. On the trigger where `target_amount > 1000`, `issueAsset` finds `rows.length > 0` ("already issued") and returns `'already issued'`; `completePaymentPayload` propagates `'not enough funds ... of asset <hash>'`; the response bounces per [5](#0-4) .
5. That user's (and all subsequent users') legitimate claim permanently bounces — the AA can never issue additional units of that asset, since the definer-only single issuance already consumed the entire fixed `cap`, and `validation.js` requires future issues to equal `cap` exactly (impossible, since it's already been issued) per [3](#0-2) .

### Citations

**File:** aa_composer.js (L1175-1200)
```javascript
			function issueAsset(cb2) {
				var objAsset = assetInfos[asset];
				if (objAsset.issued_by_definer_only && address !== objAsset.definer_address)
					return cb2("not a definer");
				var issue_amount = objAsset.cap || (target_amount - total_amount);

				function addIssueInput(serial_number){
					var input = {
						type: "issue",
						amount: issue_amount,
						serial_number: serial_number
					};
					payload.inputs.unshift(input);
					total_amount += issue_amount;
					var change_amount = total_amount - target_amount;
					if (change_amount > 0)
						payload.outputs.push({ address: address, amount: change_amount });
					cb2();
				}
				
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
```

**File:** aa_composer.js (L1223-1245)
```javascript
			readStableOutputs(function (rows) {
				iterateUnspentOutputs(rows);
				if (bFound && !send_all_output)
					return sortOutputsAndReturn();
				readUnstableOutputsSentByAAs(function (rows2) {
					iterateUnspentOutputs(rows2);
					if (bFound)
						return sortOutputsAndReturn();
					if (!asset)
						return cb('not enough funds for ' + target_amount + ' bytes');
					var bSelfIssueForSendAll = mci < (constants.bTestnet ? 2080483 : constants.aa3UpgradeMci);
					if (!bSelfIssueForSendAll && send_all_output && payload.outputs.length === 1) // send-all is the only output - don't issue for it
						return sortOutputsAndReturn();
					issueAsset(function (err) {
						if (err) {
							console.log("issue failed: " + err);
							return cb('not enough funds for ' + target_amount + ' of asset ' + asset);
						}
						sortOutputsAndReturn();
					});
				});
			});
		}
```

**File:** validation.js (L2344-2347)
```javascript
					if (objAsset){
						if (objAsset.cap && !objAsset.fixed_denominations && input.amount !== objAsset.cap)
							return cb("issue must be equal to cap");
					}
```
