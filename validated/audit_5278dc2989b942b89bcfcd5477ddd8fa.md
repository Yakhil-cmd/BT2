### Title
`estimatePrimaryAATrigger`/`dry_run_aa` estimate ignores `storage_size` deduction, giving inaccurate predicted AA response to trigger senders - (File: aa_composer.js)

### Summary
Ammplify's `View::queryAssetBalances` is a read-only "preview" function used by front-ends to show a user the funds they'd receive on withdrawal, but it fails to apply the JIT penalty that the real `removeMaker` function applies, causing the preview to overstate the payout. The analogous pattern in ocore is `estimatePrimaryAATrigger` (and its network-exposed twin `dryRunPrimaryAATrigger`, reachable via the `light/dry_run_aa` request handler), which is explicitly documented as an approximation of what a real AA trigger execution will produce, but skips accounting for `storage_size`-driven balance deductions that the real trigger-handling code (`sendUnit`/`completePaymentPayload`) applies.

### Finding Description
`estimatePrimaryAATrigger` is described in its own comment as inexact: "The estimation is not 100% accurate, e.g. storage_size is ignored, unit validation errors are not caught" [1](#0-0) . It runs the trigger through the same `handleTrigger` pipeline but with `bAir: true`, which routes payment-message settlement through `sendDummyUnit` instead of the real `sendUnit` [2](#0-1) . `sendDummyUnit` deducts output amounts directly from `assocBalances` without ever computing or reserving `storage_size` [3](#0-2) .

In the real execution path (`sendUnit` → `completePaymentPayload`), when a "send-all" base-asset output is used, the code explicitly carves out `storage_size` bytes worth of value as a change output kept on the AA address to preserve its minimum required storage balance: "we add a change output to AA to keep balance above storage_size" [4](#0-3) . This deduction/reservation of funds never happens in the `bAir`/dummy-unit estimate path, so the balances and payout amounts reported by `estimatePrimaryAATrigger` (and thus by the `light/dry_run_aa`/`estimatePrimaryAATrigger` results returned to callers) can diverge from what a real trigger unit posted by an unprivileged AA trigger sender would actually produce, exactly mirroring the Ammplify root cause: a value-computing view path that omits a penalty/deduction applied only in the state-changing path.

### Impact Explanation
Any unprivileged user composing an AA trigger (or a wallet acting on their behalf) relies on `estimatePrimaryAATrigger`/`dryRunPrimaryAATrigger` results to decide how much to send and what outputs/balances to expect back from an AA response. Because the estimate omits the `storage_size` reservation that the real trigger execution enforces, the estimated outputs/balances can overstate the funds an address will actually receive, causing the sender to construct a real trigger based on incorrect expectations, or to misjudge whether a "send-all" response leaves the AA sufficiently funded. This is a genuine value-mismatch between a view/estimate path and the real state-changing path, matching the Sherlock finding's medium-severity bug class (incorrect return value used by other logic/decisions, deviating from the real amount).

### Likelihood Explanation
This is triggered any time a wallet or dApp front-end calls the `light/dry_run_aa` request (which calls `dryRunPrimaryAATrigger`) or a full/hub node calls `estimatePrimaryAATrigger` to preview AA trigger effects for a trigger involving a "send-all" base-asset payment output from the AA and where the AA's resulting balance interacts with `storage_size`. Since `dryRunPrimaryAATrigger` is directly reachable by any unprivileged caller over the light-wallet protocol with an arbitrary, self-constructed trigger object, no privileged access is required to observe the discrepancy.

### Recommendation
Have `estimatePrimaryAATrigger`/`dryRunPrimaryAATrigger`'s `bAir`/dry-run payment-settlement path (`sendDummyUnit`) account for the same `storage_size`-based change reservation logic used by `sendUnit`/`completePaymentPayload`, or otherwise clearly reconcile the estimate against the real post-storage-size balance so that estimated outputs/balances match what a real trigger unit would produce.

### Proof of Concept
Not applicable — this is a logic/documentation-confirmed discrepancy between the `bAir` dummy-unit settlement path (`sendDummyUnit`, `aa_composer.js:948-974`) and the real settlement path (`sendUnit`/`completePaymentPayload`, `aa_composer.js:1074-1082`), corroborated by the code's own comment acknowledging that `storage_size is ignored` in the estimate [5](#0-4) .

### Citations

**File:** aa_composer.js (L152-157)
```javascript
// estimates the effects of an AA trigger before it gets stable.
// stateVars and assocBalances are updated after the function returns.
// The estimation is not 100% accurate, e.g. storage_size is ignored, unit validation errors are not caught
function estimatePrimaryAATrigger(objUnit, address, stateVars, assocBalances, onDone) {
	if (!onDone)
		return new Promise(resolve => estimatePrimaryAATrigger(objUnit, address, stateVars, assocBalances, resolve));
```

**File:** aa_composer.js (L948-974)
```javascript
	function sendDummyUnit(messages) {
		console.log('AA ' + address + ': send dummy unit with messages', util.inspect(messages, { depth: 6 }));
		var objUnit = messages.length ? {
			unit: 'dummy' + Date.now(),
			authors: [{ address: address }],
			messages: messages,
		} : null;
		executeStateUpdateFormula(objUnit, function (err) {
			if (err)
				return bounce(err);
			// update balances
			var arrOutputAddresses = [];
			messages.forEach(message => {
				if (message.app !== 'payment')
					return;
				var asset = message.payload.asset || 'base';
				message.payload.outputs.forEach(output => {
					if (output.amount !== 0 && arrOutputAddresses.indexOf(output.address) === -1)
						arrOutputAddresses.push(output.address);
					if (!trigger_opts.assocBalances[address][asset])
						trigger_opts.assocBalances[address][asset] = 0;
					if (output.amount === undefined) // send all
						output.amount = trigger_opts.assocBalances[address][asset];
					// deduct from this AA's balance. It can get negative if we are issuing coins but in this case balance[] is probably meaningless
					trigger_opts.assocBalances[address][asset] -= output.amount;
				});
			});
```

**File:** aa_composer.js (L1043-1045)
```javascript
	async function sendUnit(messages) {
		if (trigger_opts.bAir)
			return sendDummyUnit(messages);
```

**File:** aa_composer.js (L1074-1082)
```javascript
			// remove the send-all output from size calculation, it might be added later
			if (send_all_output && is_base){
				size -= 32 + (bWithKeys ? "address".length : 0);
				// we add a change output to AA to keep balance above storage_size
				if (storage_size > FULL_TRANSFER_INPUT_SIZE && mci >= constants.aaStorageSizeUpgradeMci){
					size += OUTPUT_SIZE + (bWithKeys ? OUTPUT_KEYS_SIZE : 0);
					payload.outputs.push({ address: address, amount: storage_size });
				}
			}
```
