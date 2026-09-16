## Title
AA composer forces full rollback of a user withdrawal payout when a bundled secondary-AA call fails, causing denial of service - (File: aa_composer.js)

## Summary
`aa_composer.js`'s `handleTrigger()` treats any AA response that includes a payment to another AA address as a mandatory chained "secondary trigger" into that AA. If that secondary AA bounces for *any* reason (including reasons entirely outside the control of the original trigger sender, e.g. the downstream AA reaching a terminal/"finished"/"shutdown"-like state), the entire primary response — including the valid, unrelated payout owed to the original user — is unwound via `revert()` and the whole unit is bounced. This mirrors the VotiumStrategy pattern: a legitimate withdrawal is bundled with an auxiliary action whose success depends on the live state of a separate contract, and failure of that auxiliary action forces the whole withdrawal to fail.

## Finding Description
When a primary AA trigger produces a response unit, `handleSecondaryTriggers()` looks at every output address of that response and, for any address that is itself an AA, recursively re-invokes `handleTrigger()` as a "secondary trigger" [1](#0-0) .

If any of these secondary AA invocations bounces, `async.eachSeries`'s error handler does not simply drop that one payment — it calls `revert()` on the *entire* primary trigger: [2](#0-1) 

`revert()` then unconditionally rolls back **all** balance and state changes made by the primary AA (not just the failed secondary payment), restores `stateVars`, issues `ROLLBACK TO SAVEPOINT initial_balances`, and finally calls `bounce(err)` on the original trigger unit: [3](#0-2) 

This means that any AA which, as part of a single case/response, both (a) pays out to the triggering user (a legitimate, fully-satisfied withdrawal/payout) and (b) forwards funds or data to a second AA (e.g. a downstream integration, fee-sharing AA, or "destination" AA as in the pattern used by `fundraising_proxy.oscript`) is exposed: if condition (b) ever fails because the downstream AA's own state has changed (finished, expired, or otherwise permanently unable to accept the call), condition (a) — the user's own valid withdrawal — is discarded along with it. Unlike VotiumStrategy's `lock()` precondition, which is controlled by Convex, here the failing precondition is controlled by the downstream AA's *own* state, which can be driven into a permanently failing condition by unrelated third parties (other users' triggers, timestamp/expiry conditions, or race conditions between concurrent triggers), exactly as the vlCVX contract's `isShutdown` flag can be toggled by governance independent of the withdrawing user.

## Impact Explanation
Any AA design that composes a user-facing withdrawal/payout with a call into another AA is subject to full denial of service: legitimate users who are otherwise 100% entitled to their payout get their entire response bounced whenever the downstream AA is (or becomes) unable to process the secondary trigger. Because the failure mode is baked into core protocol behavior (`aa_composer.js`), this is not a corner case restricted to a single script — it applies to every AA-to-AA payment composition pattern documented and used in ocore itself (e.g., the fundraising-proxy-to-game pattern in `fundraising_proxy.oscript`). Once the downstream AA reaches a state where it will always bounce (e.g., its "finished"/game-over condition is permanently true), the primary AA becomes permanently unable to deliver payouts bundled with that secondary call, freezing user funds inside the primary AA.

## Likelihood Explanation
This is triggered by ordinary AA usage, not by any privileged or malicious actor: an unprivileged AA trigger sender simply calling the primary AA once the downstream AA has transitioned to a terminal state (which can happen from normal protocol activity, e.g., another team/contributor finishing a game, a milestone AA expiring, or a race between two concurrent triggers) reliably reproduces the DoS. No special access, timing attack, or malicious peer/node behavior is required — only ordinary interaction with AAs that compose payouts with secondary AA calls, exactly the reachable path described by the bug-class hint (unprivileged unit poster / AA trigger sender).

## Recommendation
- Do not force a hard rollback of the entire primary AA response when a secondary trigger bounces; instead allow AA authors to explicitly opt into "fire-and-forget" semantics for secondary-AA payments (e.g., a flag/case construct that tolerates a bounced secondary trigger without reverting the primary trigger's own already-validated state changes and payouts).
- Alternatively, document and strongly encourage AA authors to never bundle a downstream AA call in the same response branch as a payout that must always succeed for the trigger's own sender; instead split them into independent AA calls/triggers so a downstream failure cannot roll back an already-earned payout.
- Consider adding a getter/state check (analogous to checking `isShutdown` before calling `lock()`) that lets an AA author query whether the downstream AA can currently accept the call before including that call in the same composed response as the user's own withdrawal.

## Proof of Concept
1. Deploy `ProxyAA` that, in a single response to a trigger, (a) pays back shares/proceeds to `trigger.address`, and (b) forwards accumulated funds plus a `data` message to `GameAA` once a target condition is met — mirroring the pattern in `test/samples/fundraising_proxy.oscript`.
2. `GameAA` has an internal terminal condition (e.g., `finished`) after which any secondary trigger sent to it is expected to bounce.
3. Have `GameAA` reach its terminal condition through ordinary use (e.g., another team reaches 51% first, or the challenge period completes), which is entirely outside the control of a user currently contributing to `ProxyAA`.
4. A subsequent contributor sends a trigger to `ProxyAA` that satisfies all of `ProxyAA`'s own conditions and should be entitled to their share payout `(a)`. Because `ProxyAA`'s case also emits payment `(b)` to `GameAA`, `aa_composer.js`'s `handleSecondaryTriggers` invokes `GameAA` as a secondary trigger, which bounces due to its terminal state.
5. `aa_composer.js`'s error handler calls `revert()` [2](#0-1) , which rolls back all of `ProxyAA`'s state changes, including the payout that was fully valid and unrelated to `GameAA`'s terminal state, and bounces the entire unit [3](#0-2) .
6. The contributor's funds are frozen inside `ProxyAA`, unrecoverable through the composed withdrawal path, for as long as `GameAA` remains in its failing state.

### Citations

**File:** aa_composer.js (L1702-1720)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
```

**File:** aa_composer.js (L1743-1750)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
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
