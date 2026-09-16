### Title
Funder can send an asset with an unsatisfiable `transfer_condition` to freeze AA funds and bounce all bundled payouts - (File: `aa_composer.js`)

### Summary
An AA that accepts arbitrary user-supplied assets (a common pattern for bounty/vault/exchange-style AAs, e.g. the `a_bank_without_percent.oscript` and `bouncer_infinite_cycle.oscript` samples that read `trigger.output[[asset!=base]]` and later forward it) never checks whether the asset it is about to pay out actually has a satisfiable `transfer_condition` before composing the response unit. This mirrors the OpenQ bug where `fundBountyToken` accepts any non-whitelisted ERC20 and later bricks the claim path.

### Finding Description
When an AA composes an outgoing response unit in `sendUnit()`, for every non-base asset payment message it loads the asset info via `storage.loadAssetWithListOfAttestedAuthors` and only checks `fixed_denominations` and `is_private` before building the payload: [1](#0-0) 

There is no check of `objAsset.transfer_condition` (or `issue_condition`) at this stage. The condition is only actually evaluated much later, inside full unit validation triggered from `validateAndSaveUnit`: [2](#0-1) 

If `bSatisfiesCondition` is false, `validatePaymentInputsAndOutputs` returns `"transfer or issue condition not satisfied"`, `validateAndSaveUnit` fails, and `sendUnit` calls `bounce(err)`: [3](#0-2) 

`transfer_condition` is a fully general oscript definition (validated the same way as address definitions, via `Definition.validateDefinition`), and it is explicitly permitted for public (non-private) assets: [4](#0-3) [5](#0-4) 

An attacker can therefore issue an ordinary public asset (via a normal `asset` message, no whitelist restriction exists for assets sent into an AA in oscript) whose `transfer_condition` can never be satisfied for outputs the AA composer will ever produce - e.g. a condition requiring `['in data feed', ...]` with a feed value the attacker will never post, or an `attested`/`seen address` condition tied to an address the attacker fully controls and never satisfies. The attacker sends this asset into a vault/bounty-style AA (any AA using the common `trigger.output[[asset!=base]]` pattern shown in the sample scripts), which happily credits it to internal balances/state (`var[$asset_key]` etc., as in `a_bank_without_percent.oscript`).

When the AA (or any claimant) later triggers a payout of that asset, the composer builds the payment message, but validation of the transfer condition fails at `validateAndSaveUnit` time. Critically, AA responses are atomic: because `sendUnit` bounces on this single failure, **all** messages in that response - including any legitimate bytes/asset outputs bundled in the same trigger response (e.g., paying out a bounty in both bytes and the poisoned asset) - are discarded and the whole response bounces: [6](#0-5) 

Because the condition can never be satisfied by construction, every future attempt to pay out that balance bounces identically, permanently freezing the asset inside the AA and preventing the AA from ever forwarding it (or, if bundled together, blocking whichever other outputs were composed in that response).

### Impact Explanation
- Direct analog of the OpenQ finding: an unprivileged party (a "funder"/depositor) can permanently freeze funds held by an AA and make dependent payout logic non-executable, without any special privilege.
- If the vulnerable asset's payout is bundled with other legitimate payments in the same response template (a common oscript pattern), the entire response bounces, so **other users' legitimate claims/payouts can also be blocked** by this single poisoned asset, not just the attacker's own deposit.
- This is a genuine "AA fund freezing" / denial-of-payout condition reachable by any address that can send a payment message to an AA - satisfies the Medium/High bar (AA fund loss or freezing).

### Likelihood Explanation
High reachability: defining a custom asset with an issue/transfer condition and sending it as a normal public payment to any AA requires no special permissions, no admin/whitelist bypass, and is standard/documented functionality (`app: 'asset'` + `transfer_condition`). Any AA that generically accepts "any asset sent to it" (a widely used and recommended pattern, as shown in the shipped sample oscripts) is exposed. The AA author has no reliable, built-in mechanism to pre-validate that an arbitrary incoming asset's transfer condition will be satisfiable for the AA's own future outputs, since `evaluateAssetCondition` depends on runtime unit context (addresses, data feeds, etc.) that isn't known in advance and isn't checked by the composer before it commits to sending the payment.

### Recommendation
- In `aa_composer.js`'s `sendUnit` (around `aa_composer.js:1323-1330`), before completing a non-base asset payment payload, pre-evaluate the asset's `transfer_condition` (via `Definition.evaluateAssetCondition`) against the composed outputs, and bounce early with a clear, isolated error rather than only discovering the failure inside `validateAndSaveUnit`.
- Consider decoupling failure of an individual asset payment from the rest of the response bundle where feasible, so a single poisoned asset cannot cause legitimate bundled payments to bounce as well.
- Document prominently for AA authors that accepting "any asset" (`trigger.output[[asset!=base]]`) carries the risk of receiving assets with unsatisfiable `issue_condition`/`transfer_condition`, and recommend patterns (e.g., asset allow-lists, or immediately bouncing/rejecting unknown assets) analogous to the ERC20 allow-list recommendation in the original report.

### Proof of Concept
Conceptual PoC (cannot be executed without the full test harness, but the mechanics are directly supported by the cited code):
1. Attacker (address A) issues a public, transferable asset X with `transfer_condition: ["in data feed", [["ORACLE_ADDR"], "never_posted_feed", "=", "1"]]` — a condition that can never be satisfied since the oracle never posts that feed value. This is valid per `validateAssetDefinition`/`Definition.validateDefinition` (`validation.js:2794-2826`).
2. Attacker sends a payment of asset X to a vault/bounty AA that generically credits any received asset to internal state (pattern shown in `test/samples/a_bank_without_percent.oscript:31-52`).
3. A legitimate user later triggers a withdrawal/payout that includes asset X (and possibly other assets/bytes) in the same response `messages` array.
4. `sendUnit` composes the payment for asset X without checking `transfer_condition` (`aa_composer.js:1323-1330`), reaches `validateAndSaveUnit`, which calls `validatePaymentInputsAndOutputs` and fails at the `evaluateAssetCondition` check (`validation.js:2643-2658`) because the data feed condition is never true.
5. `sendUnit` bounces (`aa_composer.js:1405-1411`), reverting the whole response, including any bundled legitimate payouts, and leaves asset X's balance permanently stuck in the AA since the condition can never be satisfied on any future retry.

### Citations

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
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

**File:** validation.js (L2643-2658)
```javascript
					function(cb){
						var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
						if (!arrCondition)
							return cb();
						Definition.evaluateAssetCondition(
							conn, payload.asset, arrCondition, objUnit, objValidationState, 
							function(cond_err, bSatisfiesCondition){
								if (cond_err)
									return cb(cond_err);
								if (!bSatisfiesCondition)
									return cb("transfer or issue condition not satisfied");
								console.log("validatePaymentInputsAndOutputs with transfer/issue conditions done");
								cb();
							}
						);
					}
```

**File:** validation.js (L2794-2801)
```javascript
	if (payload.is_private && payload.is_transferrable && !payload.fixed_denominations)
		return callback("if private and transferrable, must have fixed denominations");
	if (payload.is_private && !payload.fixed_denominations){
		if (!(payload.auto_destroy && !payload.is_transferrable))
			return callback("if private and divisible, must also be auto-destroy and non-transferrable");
	}
	if (payload.is_private && ("issue_condition" in payload || "transfer_condition" in payload) && (objValidationState.last_ball_mci >= constants.noPrivateAssetsWithConditionsUpgradeMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.noPrivateAssetsWithConditionsUpgradeMci))
		return callback("if private, cannot have issue or transfer conditions");
```

**File:** definition.js (L2815-2826)
```javascript

```
