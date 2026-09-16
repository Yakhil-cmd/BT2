### Title
Attacker-controlled asset issuance can permanently push an AA's per-asset balance over `MAX_BALANCE`, freezing that AA's ability to accept further payments of the asset - (File: `aa_composer.js`)

### Summary
`aa_composer.js` enforces a hard `MAX_BALANCE` cap on any single `(address, asset)` balance held by an Autonomous Agent. Any unprivileged sender can post a trigger unit whose payment message pushes the target AA's stored balance for a chosen asset past this cap. The check fires *after* the balance update has already been queued/applied, so the AA is left in a permanently over-cap state for that asset, and every subsequent trigger that sends the same asset to the AA will keep failing the same check and bounce - a persistent denial-of-service on a specific AA function, directly analogous to the Tokemak `sink`/`perWalletLimit` issue where an attacker inflates a privileged address's balance/limit to permanently block a critical operation (`rebalance()`/`flashRebalance()`).

### Finding Description
`aa_composer.js` defines: [1](#0-0) 

and enforces it while merging the trigger's payment outputs into the AA's balance, in `updateInitialAABalances`: [2](#0-1) 

Note that the `UPDATE aa_balances SET balance=balance+?` query (and the equivalent in-memory update for the `bAir`/estimation path) is executed as part of `arrQueries` and completes *before* the overflow condition is evaluated and reported via `cb(... "balance overflow" ...)`. The caller only decides to `bounce(err)` afterward: [3](#0-2) 

`bounce()` composes a response that refunds bytes (`bounce_fees.base`) to the trigger's sender, but it does not necessarily unwind the balance increment that already occurred for the asset that caused the overflow (the `revert()`/`ROLLBACK TO SAVEPOINT initial_balances` path is only used for secondary-AA-call failures inside `handleSecondaryTriggers`, not for the initial-trigger overflow check at line 1841-1845). Once an AA's balance for `(address, asset)` sits above `MAX_BALANCE`, any further trigger that adds a positive amount of that same asset will again trip the `> MAX_BALANCE` condition and bounce, because the balance never decreases below the cap on its own.

Any address can create an uncapped asset (`issued_by_definer_only` under attacker's own control) via the `asset` message type validated in `validateAssetDefinition`: [4](#0-3) 

and repeatedly issue it (up to `MAX_CAP` per issue, no limit on number of issues for uncapped assets), as seen in the issue-input validation: [5](#0-4) 

An attacker who owns the asset can therefore accumulate an arbitrarily large quantity of it and, in a single payment message, send enough of it to a target AA to push that AA's `(address, asset)` balance above `MAX_BALANCE` (roughly `2^63 - 1 - MAX_MESSAGES_PER_UNIT*MAX_CAP`), permanently poisoning the AA's ability to process that asset going forward - the same class of bug as the Tokemak report, where an unprivileged actor inflates a balance/limit tied to a system-critical address until further legitimate operations revert.

### Impact Explanation
Any AA that is designed to accept a particular asset as part of its normal trigger flow (e.g., a swap/vault/exchange AA analogous to `LMPVault`) can have that specific asset-acceptance path permanently disabled by an attacker who issues and sends enough of a self-controlled asset to breach `MAX_BALANCE`. From that point on, all triggers sending that asset to the AA bounce with `"balance overflow"`, freezing AA functionality that depends on receiving it (deposits, order fills, rebalances, etc.), matching the accepted impact category of "AA fund loss or freezing."

### Likelihood Explanation
The precondition (attacker fully controls an uncapped asset and can issue and transfer it freely to any AA) is trivially satisfiable by any unprivileged user - no special role or permission is required, only the ability to define an asset and post payment/trigger units, both of which are ordinary AA-trigger capabilities. The only cost is the byte/asset issuance overhead to accumulate near `MAX_BALANCE` worth of the asset, which is a resource cost rather than a permission barrier.

### Recommendation
Reject or fully unwind the balance update for the specific `(address, asset)` pair that overflows before evaluating/bouncing, instead of allowing the queued `UPDATE aa_balances` to persist past the check; alternatively, validate the projected post-trigger balance before committing the update (fail-closed check-then-act) so an overflowing trigger never mutates `aa_balances`, and consider bouncing back the entire *asset* payload (not only `bounce_fees.base`) when overflow is detected, to avoid leaving the AA in the over-cap state.

### Proof of Concept
1. Attacker defines an uncapped, `issued_by_definer_only`-controlled asset `X` via an `asset` message (`validateAssetDefinition`, `validation.js:2725-2827`).
2. Attacker repeatedly issues asset `X` to themselves (each issue up to `MAX_CAP`, unlimited number of issues since uncapped), accumulating a balance near `MAX_BALANCE`.
3. Attacker sends a single trigger unit with a `payment` message transferring a large amount of asset `X` to the target AA address.
4. In `handleTrigger` → `updateInitialAABalances` (`aa_composer.js:475-514`), the AA's `(address, X)` balance is updated to exceed `MAX_BALANCE`; the query already commits before the overflow is reported.
5. `updateInitialAABalances`'s callback returns `"balance overflow"`, and `handleTrigger` calls `bounce(err)` (`aa_composer.js:1841-1845`), but the AA's stored balance for asset `X` remains above `MAX_BALANCE`.
6. Any subsequent legitimate trigger sending asset `X` to this AA re-triggers the same `> MAX_BALANCE` check and bounces indefinitely, permanently blocking that AA function for asset `X`.

### Citations

**File:** aa_composer.js (L48-49)
```javascript
// some precision loss in this calc (it's entirely beyond MAX_SAFE_INTEGER) but that's inconsequential
const MAX_BALANCE = 2 ** 63 - 1 - constants.MAX_MESSAGES_PER_UNIT * constants.MAX_CAP;
```

**File:** aa_composer.js (L475-514)
```javascript
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
		objValidationState.assocBalances[address] = {};
		var arrAssets = Object.keys(trigger.outputs);
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
					if (!trigger.outputs[row.asset]) {
						objValidationState.assocBalances[address][row.asset] = row.balance;
						return;
					}
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
				});
```

**File:** aa_composer.js (L1841-1845)
```javascript
	updateInitialAABalances(function (err) {

		// these errors must be thrown after updating the balances
		if (err)
			return bounce(err);
```

**File:** validation.js (L2307-2327)
```javascript
			switch (type){
				case "issue":
				//	if (objAsset)
				//		profiler2.start();
					if (input_index !== 0)
						return cb("issue must come first");
					if (hasFieldsExcept(input, ["type", "address", "amount", "serial_number"]))
						return cb("unknown fields in issue input");
					if (!isPositiveInteger(input.amount))
						return cb("amount must be positive");
					if (input.amount > constants.MAX_CAP)
						return cb("issue amount too large: " + input.amount)
					if (!isPositiveInteger(input.serial_number))
						return cb("serial_number must be positive");
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
					if (bIssue)
						return cb("only one issue per message allowed");
					bIssue = true;
```

**File:** validation.js (L2725-2755)
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

	// denominations
	if (payload.fixed_denominations && !isNonemptyArray(payload.denominations))
		return callback("denominations not defined");
	if (!payload.fixed_denominations && "denominations" in payload)
```
