## Title
AA balance overflow is written to `aa_balances` before the overflow check aborts the trigger - ([File: aa_composer.js])

## Summary
This is the same bug class as the reported `insertValidatorSet()` issue: data is inserted/updated in a persistent store first, and only afterwards is it validated; when validation fails, the code returns an error but never undoes the write. In `ocore`, the analogous path is `updateInitialAABalances()` inside `handleTrigger()`, which updates the `aa_balances` table with the AA's new balance and only detects a `MAX_BALANCE` overflow after the DB write has already executed.

## Finding Description
In the non-`bAir` branch of `updateInitialAABalances`, the code reads existing balances, then builds `arrQueries` that `UPDATE`/`INSERT` the AA's `aa_balances` row with `balance + trigger.outputs[asset]`, tracking overflow only in a local `bOverflow` flag: [1](#0-0) 

These queries (including the balance mutation) are executed unconditionally via `async.series(arrQueries, ...)`, and the `SAVEPOINT initial_balances` is only added to `arrQueries` *after* the balance-mutating queries, i.e., the savepoint baseline itself already contains the (possibly overflowed) balance: [2](#0-1) 

Only in the `async.series` completion callback does the function report the overflow via `cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null)` — after the write has already been committed within the current DB transaction: [3](#0-2) 

The caller treats this as a normal bounce condition: [4](#0-3) 

Because the invalid (over-`MAX_BALANCE`) row was written to `aa_balances` *before* the `SAVEPOINT initial_balances` was taken, any later `ROLLBACK TO SAVEPOINT initial_balances` performed by the generic `revert()` path used elsewhere in `handleTrigger` cannot undo this specific write — the savepoint's baseline is already the corrupted value: [5](#0-4) 

This mirrors the reported analog exactly: `insertValidatorSet()` inserted a validator, then checked its `power`/pubkey validity, and returned an error without removing the already-inserted row. Here, the code updates `aa_balances`, then checks the overflow condition, and returns "balance overflow" without removing/undoing the update — and the rollback mechanism that exists for other error paths does not cover this particular write because of the ordering of the `SAVEPOINT` relative to the balance-mutating queries.

## Impact Explanation
Any unprivileged unit poster can send a trigger unit with `outputs` chosen so that an AA's stored balance crosses `MAX_BALANCE`. Even though the trigger correctly bounces (no response messages are produced), the underlying `aa_balances` row for the AA has already been permanently mutated to an invalid/overflowed value as part of the committed unit-processing transaction. Because AA logic (`bal[...]`, `trigger.output[[...]]`, and payment logic in `oscript`) reads balances directly from `objValidationState.assocBalances` / `aa_balances`, a corrupted balance can lead to:
- incorrect accounting for the AA going forward (funds effectively frozen or unreachable if the AA's logic can no longer correctly compute payouts), or
- unexpected arithmetic/behavior in the AA's formulas that rely on `balance[...]` being within an expected numeric range.

This falls under "AA fund loss or freezing" per the validation rules, since it corrupts the AA's own state store outside the normal bounce-and-discard semantics that the rest of the code otherwise guarantees (e.g., `revertResponsesInCaches`/`ROLLBACK TO SAVEPOINT` for other kinds of failures).

## Likelihood Explanation
Reaching `MAX_BALANCE` requires a very large `trigger.outputs` amount (the constant is presumably close to `MAX_CAP`/total supply bounds), so a single unit is unlikely to trigger it in practice, but repeated attacker-controlled triggers accumulating balance toward the cap are plausible over time, and the check is explicitly coded to be reachable (`mci >= constants.pemCurvesFixMci`), implying the developers considered it a real, currently-active code path.

## Recommendation
Move the `SAVEPOINT initial_balances` to be issued before any balance-mutating queries are added to `arrQueries` (or check `bOverflow` before adding/executing the mutating queries at all, computing the prospective post-update balance first and aborting prior to writing). This ensures the savepoint baseline never includes an invalid state and that `ROLLBACK TO SAVEPOINT` (or an explicit rollback on overflow) fully reverts the `aa_balances` mutation when the trigger is bounced.

## Proof of Concept
Not independently executed (no filesystem/terminal access in this session); the flow is derived from static analysis of `aa_composer.js`:
1. Post an AA trigger with `outputs.base` (or any asset) large enough that `trigger_opts.assocBalances[address][asset]` (in-memory) or the DB-computed `objValidationState.assocBalances[address][row.asset]` (DB path) exceeds `MAX_BALANCE`.
2. `updateInitialAABalances` executes the `UPDATE`/`INSERT INTO aa_balances` queries unconditionally, then sets the savepoint, then reports `"balance overflow"`. [6](#0-5) 
3. `handleTrigger` calls `bounce("balance overflow")` at the `updateInitialAABalances` callback site. [4](#0-3) 
4. If the overall unit still validates and commits (the trigger still bounces cleanly, which is a valid, accepted outcome for the enclosing unit), the `aa_balances` row for the AA now permanently contains the overflowed value, since no code path specifically undoes this particular write.

Because I could not execute code or trace `bounce()`'s exact downstream commit path in this session, I cannot 100% confirm whether some other commit/rollback logic outside the snippets shown independently discards this write in every case; this should be verified with a live test (e.g., an integration test that drives an AA trigger past `MAX_BALANCE` and inspects `aa_balances` after the enclosing unit is saved) via a Devin session with full repository and execution access.

### Citations

**File:** aa_composer.js (L491-538)
```javascript
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
				// 2. insert balances of new assets
				var arrExistingAssets = rows.map(function (row) { return row.asset; });
				var arrNewAssets = _.difference(arrAssets, arrExistingAssets);
				if (arrNewAssets.length > 0) {
					var arrValues = arrNewAssets.map(function (asset) {
						objValidationState.assocBalances[address][asset] = trigger.outputs[asset];
						return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", " + trigger.outputs[asset] + ")"
					});
					conn.addQuery(arrQueries, "INSERT INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
				}
				byte_balance = objValidationState.assocBalances[address].base;
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
				if (!bSecondary)
					conn.addQuery(arrQueries, "SAVEPOINT initial_balances");
				async.series(arrQueries, function () {
					conn.query("SELECT storage_size FROM aa_addresses WHERE address=?", [address], function (rows) {
						if (rows.length === 0)
							throw Error("AA not found? " + address);
						storage_size = rows[0].storage_size;
						objValidationState.storage_size = storage_size;
						cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
					});
				});
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

**File:** aa_composer.js (L1841-1845)
```javascript
	updateInitialAABalances(function (err) {

		// these errors must be thrown after updating the balances
		if (err)
			return bounce(err);
```
