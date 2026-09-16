### Title
Precision loss in AA balance-overflow check due to double-precision arithmetic beyond `Number.MAX_SAFE_INTEGER` - (File: aa_composer.js)

### Summary
The TRST-M-4 report describes a reward calculation that silently loses precision because a multiplication (`reward * ACC_TOKEN_PRECISION`) can exceed the safe range of the integer type used to hold it (`uint128`), so the check/accumulation using that value becomes inaccurate. `ocore`'s AA engine has a structurally similar pattern: it tracks each AA's per-asset balance as a plain JS `number` (IEEE-754 double, exact only up to `2**53`), and guards against balance blow-up with a single comparison against `MAX_BALANCE = 2**63 - 1 - MAX_MESSAGES_PER_UNIT * MAX_CAP`, a constant that is itself far beyond `Number.MAX_SAFE_INTEGER` and is explicitly annotated as suffering “precision loss” in the source.

### Finding Description
In `aa_composer.js`, `updateInitialAABalances()` accumulates the trigger's outputs into an AA's balance and only afterwards decides whether an overflow occurred: [1](#0-0) [2](#0-1) [3](#0-2) 

The overflow check compares `objValidationState.assocBalances[address][row.asset]` (or `trigger_opts.assocBalances[address][asset]`) — an ordinary JS `number` — against `MAX_BALANCE`, a value close to `2**63`. Both sides of this comparison are computed with IEEE‑754 double arithmetic, which only guarantees exact integer results up to `2**53 (≈9.007e15)`. Beyond that boundary, `+` and `>` operations on numbers can silently round to the nearest representable double, exactly the “tiny amount lost/gained” effect described in the report, except here it is used as a *security boundary* (an overflow guard used to reject state that could corrupt bookkeeping), not just a reward accrual value.

The source itself acknowledges the issue with the comment "some precision loss in this calc (it's entirely beyond MAX_SAFE_INTEGER) but that's inconsequential", but it is asserted rather than proven: the guard is only meaningfully protective if the comparison is exact at the values actually reached, and rounding near this boundary means the effective threshold enforced at runtime can differ from the intended `MAX_BALANCE` by an amount not bounded by anything smaller than the double's ULP at that magnitude (which is far larger than 1, i.e., >1024 at `2**63`).

Additionally, the `checkBalances()` background sanity-check job that cross-validates DB-stored balances against SQL-summed outputs explicitly special-cases and *ignores* differences it deems attributable to `Number.MAX_SAFE_INTEGER` precision loss: [4](#0-3) 
This confirms that the balance-tracking code path is designed to tolerate the precision-loss condition rather than eliminate it, mirroring the "team accepted, tiny discrepancy is fine" resolution in the original TRST-M-4 report — except unlike a slow-drifting reward accumulator, an AA balance overflow guard failing near its boundary has a more direct bearing on bookkeeping integrity for large asset caps (`MAX_CAP`) and many-message units.

### Impact Explanation
If the balance overflow comparison is inexact near the `MAX_BALANCE`/`2**53` boundary, an attacker able to drive an AA's tracked balance for an asset with a very large `cap` (assets can be defined with caps up to `constants.MAX_CAP`) into that region could cause the overflow check to pass or fail incorrectly. A false negative (overflow not detected) risks internal balance bookkeeping desynchronizing from actual on-chain outputs, which the `checkBalances()` consistency check is specifically told to ignore once amounts pass `Number.MAX_SAFE_INTEGER`. This is a bookkeeping/consistency-integrity issue for AA-held funds at extreme scale rather than a routine, easily triggered spend, and its practical exploitability depends on getting cumulative balances into the affected numeric range, which is difficult under normal `MAX_CAP` limits.

### Likelihood Explanation
Reaching amounts near `2**53`–`2**63` requires assets configured with very large caps and/or many large outputs sent to an AA across triggers, which is possible for any asset issuer/AA author (an unprivileged actor can define an asset with `cap` up to `constants.MAX_CAP` and drive an AA's balance for that asset), but it is not a one-shot, trivially reachable condition — it requires deliberately engineering large cumulative balances, and the codebase already tries to compensate for it in the balance-consistency checker. This keeps likelihood moderate rather than high.

### Recommendation
Replace the double-precision-based balance/overflow bookkeeping in `aa_composer.js` (`assocBalances`, `MAX_BALANCE` comparisons, and the `checkBalances()` tolerance logic) with an exact arbitrary-precision integer representation (e.g., `BigInt` or a decimal library operating in integer mode) for all balance accumulation and overflow-threshold comparisons, so that the overflow guard is exact regardless of magnitude, removing the need to special-case “precision loss above `Number.MAX_SAFE_INTEGER`” as an accepted risk.

### Proof of Concept
Conceptual (not fully demonstrated against a live network, since exact trigger amounts needed to hit the rounding boundary depend on runtime state):
1. Define an asset with `cap` close to `constants.MAX_CAP` via an `asset` message from an unprivileged AA-defining unit.
2. Drive AA-held balance of that asset through repeated triggers/payments so that `assocBalances[address][asset]` accumulates to a value approaching `Number.MAX_SAFE_INTEGER` (`2**53`) and beyond, per: [5](#0-4) 
3. At values above `2**53`, JS number addition/comparison (`balance + trigger.outputs[asset]` then `> MAX_BALANCE`) is not guaranteed exact; craft the trigger amount so the true sum should exceed `MAX_BALANCE` but the double-rounded result does not (or vice versa), bypassing/mis-triggering the `"balance overflow"` rejection at: [6](#0-5) 
4. Confirm the discrepancy persists undetected because `checkBalances()` explicitly filters out rows whose balances exceed `Number.MAX_SAFE_INTEGER` when the relative difference is small: [7](#0-6)

### Citations

**File:** aa_composer.js (L46-49)
```javascript
const CHECK_BALANCES_INTERVAL = conf.CHECK_BALANCES_INTERVAL || 600 * 1000;

// some precision loss in this calc (it's entirely beyond MAX_SAFE_INTEGER) but that's inconsequential
const MAX_BALANCE = 2 ** 63 - 1 - constants.MAX_MESSAGES_PER_UNIT * constants.MAX_CAP;
```

**File:** aa_composer.js (L481-490)
```javascript
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
```

**File:** aa_composer.js (L506-514)
```javascript
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

**File:** aa_composer.js (L2029-2039)
```javascript
								return cb();
							// ignore discrepancies that result from limited precision of js numbers
							rows = rows.filter(row => {
								if (row.balance <= Number.MAX_SAFE_INTEGER || row.calculated_balance <= Number.MAX_SAFE_INTEGER)
									return true;
								var diff = Math.abs(row.balance - row.calculated_balance);
								if (diff > row.balance * 1e-5) // large relative difference cannot result from precision loss
									return true;
								console.log("ignoring balance difference in", row);
								return false;
							});
```
