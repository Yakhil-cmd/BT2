### Title
Attacker-inflated asset balance can permanently freeze an AA's funds via the `MAX_BALANCE` overflow check - (File: `aa_composer.js`)

### Summary
`handleTrigger`'s `updateInitialAABalances` function increments an AA's tracked `aa_balances` entry for whatever asset a trigger unit sends, and rejects the entire trigger with `"balance overflow"` whenever that asset balance exceeds `MAX_BALANCE`. Because `aa_balances` is a persistent, monotonically-influenced ledger and the overflow check runs *before* any AA logic executes, an unprivileged party can permanently push an asset's tracked balance above `MAX_BALANCE` for a target AA, after which every future trigger carrying that asset is bounced before the AA gets a chance to spend or forward it — permanently freezing those funds. This mirrors the Malt `LinearDistributor` bug class: a balance-dependent guard (`declaredBalance`/`bufferRequirement` there, `MAX_BALANCE` here) that unprivileged inbound transfers can push past a hard limit, causing a permanent, unrecoverable revert.

### Finding Description
In `updateInitialAABalances` (aa_composer.js), when a trigger sends coins of some asset to an AA, the code adds the received amount to the AA's tracked balance and flags overflow if the result exceeds `MAX_BALANCE`: [1](#0-0) [2](#0-1) 

`MAX_BALANCE` is defined as: [3](#0-2) 

Once `bOverflow` is set (for `mci >= constants.pemCurvesFixMci`), `updateInitialAABalances` returns the error `"balance overflow"`, which is handled immediately after the balances are updated, *before* the AA's own logic (`evaluateAA`) is ever invoked: [4](#0-3) 

Critically, the balance update happens unconditionally (persisted to the `aa_balances` table via `UPDATE aa_balances SET balance=balance+?`) even on the very trigger that causes the overflow, and the trigger is then bounced. Because the AA never runs its message/state logic when this bounce occurs, it has no opportunity to spend down, forward, or otherwise reduce that asset balance. Any subsequent trigger that also carries an output in that same asset will again exceed `MAX_BALANCE` (since the stored balance is already at or above the threshold) and be bounced the same way — permanently.

Assets are open to be created and funded by anyone: any user can issue a custom asset with a very large `cap` (bounded only by `MAX_CAP`), and then send output(s) in that asset to a target AA. Many published/community AA patterns (e.g., `test/samples/a_bank_without_percent.oscript`, `test/samples/order_book_exchange.oscript`) explicitly accept and track *arbitrary* incoming assets via a generic "silently accept coins" branch: [5](#0-4) 

For such AAs (or any AA that doesn't reject unexpected assets outright), an attacker only needs to accumulate enough of a single, attacker-controlled asset in the AA's tracked balance to cross `MAX_BALANCE`, after which all future interactions involving that asset with that AA address are permanently DoS'd at the balance-tracking layer, independent of the AA's own bounce/business logic.

### Impact Explanation
This is an AA-fund-freezing vulnerability: once an asset balance for a given AA address is pushed past `MAX_BALANCE`, the AA can never again process a trigger carrying that asset, so any of that asset already held by (or subsequently sent to) the AA becomes permanently unspendable/unrecoverable through the AA. This matches the accepted impact category of "AA fund loss or freezing." The attack does not require any special privilege — any user can issue an asset (`aa_validation.js`/`validation.js` impose only generic size/cap validation on asset definitions) and send it to the target AA.

### Likelihood Explanation
`MAX_BALANCE = 2**63 - 1 - MAX_MESSAGES_PER_UNIT * MAX_CAP` is very large, so reaching it for the base "bytes" asset (whose total supply, `TOTAL_WHITEBYTES`, is far smaller) is infeasible. However, for a *custom, attacker-issued asset*, the attacker fully controls `cap` (up to `MAX_CAP`) and can issue and send arbitrarily many units of their own asset to the AA over one or more triggers, making it feasible to cross `MAX_BALANCE` for that specific asset without needing cooperation from the AA's regular users or large amounts of real value. The requirement that the AA actually process/track outputs of arbitrary assets (as several published AA templates in this codebase do) somewhat narrows applicability, but such patterns are common and not disallowed by the platform.

### Recommendation
- Reject (bounce) or ignore trigger outputs for a specific asset before crediting them to `aa_balances` if crediting would push the balance above `MAX_BALANCE`, rather than crediting first and bouncing the whole trigger afterward. This way the excess amount is not persisted into the frozen state.
- Alternatively, allow the specific overflow-causing output to be treated as a bounce-with-refund (returning the excess to the sender) rather than being irreversibly added to `aa_balances` before the check.
- Add a sweep/reclaim mechanism so that if `aa_balances` for an asset is already at/above a safety threshold, the AA (or its owner) can withdraw/burn the excess to bring the tracked balance back under `MAX_BALANCE`, restoring the ability to process further triggers for that asset.

### Proof of Concept
1. Attacker defines a custom asset `X` with `cap` set to a very large value (up to `constants.MAX_CAP`) via an `asset` message, `issued_by_definer_only: true`.
2. Attacker issues/collects a large quantity of asset `X` (using the asset's own issuance mechanics, potentially across multiple issuances/transfers if `cap`-based single issuance isn't enough — repeated custom assets can also be created and each pushed near-`MAX_CAP`).
3. Attacker repeatedly sends payments containing asset `X` outputs to a target AA that accepts/tracks arbitrary incoming assets (per the "silently accept coins" pattern shown in `test/samples/a_bank_without_percent.oscript` lines 31-52), each trigger adding to `aa_balances[address][X]` via `aa_composer.js` lines 506-513.
4. Once `aa_balances[address][X] > MAX_BALANCE`, the next trigger carrying asset `X` sets `bOverflow = true` and `updateInitialAABalances` returns `"balance overflow"` (aa_composer.js lines 483-489, 512-513), causing `handleTrigger` to bounce the trigger at lines 1841-1845 before any AA logic runs.
5. From this point forward, every trigger that includes an output in asset `X` to this AA address is unconditionally bounced at the balance-tracking stage, and the AA can never spend, forward, or refund the already-tracked balance of asset `X`, since its state/payment logic never executes.

### Citations

**File:** aa_composer.js (L48-49)
```javascript
// some precision loss in this calc (it's entirely beyond MAX_SAFE_INTEGER) but that's inconsequential
const MAX_BALANCE = 2 ** 63 - 1 - constants.MAX_MESSAGES_PER_UNIT * constants.MAX_CAP;
```

**File:** aa_composer.js (L481-489)
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
```

**File:** aa_composer.js (L506-513)
```javascript
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
```

**File:** aa_composer.js (L1841-1849)
```javascript
	updateInitialAABalances(function (err) {

		// these errors must be thrown after updating the balances
		if (err)
			return bounce(err);
		if (arrResponses.length >= constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER) // max number of responses per primary trigger, over all branches stemming from the primary trigger
			return bounce("max number of responses per trigger exceeded");
		if ("max_aa_responses" in trigger && arrResponses.length >= trigger.max_aa_responses)
			return bounce(`max_aa_responses ${trigger.max_aa_responses} exceeded`);
```

**File:** test/samples/a_bank_without_percent.oscript (L31-52)
```text
			{ // silently accept coins
				if: "{!trigger.data.withdraw}",
				messages: [{
					app: 'state',
					state: `{
						$asset = trigger.output[[asset!=base]].asset;
						if ($asset == 'ambiguous')
							bounce('ambiguous asset');
						if (trigger.output[[asset=base]] > 10000){
							$base_key = 'balance_'||trigger.address||'_'||'base';
							var[$base_key] = var[$base_key] + trigger.output[[asset=base]];
							$response_base = trigger.output[[asset=base]] || ' bytes\n';
						}
						if ($asset != 'none'){
							$asset_key = 'balance_'||trigger.address||'_'||$asset;
							var[$asset_key] = var[$asset_key] + trigger.output[[asset=$asset]];
							$response_asset = trigger.output[[asset=$asset]] || ' of ' || $asset || '\n';
						}
						response['message'] = 'accepted coins:\n' || ($response_base otherwise '') || ($response_asset otherwise '');
					}`
				}]
			},
```
