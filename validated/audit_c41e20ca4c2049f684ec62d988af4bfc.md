### Title
Genesis unit's headers commission is permanently unspendable, freezing the "first-epoch" reward - ([File: headers_commission.js])

### Summary
`headers_commission.js` computes and pays out the per-unit "headers commission" that a parent unit's payload/header size fee earns for whichever child unit (its author) best represents/includes it as a parent. The code contains an explicit, hard-coded carve-out for the genesis unit that causes the headers commission attributable to the genesis unit to never be computed and never be inserted into `headers_commission_outputs`, so it becomes permanently unclaimable — the same "first epoch reward is stuck forever" failure pattern described in the external report for `RewardsDistributor`.

### Finding Description
`calcHeadersCommissions()` walks parent units (`punits`) whose children (`chunits`) are stable, and looks up `storage.assocStableUnitsByMci[parent.main_chain_index+1]` to find the best child that "wins" the headers commission of the parent: [1](#0-0) 

For the genesis unit (`main_chain_index === 0`), `parent.main_chain_index+1` is `1`. When `since_mc_index == 0` (which is always true the very first time commissions are calculated, since `initMaxSpendableMci` initializes `max_spendable_mci` to `0`), the code explicitly `return`s and skips building the children info for that parent — with the comment "hack for genesis unit where we lose hc": [2](#0-1) 

This means the genesis unit is never included as a `payer_unit` in `assocWonAmounts`, so no row is ever inserted into `headers_commission_contributions` for it, and consequently `headers_commission_outputs` never receives an entry crediting the genesis unit's headers_commission to any address. The `initMaxSpendableMci` function itself documents this consequence directly: [3](#0-2) 

This is structurally identical to the reported `RewardsDistributor` bug class: a reward pool tied to the very first unit of accounting (the "first epoch" / genesis unit) is computed against a state where the beneficiary-selection mechanism (best-child lookup via `assocStableUnitsByMci[mci+1]`) is not yet populated/available, so the code takes a shortcut that discards the reward instead of deferring or reassigning it — permanently freezing those funds. Just as veALCX holders can never retroactively become "the holder at the end of epoch 0" in the Alchemix report, no unit can retroactively become "the best child of the genesis unit for since_mc_index=0" once this code path has run, since `since_mc_index` (aka `max_spendable_mci`) is monotonically advanced and the calculation for `mci=0`-as-payer is never revisited.

Compounding this, `calcCommissions()` in `main_chain.js` explicitly skips commission calculation entirely for `mci === 0`: [4](#0-3) 
so the very first opportunity to account for the genesis unit's headers commission is bypassed at the point where it becomes stable, and the follow-up hack in `headers_commission.js` bypasses it again at the point where `mci=1` first triggers a real calculation.

### Impact Explanation
The headers commission attributable to the genesis unit is a real transferable balance component that funds `headers_commission_outputs`, from which node operators/authors compose `headers_commission` inputs to spend real bytes (see `inputs.js` `addHeadersCommissionInputs`, `validation.js` commission-input validation at lines 2582-2599). Any amount permanently excluded from `headers_commission_outputs` for the genesis unit is bytes that no address can ever construct a valid `headers_commission` input to claim — a permanent freezing of value, matching the report's "Permanent freezing of unclaimed yield" impact category. Because this happens automatically on every fresh chain initialization (it is baked into the deterministic commission-calculation logic, not an attacker-triggerable edge case), it deterministically reduces total spendable headers commission at network genesis by exactly this one, well-defined amount.

### Likelihood Explanation
This is not a theoretical edge case reachable only by an attacker — it triggers automatically and deterministically for every ocore-based network at genesis, the first time `calcHeadersCommissions` runs (`since_mc_index == 0`). It requires no privileged or malicious actor; it is an inherent consequence of how the genesis unit is bootstrapped (no `parent_units`, hence the ordinary best-child/next-mc-unit lookup mechanism used for all other units cannot apply) combined with the explicit `return` "hack" comment acknowledging the loss. Given the comments explicitly acknowledging the loss twice (`headers_commission.js:91-94` and `headers_commission.js:263`), the developers are aware of this specific, reproducible loss condition, but it has not been fixed to redirect the lost commission (e.g., to burn, to the first-child author by fallback rule, or otherwise safely accounted for).

### Recommendation
Add an explicit, deterministic fallback for the genesis unit's headers commission instead of silently dropping it: e.g., attribute the genesis-unit headers commission to the author(s) of the actual first non-genesis unit(s) built directly on top of genesis (the true "best child" by the same hash-based selection rule used elsewhere, computed once `mci=1` is stable), or explicitly burn/void it with a well-defined, auditable accounting entry instead of implicitly excluding it from `headers_commission_outputs`. This mirrors how the Alchemix report recommends distributing to whichever population becomes eligible once the first real "epoch" balances exist, rather than leaving the reward orphaned.

### Proof of Concept
Conceptual reproduction (matches the documented behavior of the code, not requiring any special attacker capability):
1. Start a fresh ocore-based network; write the genesis unit (`main_chain_index=0`, `is_stable=1`, `is_on_main_chain=1`), which is assigned some nonzero `headers_commission` value by the unit-size fee formula (`writer.js`/`composer.js` set `headers_commission: objUnit.headers_commission || 0`).
2. Post the first real unit(s) referencing genesis as parent; let `mci=1` stabilize. `main_chain.js`'s `calcCommissions()` explicitly does nothing for `mci===0` and only starts calling `headers_commission.calcHeadersCommissions()` for `mci >= 1`: [4](#0-3) 
3. On the first invocation, `max_spendable_mci` is `null`, so `initMaxSpendableMci` sets it to `0` (documented as "should be -1, we lose headers commissions paid by genesis unit"): [3](#0-2) 
4. `calcHeadersCommissions` then runs with `since_mc_index = 0`; when iterating `arrParentUnits = storage.assocStableUnitsByMci[since_mc_index+1]` — wait, the actual skip is keyed by the genesis parent's own `main_chain_index+1` lookup failing/being special-cased with `if (since_mc_index == 0) return;`: [5](#0-4) 
5. Query `SELECT amount FROM headers_commission_outputs WHERE main_chain_index=0` — the genesis unit's headers commission never appears, and no `headers_commission` input referencing `from_main_chain_index<=0` can ever be validly composed or spent (`inputs.js` `getMaxSpendableMciForLastBallMci`, `validation.js` lines 2579-2599 reading `mc_outputs.readNextSpendableMcIndex` starting from `max_spendable_mci`, which never includes mci 0 for the genesis payer). The value is permanently frozen.

I was unable to fully verify the exact byte magnitude of the genesis unit's `headers_commission` field (whether it is nonzero by default in this repo's genesis-generation tooling) due to index size limits on some tooling/test-fixture files; a Devin session with full repository access could confirm the exact numeric value via `tools/` genesis-generation scripts or `initial-db` fixtures if further quantification of the loss is required.

### Citations

**File:** headers_commission.js (L88-99)
```javascript
						var arrParentUnits = storage.assocStableUnitsByMci[since_mc_index+1].filter(function(props){return props.sequence === 'good'});
						arrParentUnits.forEach(function(parent){
							if (!assocChildrenInfosRAM[parent.unit]) {
								if (!storage.assocStableUnitsByMci[parent.main_chain_index+1]) { // hack for genesis unit where we lose hc
									if (since_mc_index == 0)
										return;
									throwError("no storage.assocStableUnitsByMci[parent.main_chain_index+1] on " + parent.unit);
								}
								var next_mc_unit_props = storage.assocStableUnitsByMci[parent.main_chain_index+1].find(function(props){return props.is_on_main_chain});
								if (!next_mc_unit_props) {
									throwError("no next_mc_unit found for unit " + parent.unit);
								}
```

**File:** headers_commission.js (L261-266)
```javascript
function initMaxSpendableMci(conn, onDone){
	conn.query("SELECT MAX(main_chain_index) AS max_spendable_mci FROM headers_commission_outputs", function(rows){
		max_spendable_mci = rows[0].max_spendable_mci || 0; // should be -1, we lose headers commissions paid by genesis unit
		if (onDone)
			onDone();
	});
```

**File:** main_chain.js (L1676-1689)
```javascript
	function calcCommissions(){
		if (mci === 0)
			return handleAATriggers();
		async.series([
			function(cb){
				profiler.start();
				headers_commission.calcHeadersCommissions(conn, cb);
			},
			function(cb){
				profiler.stop('mc-headers-commissions');
				paid_witnessing.updatePaidWitnesses(conn, cb);
			}
		], handleAATriggers);
	}
```
