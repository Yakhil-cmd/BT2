## Analog Found

### Title
Inconsistent `witnessedLevelMustNotRetreatFromAllParentsUpgradeMci` boundary comparison between ancestor-inclusion and stability logic enables a one-MCI double-spend/consensus window at hard-fork activation - (File: `graph.js` / `main_chain.js`)

### Summary
The reported zkSync bug stems from a hard-fork migration boundary check (`_l2BatchNumber < eraFirstPostUpgradeBatch`) that is evaluated inconsistently around the exact upgrade point, letting a withdrawal that should still be treated as "legacy" slip through the new code path and be paid twice. `ocore--018` uses an analogous pattern: hard-fork activation points are gated by comparing `main_chain_index`/`first_unstable_mc_index` against named `...UpgradeMci` constants (`constants.js`), and the same named constant `witnessedLevelMustNotRetreatFromAllParentsUpgradeMci` is used to gate the *same* consensus rule ("witnessed level must not retreat") in two different functions, but with **different comparison operators**.

### Finding Description
In `graph.js`, the ancestor-inclusion algorithm `determineIfIncluded` (used to resolve whether a conflicting/double-spend unit is a genuine ancestor of the current unit) prunes a candidate path only when the unit's main chain index is strictly greater than the threshold: [1](#0-0) 
```
if (objUnitProps.witnessed_level < objEarlierUnitProps.witnessed_level && objEarlierUnitProps.main_chain_index > constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci)
    continue;
```

But in `main_chain.js`, the equivalent pruning rule inside `determineIfStableInLaterUnits` (used to decide MC stability, i.e. whether a unit and its outputs become final/spendable) applies the *stricter* new rule one MCI earlier, using `>=`: [2](#0-1) 
```
|| row.witnessed_level > max_later_witnessed_level && first_unstable_mc_index >= constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci
```

Both functions reference the exact same activation constant defined once in `constants.js`: [3](#0-2) 
```
exports.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci = exports.bTestnet ? 909000 : 5210000;
exports.timestampUpgradeMci = exports.bTestnet ? 909000 : 5210000;
```

For a unit whose `main_chain_index`/`first_unstable_mc_index` equals exactly `witnessedLevelMustNotRetreatFromAllParentsUpgradeMci`, `graph.js` still applies the *old, more permissive* rule (no pruning at `==`), while `main_chain.js` already applies the *new, stricter* rule (pruning at `==`). This is the same class of bug as the zkSync report: two related consensus-critical checks that are supposed to activate at the same hard-fork point use inconsistent boundary comparisons (`>` vs `>=`), producing a one-MCI window where "is this unit really an ancestor / is the DAG state final" is answered differently depending on which code path evaluates it.

`determineIfIncluded`/`determineIfIncludedOrEqual` from `graph.js` is directly used by the double-spend resolution logic in `validation.js`'s `checkForDoublespends`, to decide whether a conflicting input record is a genuine in-DAG ancestor conflict (which must be rejected) or an unrelated fork (which is tolerated as a resolvable double-spend): [4](#0-3) 

### Impact Explanation
At the exact activation MCI of `witnessedLevelMustNotRetreatFromAllParentsUpgradeMci`, the ancestor/conflict determination used for double-spend resolution (`graph.js`) can classify a candidate path differently than the stability algorithm (`main_chain.js`) that decides whether the same unit's outputs are already final and spendable. This mismatch means a payment output whose finality/ancestor status is borderline at the hard-fork boundary can be resolved inconsistently between the two subsystems that jointly guard against double-spending a stable output — i.e., exactly the "resource is treated as already-migrated by one check but not-yet-migrated by the other" pattern that allowed the double withdrawal in the zkSync report.

### Likelihood Explanation
This only manifests for units whose `main_chain_index` is exactly equal to the hard-coded upgrade constant (a single, deterministic MCI value, occurring once per network history for both mainnet, `5210000`, and testnet, `909000`), and only when there exist alt-branch/fork units at that specific MCI with retreating witnessed levels — a narrow but fully deterministic and already-passed condition on both networks, so it is not exploitable going forward but demonstrates the underlying bug class (inconsistent hard-fork boundary conditions across cooperating consensus functions) that the report warns about.

### Recommendation
Audit every pair of functions that reference the same `...UpgradeMci` constant to confirm they use the identical comparison operator (`>`, `>=`, `<`, `<=`) at the activation boundary, and add regression tests that construct units with `main_chain_index` exactly equal to each upgrade constant to verify `graph.determineIfIncluded`, `main_chain.determineIfStableInLaterUnits`, and `validation.checkForDoublespends` all agree on ancestor/finality status at that boundary.

### Proof of Concept
1. Construct (or replay from historical DAG data) two competing branches where a witness's unit posted at `main_chain_index == constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci` has a witnessed level lower than a sibling on an alternate branch.
2. Call `graph.determineIfIncludedOrEqual(conn, conflicting_unit, arrLaterUnits, ...)` (as invoked from `checkForDoublespends` in `validation.js`) — the `>` comparison in `graph.js:224` means the retreat-pruning rule is *not* applied yet at this exact MCI, so the traversal continues past this unit.
3. Separately, call `main_chain.determineIfStableInLaterUnits` for the same unit — the `>=` comparison in `main_chain.js:999` means the retreat-pruning rule *is* already applied.
4. Compare the two results at `main_chain_index == threshold`: `graph.js` and `main_chain.js` disagree on whether the branch containing the conflicting unit should be considered for stability/inclusion purposes, demonstrating the inconsistent hard-fork boundary handling.

### Citations

**File:** graph.js (L224-225)
```javascript
					if (objUnitProps.witnessed_level < objEarlierUnitProps.witnessed_level && objEarlierUnitProps.main_chain_index > constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci)
						continue;
```

**File:** main_chain.js (L996-1002)
```javascript
									else if (
										row.is_free === 1
										|| row.level >= max_later_level
										|| row.witnessed_level > max_later_witnessed_level && first_unstable_mc_index >= constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci
										|| row.latest_included_mc_index > max_later_limci
										|| row.is_on_main_chain && row.main_chain_index > max_later_limci
									){
```

**File:** constants.js (L92-93)
```javascript
exports.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci = exports.bTestnet ? 909000 : 5210000;
exports.timestampUpgradeMci = exports.bTestnet ? 909000 : 5210000;
```

**File:** validation.js (L1676-1689)
```javascript
					graph.determineIfIncludedOrEqual(conn, objConflictingRecord.unit, objUnit.parent_units, function(bIncluded){
						if (bIncluded){
							var error = objUnit.unit+": conflicting "+type+" in inner unit "+objConflictingRecord.unit;

							// too young (serial or nonserial)
							if (objConflictingRecord.main_chain_index > objValidationState.last_ball_mci || objConflictingRecord.main_chain_index === null)
								return cb2(error);

							// in good sequence (final state); final-bad is excluded by the query and treated as non-existent
							if (objConflictingRecord.sequence === 'good')
								return cb2(error);

							throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);
						}
```
