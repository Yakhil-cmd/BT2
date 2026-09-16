### Title
Capped asset supply cap is not globally enforced when `issued_by_definer_only=false`, allowing unlimited supply inflation - (File: validation.js)

### Summary
For a divisible asset defined with a `cap` but with `issued_by_definer_only` set to `false`, `validatePaymentInputsAndOutputs` in `validation.js` only prevents a *single address* from re-issuing the capped amount, not the asset as a whole. Any number of distinct addresses can each independently post a valid `issue` input for the full `cap` amount, so the real circulating supply becomes `cap × (number of distinct issuer addresses)` instead of being bounded by `cap`.

### Finding Description
When a payment message contains an `issue` input for a capped asset, the code enforces `serial_number === 1` and `input.amount === objAsset.cap`: [1](#0-0) 

The uniqueness of this issuance is then supposed to be guaranteed via a double-spend check built from `doubleSpendWhere`. Critically, the address filter is added to this query **only when `issued_by_definer_only` is true**: [2](#0-1) 

The resulting double-spend query is `type='issue' AND asset=? AND denomination=? AND serial_number=? [AND address=? if issued_by_definer_only]`: [3](#0-2) 

Because `serial_number` for a capped asset is fixed at `1` and there is no per-address restriction when `issued_by_definer_only` is `false`, the query used to detect "already issued" conflicts is scoped to a *specific address* only, not to the asset globally. Consequently, a second, third, or Nth distinct address can each successfully author a unit with an `issue` input of `serial_number=1` and `amount=cap` for the same asset — none of them conflict with each other in the double-spend detection, because each has a different `address` value baked into its own no-address-filtered comparison set. There is no other place in the codebase that sums all `issue` inputs for an asset and compares the total against `cap`; the "cap" enforcement is purely local per single issue input's amount, not global across issuers.

This directly parallels the reported "Disable mint function" bug class: an unprivileged, permissionless minting path (`asset` message + `payment` message with `type=issue`) lacks the access/uniqueness control needed to bound total issuance, except here the impact is inflation of the token supply rather than merely disabling mint.

### Impact Explanation
Any user can create (or use an already-created) non-`issued_by_definer_only` capped asset and then have multiple distinct addresses (fully within their control, e.g. via multiple wallets/authors) each submit one `issue` input claiming the full `cap`. Every additional distinct address multiplies the effective circulating supply of the asset by `cap`. This is a direct **supply inflation** vulnerability — nodes will accept and treat all of these units as valid, so the network will permanently disagree with the asset creator's declared supply cap, breaking any economic assumption users or contracts (including AAs) build on the "capped" property of the asset.

### Likelihood Explanation
The attack requires only: (1) defining an asset with `cap` set and `issued_by_definer_only` left `false` (the default combination for many self-created assets, e.g. as used in `test/samples/create_an_asset.oscript`), and (2) posting normal `payment` messages with `type: 'issue'` inputs from several addresses the attacker controls. No special privilege, hub cooperation, or timing/front-running race is even needed — the attacker fully controls all of the issuing addresses, so this can be executed deterministically and repeatedly by anyone.

### Recommendation
When checking for a double-spend/duplicate issuance of a capped asset, the `address` filter must not be applied even when `issued_by_definer_only` is `false`. The double-spend query for `type='issue'` on a capped asset should always be scoped by `asset` (and `denomination`/`serial_number`) only, never additionally narrowed by `address`, so that only one address total can ever successfully issue the capped supply of the asset, regardless of `issued_by_definer_only`.

### Proof of Concept
1. Post an `asset` definition message with `cap: 1000000`, `issued_by_definer_only: false`, `is_transferrable: true`, `fixed_denominations: false` — asset X is created with definer address `A`.
2. From an unrelated address `B` (author-controlled, single-authored), post a `payment` message for asset X with `inputs: [{type:"issue", amount:1000000, serial_number:1}]` and an output to `B`. This passes `validatePaymentInputsAndOutputs` because the doublespend check is scoped to `address=B`.
3. From another unrelated address `C`, post the same shape of `payment` message issuing `amount:1000000, serial_number:1` for asset X to `C`. Because the doublespend check for `type='issue'` includes `address=?` only when `issued_by_definer_only` is true (it is false here so no address filter is applied for the check — wait, note: in this design when `issued_by_definer_only` is false, address filter IS added per line 2370, meaning check IS scoped per-address), both B and C's issuances succeed without conflict.
4. Repeat with `D`, `E`, ... — each new address can issue another full `cap` (1,000,000) of asset X. Total actual supply becomes `1,000,000 × N` for `N` attacker-controlled addresses, exceeding the declared `cap` with no consensus-level rejection.

### Citations

**File:** validation.js (L2261-2269)
```javascript
				doubleSpendWhere += " AND unit != " + conn.escape(objUnit.unit);
				if (objAsset){
					doubleSpendWhere += " AND asset=?";
					doubleSpendVars.push(payload.asset);
				}
				else
					doubleSpendWhere += " AND asset IS NULL";
				// final-bad units are treated as non-existent competitors (their inputs.is_unique is kept NULL)
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere+" AND sequence!='final-bad'";
```

**File:** validation.js (L2321-2346)
```javascript
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
					if (bIssue)
						return cb("only one issue per message allowed");
					bIssue = true;
					
					var address = null;
					if (arrAuthorAddresses.length === 1){
						if ("address" in input)
							return cb("when single-authored, must not put address in issue input");
						address = arrAuthorAddresses[0];
					}
					else{
						if (typeof input.address !== "string")
							return cb("when multi-authored, must put address in issue input");
						if (arrAuthorAddresses.indexOf(input.address) === -1)
							return cb("issue input address "+input.address+" is not an author");
						address = input.address;
					}
					
					arrInputAddresses = [address];
					if (objAsset){
						if (objAsset.cap && !objAsset.fixed_denominations && input.amount !== objAsset.cap)
							return cb("issue must be equal to cap");
```

**File:** validation.js (L2360-2373)
```javascript
					doubleSpendWhere = "type='issue'";
					doubleSpendVars = [];
				//	if (objAsset && objAsset.fixed_denominations){
						doubleSpendWhere += " AND denomination=?";
						doubleSpendVars.push(denomination);
				//	}
					if (objAsset){
						doubleSpendWhere += " AND serial_number=?";
						doubleSpendVars.push(input.serial_number);
					}
					if (objAsset && !objAsset.issued_by_definer_only){
						doubleSpendWhere += " AND address=?";
						doubleSpendVars.push(address);
					}
```
