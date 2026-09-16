### Title
Capped divisible-asset supply inflation via per-address double-spend scoping bypasses cap enforcement - ([File: validation.js])

### Summary
The ChainSwap exploit abused a bridge auth check that only tracked *per-transaction signer addresses* rather than a global mint ledger, letting the attacker mint unlimited tokens by rotating the destination/signer address on each call. `ocore`'s divisible-payment issue-input validation has the same class of flaw: for a capped custom asset that is not `issued_by_definer_only`, the double-spend uniqueness check that is supposed to enforce "only one issuance of the cap" is scoped by `address`, so a different author address can re-issue the full cap again.

### Finding Description
In `validatePaymentInputsAndOutputs` (validation.js), when an `issue` input is processed for a capped asset, `serial_number` is forced to `1`: [1](#0-0) 

and for assets with a `cap` (and not `fixed_denominations`) the issued amount must equal the full cap: [2](#0-1) 

The uniqueness/double-spend key that is meant to prevent this cap-issuance from happening more than once is built as: [3](#0-2) 

Critically, the `address` predicate is only added to the double-spend `WHERE` clause when `objAsset.issued_by_definer_only` is false: [4](#0-3) 

This means the "already issued" check for a capped asset is effectively: *"has this exact address already issued serial_number=1 at this denomination?"* rather than *"has anyone already issued this capped asset?"*. Because `issue_amount` for a capped divisible asset must equal `objAsset.cap` exactly, any new author address that has never issued this asset before can author a fresh unit with an `issue` input of `type=issue, serial_number=1, amount=cap, address=<new address>` and it passes both the per-input checks and the double-spend query (which finds no prior row for that specific address). The `and`/`or` address-rotation trick from ChainSwap ("use a new address each tx to dodge the auth check") maps directly onto rotating the multi-authored issuer address on the `issue` input.

The only requirement enforced elsewhere is that the issuer address be among `arrAuthorAddresses` for multi-authored units, and (if `issued_by_definer_only` is set) that it equal the definer: [5](#0-4) 

but for any asset defined with `issued_by_definer_only: false` (the default/common configuration for freely-issuable capped tokens), any address can act as issuer, and the per-address scoping of the uniqueness check lets each new address mint the entire cap again.

### Impact Explanation
This is a direct asset supply-inflation bug: the "cap" on a divisible custom asset is not actually a global cap when `issued_by_definer_only` is false — it can be issued once per distinct author address, unboundedly, by simply using a fresh address for each issuing unit (trivial and free to generate, same as rotating an EOA in the ChainSwap case). This lets an attacker mint unlimited additional supply of any such capped asset, destroying its scarcity guarantee and enabling drains of any AMM/DEX pools or protocols relying on the advertised fixed cap, analogous to the WILD token being minted far beyond intended supply and dumped for real value in the ChainSwap incident.

### Likelihood Explanation
High. No special privilege is needed — this only requires posting ordinary multi-authored `payment`/`issue` units referencing a target capped asset with `issued_by_definer_only: false`, using a new never-before-used address as the "issuer" address each time. It is trivially repeatable and matches exactly the "unprivileged unit poster" and "asset issuance and transfer conditions" reachable surface called out in scope.

### Recommendation
For capped, non-`issued_by_definer_only` divisible assets, the double-spend/uniqueness key for the `issue` input must not include `address` — the cap should be enforced globally per `(asset, denomination, serial_number)` regardless of which address performs the issuance, mirroring how indivisible/fixed-denomination assets enforce global uniqueness via `asset_denominations.max_issued_serial_number` (see `indivisible_asset.js:517-540`). Alternatively, require that only a single, pre-registered issuer (or the definer) can issue a capped asset unless the whole design intentionally allows one issuance per address (in which case documentation/wallet UX must make clear that "cap" for such assets is *per-issuer*, not global, and downstream consumers should not treat it as a hard total-supply limit).

### Proof of Concept
1. Define asset `A` with `cap: 1000000`, `issued_by_definer_only: false`, `fixed_denominations: false`, `cosigned_by_definer: false`.
2. Address `X1` posts a multi-authored unit containing a `payment` message for asset `A` with `inputs: [{type:"issue", serial_number:1, amount:1000000, address:X1}]` and appropriate outputs — this succeeds and is the "intended" one-time cap issuance.
3. Generate a brand-new address `X2` (free, instant), author another multi-authored unit for asset `A` with `inputs: [{type:"issue", serial_number:1, amount:1000000, address:X2}]`.
4. Validation in `validatePaymentInputsAndOutputs` builds `doubleSpendWhere = "type='issue' AND denomination=? AND serial_number=? AND address=?"` with `address=X2`; the query finds no existing row (only `X1`'s issuance exists), so validation passes and a second full-cap issuance of 1,000,000 units of asset `A` is accepted.
5. Repeat with `X3, X4, …` to mint arbitrarily many multiples of the "capped" supply.

### Citations

**File:** validation.js (L2100-2111)
```javascript
		var issuer_address;
		if (bIssue){
			if (arrAuthorAddresses.length === 1)
				issuer_address = arrAuthorAddresses[0];
			else{
				issuer_address = payload.inputs[0].address;
				if (arrAuthorAddresses.indexOf(issuer_address) === -1)
					return callback("issuer not among authors");
			}
			if (objAsset.issued_by_definer_only && issuer_address !== objAsset.definer_address)
				return callback("only definer can issue this asset");
		}
```

**File:** validation.js (L2321-2324)
```javascript
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
```

**File:** validation.js (L2344-2347)
```javascript
					if (objAsset){
						if (objAsset.cap && !objAsset.fixed_denominations && input.amount !== objAsset.cap)
							return cb("issue must be equal to cap");
					}
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
