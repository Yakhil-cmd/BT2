### Title
Missing asset-equality check when validating transfer inputs for private fixed-denomination assets - (File: validation.js)

### Summary
In `validatePaymentInputsAndOutputs()`, the code path that validates a `transfer` input for a **private, fixed-denomination asset** relies on a pre-populated `objValidationState.src_coin` object and only checks that the **denomination** matches, never that the **asset** of the source coin matches `payload.asset`. This mirrors the PoolTogether H-04 pattern: a value-bearing object is accepted into a different "pool" (here, a different asset/coin type) after checking only a superficial attribute (denomination) rather than the identity of the underlying asset.

### Finding Description
For ordinary transfers (public assets, or private assets looked up from the DB), `validatePaymentInputsAndOutputs()` explicitly enforces that the spent output's asset matches the payload's asset: [1](#0-0) 

However, for **private, fixed-denomination** assets, the source coin is not looked up from the database — it is taken from `objValidationState.src_coin`, which was pre-populated earlier in the private-payment-chain validation flow (in `indivisible_asset.js`). In this branch, the code checks address ownership, `denomination`, `auto_destroy`, and attestation, but it never compares `src_coin.asset` (or any asset identifier) against `payload.asset`: [2](#0-1) 

Compare this to the DB-backed path a few lines below, where the equivalent check `if (!(!payload.asset && !src_output.asset || payload.asset === src_output.asset)) return cb("asset mismatch");` is present: [3](#0-2) 

The private-payment chain entry point, `validateAndSavePrivatePaymentChain()` in `private_payment.js`, reads the asset from the head element of the chain and delegates the rest of the chain-walking/validation to `indivisible_asset.js` or `divisible_asset.js`: [4](#0-3) [5](#0-4) 

Because I could not fully inspect `indivisible_asset.js`'s internal logic for how `src_coin` (and its implicit asset) is derived and cross-checked against `payload.asset` at each hop of the private chain, I cannot confirm with certainty whether an equivalent asset-match check is enforced *elsewhere* in that module before reaching `validation.js`. This is the main source of uncertainty in this finding — the missing check is definitively absent in `validation.js` itself, but whether it is redundantly guaranteed upstream is unverified.

### Impact Explanation
If the asset identity of a private fixed-denomination coin is not cross-checked against the `payload.asset` declared in the unit's message at this validation layer, an attacker who can influence the pre-populated `src_coin` (e.g., by crafting a private payment chain response, or via a bug in the upstream chain-walking logic in `indivisible_asset.js`) could get a coin of one asset accepted as spend for a different asset — analogous to the H-04 exploit where a higher-valued token (WETH) was accepted in place of a lower-valued one (DAI). This would let an attacker inflate their apparent balance of a target private asset using a coin belonging to a different asset, i.e., asset-transfer/spend-condition bypass and potential double-spend/inflation of the private asset's effective supply.

### Likelihood Explanation
Medium. This is not directly triggerable by an ordinary poster in a single step; it depends on whether `indivisible_asset.js` guarantees `src_coin`'s asset consistency before calling into `validatePaymentInputsAndOutputs()`. Given the explicit, mirrored check that exists for the DB-lookup path but is absent for the `src_coin` (private chain) path, this looks like an intentional omission based on an implicit assumption that the caller only ever passes coins of the correct asset — the same kind of implicit-trust assumption that caused H-04 in the reference report. If that upstream invariant is ever violated (e.g. a code change to `indivisible_asset.js`, or a private-chain response crafted by a malicious peer that reaches a light client's local validation), the missing check in `validation.js` provides no defense-in-depth.

### Recommendation
Add an explicit assertion in the `src_coin` branch of `validatePaymentInputsAndOutputs()` (validation.js, around line 2428) that `src_coin.asset` (or the asset value implicitly known when `src_coin` was constructed) equals `payload.asset`, mirroring the check already present for DB-backed transfers at line 2477. This closes the gap regardless of whether the invariant is currently (perhaps only incidentally) maintained by `indivisible_asset.js`.

### Proof of Concept
Conceptual (not confirmed as directly triggerable without deeper access to `indivisible_asset.js`'s chain-walking code, which the index did not fully expose):
1. Attacker crafts/receives a private payment chain response where the private element chain nominally declares `asset = X` (fixed-denomination, private) in `headElement.payload.asset`.
2. During validation, `objValidationState.src_coin` gets populated from data that — due to a bug or a maliciously crafted chain response — actually corresponds to a **different** private fixed-denomination asset `Y` with the same denomination but higher value/cap.
3. In `validatePaymentInputsAndOutputs()`'s `transfer` branch (validation.js:2415-2441), only `denomination` is checked; the mismatched `asset` is never detected, so the input is accepted as valid spend of asset `X`.
4. The attacker's unit is accepted, crediting them with `X`-denominated value derived from a coin that was actually of asset `Y`, enabling value extraction from asset `X`'s consumers analogous to pocketing the WETH/DAI valuation difference in the H-04 report. [2](#0-1) [3](#0-2)

### Citations

**File:** validation.js (L2415-2441)
```javascript
					if (objAsset && objAsset.is_private && objAsset.fixed_denominations){
						if (!objValidationState.src_coin)
							throw Error("no src_coin");
						var src_coin = objValidationState.src_coin;
						if (!src_coin.src_output)
							throw Error("no src_output");
						if (!isPositiveInteger(src_coin.denomination))
							throw Error("no denomination in src coin");
						if (!isPositiveInteger(src_coin.amount))
							throw Error("no src coin amount");
						var owner_address = src_coin.src_output.address;
						if (arrAuthorAddresses.indexOf(owner_address) === -1)
							return cb("output owner is not among authors");
						if (denomination !== src_coin.denomination)
							return cb("private denomination mismatch");
						if (objAsset.auto_destroy && owner_address === objAsset.definer_address)
							return cb("this output was destroyed by sending to definer address");
						if (objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
							return cb("owner address is not attested");
						if (arrInputAddresses.indexOf(owner_address) === -1)
							arrInputAddresses.push(owner_address);
						total_input += src_coin.amount;
						console.log("-- val state "+JSON.stringify(objValidationState));
					//	if (objAsset)
					//		profiler2.stop('validate transfer');
						return checkInputDoubleSpend(cb);
					}
```

**File:** validation.js (L2475-2478)
```javascript
							if (typeof src_output.amount !== 'number')
								throw Error("src output amount is not a number");
							if (!(!payload.asset && !src_output.asset || payload.asset === src_output.asset))
								return cb("asset mismatch");
```

**File:** private_payment.js (L23-45)
```javascript
function validateAndSavePrivatePaymentChain(arrPrivateElements, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("no priv elements array");
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
	var asset = headElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in head element");
	if (!ValidationUtils.isNonnegativeInteger(headElement.message_index))
		return callbacks.ifError("no message index in head private element");
	
	var validateAndSave = function(){
		storage.readAsset(db, asset, null, function(err, objAsset){
			if (err)
				return callbacks.ifError(err);
			if (objAsset.is_private !== 1)
				return callbacks.ifError("asset is not private");
			if (!!objAsset.fixed_denominations !== !!headElement.payload.denomination)
				return callbacks.ifError("presence of denomination field doesn't match the asset type");
			if (!!objAsset.fixed_denominations !== ("output" in headElement))
				return callbacks.ifError("divisible asset must not have output field, indivisible must");
			db.takeConnectionFromPool(function(conn){
```

**File:** private_payment.js (L104-105)
```javascript
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
```
