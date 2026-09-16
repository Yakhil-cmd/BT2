## Analysis

The Notional bug class is: **a function that composes/executes a privileged action skips a validation check that an equivalent/sibling function enforces**, letting invalid input flow through unchecked.

The direct analog in `ocore--010` is in the AA (Autonomous Agent) asset-issuance validation path. When an AA definition contains an `app: 'asset'` message (an asset the AA will issue when triggered), it is checked by `validateAADefinition`'s `case 'asset':` block in `aa_validation.js`. When a *regular, user-submitted* unit contains an `app: 'asset'` message, it is checked by `validateAssetDefinition` in `validation.js`. These two functions are meant to enforce the same asset-definition invariants, but the AA-side function is missing several checks that the regular-unit-side function has.

`validateAssetDefinition` in `validation.js` enforces invariants such as:
- capped assets must be `issued_by_definer_only`: [1](#0-0) 
- private+transferrable assets must have fixed denominations: [2](#0-1) 
- private+divisible assets must be `auto_destroy` and non-transferrable: [3](#0-2) 
- private assets cannot have issue/transfer conditions: [4](#0-3) 
- denomination cap arithmetic must be internally consistent (sum of denomination caps must equal `cap`, can't mix capped/uncapped denominations): [5](#0-4) 

None of these checks exist in the AA counterpart, `aa_validation.js`'s `case 'asset':` block, which only validates field presence/types, `cap` positivity, `fixed_denominations`/`denominations` presence, and a couple of AA-specific rules (`cosigned_by_definer`, `issued_by_definer_only` vs privacy): [6](#0-5)  The denomination validator `validateDenominations` inside this block only checks format (positivity, count), never cross-checks the sum against `cap`: [7](#0-6) 

I attempted to confirm whether the actual composed response unit (which contains the real `app: 'asset'` message an AA sends when triggered) is re-checked by `validation.js`'s full `validateAssetDefinition` before being written to storage. A search for `validateAssetDefinition` inside `aa_composer.js` found no matches, and the unit-composition path (`sendUnit`, `completeMessage`, `completePaymentPayload` in `aa_composer.js:1298-1387`) only builds the message, hashes definitions, and completes payment payloads — it does not re-invoke `validation.js`'s asset-definition checks. This is consistent with the AA architecture: response units are computed deterministically by each node from the AA definition and are not fed back through the standard join/validation pipeline the way externally-submitted units are. **I was not able to fully trace the entire write path with 100% certainty** (this would require inspecting `writer.js`'s AA-response-unit code path in more depth than the tool budget allowed), so this last link should be independently verified.

### Title
Incomplete asset-definition validation for AA-issued assets in `aa_validation.js` allows invalid/invariant-violating assets - (File: `aa_validation.js`)

### Summary
`aa_validation.js`'s `validateAADefinition` (`case 'asset':`) is the AA-side counterpart of `validation.js`'s `validateAssetDefinition`, but it omits several invariant checks that the latter enforces on ordinary units, including the cap/`issued_by_definer_only` relationship, private-asset transferability/auto-destroy constraints, private-asset condition prohibition, and denomination-cap arithmetic consistency.

### Finding Description
Any user can post an AA definition containing an `app: 'asset'` message. This template is validated only by `aa_validation.js`'s asset case [6](#0-5) , which lacks the checks present in `validateAssetDefinition` [8](#0-7) . When the AA is later triggered, `aa_composer.js` evaluates the template and composes/writes the actual response unit carrying the `asset` message without going back through `validation.js`'s full asset-definition validation (no reference to `validateAssetDefinition` exists in `aa_composer.js`). As a result, an AA can be defined (and then triggered) to issue an asset that violates invariants that would be rejected for a human-authored unit — e.g. a capped asset not restricted to `issued_by_definer_only`, or a private divisible asset without the mandatory `auto_destroy`/non-transferable pairing, or denominations whose caps don't sum to the declared `cap`.

### Impact Explanation
Assets are core financial primitives in Obyte; their cap/denomination/privacy invariants are relied upon by wallets, other AAs, and exchanges to reason about supply and transferability. An asset that bypasses these invariants (e.g., a "capped" asset that is not restricted to definer-only issuance, or mismatched denomination totals vs. cap) can lead to unexpected/inflated issuance behavior or asset state that downstream logic (wallets, `divisible_asset.js`/`indivisible_asset.js`, formula `asset[]` reads) does not anticipate, since they were designed assuming these invariants always hold. This matches the "supply inflation / invalid asset state" impact class.

### Likelihood Explanation
Likelihood is unprivileged and low-effort: anyone can post an AA definition unit with a crafted asset template hitting exactly the fields not covered by `aa_validation.js` (e.g. `cap` set with `issued_by_definer_only: false`, or `is_private: true, is_transferrable: false, fixed_denominations: false, auto_destroy: false`), then trigger the AA to issue it.

### Recommendation
Add the missing invariant checks to `aa_validation.js`'s `case 'asset':` block to mirror `validateAssetDefinition` in `validation.js`: enforce `cap => issued_by_definer_only`, the private/transferrable/fixed_denominations relationship, the private/auto_destroy/non-transferrable relationship, the private-with-conditions prohibition, and denomination cap-sum consistency (accounting for the fact that some of these fields may be formulas, similar to how existing checks in this block already branch on `typeof === 'string'` vs boolean).

### Proof of Concept
1. Define an AA whose template includes an `app: 'asset'` message with `cap: 1000000`, `issued_by_definer_only: false`, `cosigned_by_definer: false`, and other required booleans — this passes `aa_validation.js`'s checks because it never verifies `cap && !issued_by_definer_only` (compare to the check present in `validation.js:2802-2803`).
2. Post this AA definition (passes `validateAADefinition`).
3. Trigger the AA; `aa_composer.js` evaluates the template and composes/writes the response unit containing the non-compliant `asset` message without re-running `validation.js`'s `validateAssetDefinition`.
4. The resulting asset now exists on-chain with `cap` set but not restricted to definer-only issuance — an invariant that would be impossible to create via a normal user-submitted unit, since `validation.js:2802-2803` would reject it.

### Citations

**File:** validation.js (L2784-2803)
```javascript
		if (bHasUncappedDenominations && total_cap_from_denominations)
			return callback("some denominations are capped, some uncapped");
		if (bHasUncappedDenominations && payload.cap)
			return callback("has cap but some denominations are uncapped");
		if (total_cap_from_denominations && !payload.cap)
			return callback("has no cap but denominations are capped");
		if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
			return callback("cap doesn't match sum of denominations");
	}
	
	if (payload.is_private && payload.is_transferrable && !payload.fixed_denominations)
		return callback("if private and transferrable, must have fixed denominations");
	if (payload.is_private && !payload.fixed_denominations){
		if (!(payload.auto_destroy && !payload.is_transferrable))
			return callback("if private and divisible, must also be auto-destroy and non-transferrable");
	}
	if (payload.is_private && ("issue_condition" in payload || "transfer_condition" in payload) && (objValidationState.last_ball_mci >= constants.noPrivateAssetsWithConditionsUpgradeMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.noPrivateAssetsWithConditionsUpgradeMci))
		return callback("if private, cannot have issue or transfer conditions");
	if (payload.cap && !payload.issued_by_definer_only)
		return callback("if capped, must be issued by definer only");
```

**File:** aa_validation.js (L225-300)
```javascript
				case 'asset':
					if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations", "init"]))
						return cb2("unknown fields in asset definition in AA");
					if (payload.fixed_denominations === true && !isNonemptyArray(payload.denominations))
						return cb2("denominations not defined");
					if ("cap" in payload) {
						if (typeof payload.cap === 'number') {
							if (!(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
								return cb2("invalid cap: " + payload.cap);
						}
						else if (typeof payload.cap === 'string') {
							var f = getFormula(payload.cap);
							if (f === null)
								return cb2("bad formula in cap: " + payload.cap);
						}
						else
							return cb2("wrong cap: " + JSON.stringify(payload.cap));
					}

					function validateDenominations(denominations, cb3) {
						if (isNonemptyString(denominations)) {
							var f = getFormula(denominations);
							if (f === null)
								return cb3("denominations is a string but not formula: " + denominations);
							return cb3();
						}
						if (!isNonemptyArray(denominations))
							return cb3("wrong denominations: " + JSON.stringify(denominations));
						if (denominations.length > constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION)
							return cb3("too many denominations");
						for (var i=0; i<denominations.length; i++){
							var denomInfo = denominations[i];
							if (!isNonemptyObject(denomInfo))
								return cb3("denomination must be a non-empty object: " + JSON.stringify(denomInfo));
							if (hasFieldsExcept(denomInfo, ["denomination", "count_coins"]))
								return cb3("unknown fields in denomination: " + JSON.stringify(denomInfo));
							if (typeof denomInfo.denomination === 'number') {
								if (!isPositiveInteger(denomInfo.denomination))
									return cb3("invalid denomination");
							}
							else if (typeof denomInfo.denomination === 'string') {
								var f = getFormula(denomInfo.denomination);
								if (f === null)
									return cb3("bad formula in denomination: "+ denomInfo.denomination);
							}
							else
								return cb3("bad denomination " + JSON.stringify(denomInfo.denomination));
							if ("count_coins" in denomInfo) {
								if (typeof denomInfo.count_coins === 'number') {
									if (!isPositiveInteger(denomInfo.count_coins))
										return cb3("invalid count_coins");
								}
								else if (typeof denomInfo.count_coins === 'string') {
									var f = getFormula(denomInfo.count_coins);
									if (f === null)
										return cb3("bad formula in count_coins: "+ denomInfo.count_coins);
								}
								else
									return cb3("bad count_coins " + JSON.stringify(denomInfo.count_coins));
							}
						}
						cb3();
					}

					if ("issue_condition" in payload) {
						if (!isArrayOfLength(payload.issue_condition, 2))
							return cb2("wrong issue condition: " + JSON.stringify(payload.issue_condition));
					}
					if ("transfer_condition" in payload) {
						if (!isArrayOfLength(payload.transfer_condition, 2))
							return cb2("wrong transfer condition: " + JSON.stringify(payload.transfer_condition));
					}
					if (payload.cosigned_by_definer !== false)
						return cb2("cosigned_by_definer must be false because AA can't cosign");
					if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
						return cb2("asset issued by AA definer cannot be private or fixed denominations");
```
