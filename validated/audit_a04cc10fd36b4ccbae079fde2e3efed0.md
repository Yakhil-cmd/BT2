Confirmed: `bIssue` at line 2202 is a local variable in `validatePaymentInputsAndOutputs`, initialized to `false` and set to `true` at line ~2327 as soon as *any* input in the payload has `type === "issue"` (only one issue input is allowed per message, but it can be combined with an arbitrary number of `transfer` inputs in the same payment message, per the comment at lines 2237-2238: "max 1 issue must come first, then transfers, then hc, then witnessings"). This single message-wide `bIssue` flag is later used at line 2644 to decide which asset condition governs the *entire* payment:

```js
var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
``` [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Transfer authorization bypass via issue/transfer input mixing evaluates only `issue_condition`, skipping `transfer_condition` for the entire payment - (File: validation.js)

### Summary
`validatePaymentInputsAndOutputs` computes a single boolean `bIssue` for the whole `payment` message based on whether *any* input has `type: "issue"`, and then evaluates the asset's `issue_condition` **or** `transfer_condition` — never both — against the entire message. Because ocore payment messages allow one issue input to be combined with arbitrary transfer inputs of the same asset in a single message, an attacker can attach a nominal/self issue input to a payment whose real economic content is a transfer of already-held coins, causing the node to check only the (possibly weak or public) `issue_condition` while completely skipping the (possibly restrictive) `transfer_condition` for the transferred funds.

### Finding Description
Custom assets in ocore can define independent `issue_condition` and `transfer_condition` oscript expressions via `validateAssetDefinition`/AA `asset` messages [4](#0-3) . These are meant to enforce different authorization scopes: who/how coins may be minted vs. who/how existing coins may be moved. Enforcement happens in `validatePaymentInputsAndOutputs`:

```js
function(cb){
    var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
    if (!arrCondition)
        return cb();
    Definition.evaluateAssetCondition(
        conn, payload.asset, arrCondition, objUnit, objValidationState, ...);
}
``` [3](#0-2) 

`bIssue` is declared once per message (`var bIssue = false;`, line 2202) and flipped to `true` the moment the loop over `payload.inputs` encounters an input of `type === "issue"` (line ~2325-2327), regardless of how many other `transfer` inputs are present in the same message. The input-ordering rule explicitly permits mixing: "max 1 issue must come first, then transfers, then hc, then witnessings" [5](#0-4) . Consequently, a single payment message containing one issue input plus N transfer inputs is validated as a whole against `issue_condition` only — `transfer_condition` is never evaluated for the transfer portion of that same message, even though real, pre-existing coins are being moved to potentially arbitrary output addresses.

This mirrors the CVE's root cause: an authorization decision that is supposed to be scoped per-operation-type collapses to a single, broader classification (here "the message contains an issue" instead of "each input's condition is enforced per its own type"), silently discarding the narrower, more restrictive check.

### Impact Explanation
If an asset issuer designs `transfer_condition` to be restrictive (e.g., requiring attestation, a cosigner, a data-feed gate, or limiting recipients) while `issue_condition` is comparatively permissive (or the asset is not `issued_by_definer_only`, allowing any address to add a trivial issue input), any holder of the asset can bypass `transfer_condition` entirely by bundling a minimal self-issue input with their real transfer inputs in one payment message. This is a validator-enforced authorization bypass leading to unauthorized spending/movement of an asset that is otherwise value-restricted by its own definer's `transfer_condition`, and because all full nodes apply this same logic deterministically, transfers that should have been rejected become "good" and stabilize on the DAG.

### Likelihood Explanation
Reachable by any unprivileged unit poster who already holds outputs of a custom asset with both `issue_condition` and `transfer_condition` defined, and where issuance is not otherwise strictly gated to the definer only (or where the attacker is the definer themself, e.g. for a definer who wants their own restrictive `transfer_condition` to bind third parties but not themselves — the definer can always add a self-issue to their own spends). No special privileges, malicious peers, or timing races are required — it is a single, self-authored unit.

### Recommendation
Enforce `issue_condition` and `transfer_condition` per input type rather than for the whole message: evaluate `issue_condition` only for issue inputs and independently evaluate `transfer_condition` whenever any transfer input (of that asset) is present in the same message, requiring both to be satisfied when both input types are combined.

### Proof of Concept
1. Definer creates a custom, divisible, `is_transferrable: true`, non-capped asset with `issued_by_definer_only: false`, a permissive `issue_condition` (e.g., `['sig', {...}]` for any address), and a restrictive `transfer_condition` (e.g., requiring an `attested` check or a specific cosigner) intended to gate ordinary transfers.
2. An attacker who holds existing outputs of this asset (that do not satisfy `transfer_condition`) crafts a `payment` message with `asset` set to this custom asset, containing:
   - one `issue` input (any minimal valid amount, `serial_number: 1` since uncapped issues need not equal cap) that only needs to satisfy `issue_condition`,
   - the attacker's real `transfer` inputs spending their held (restricted) coins,
   - outputs sending the combined value to arbitrary recipient addresses.
3. In `validatePayment`/`validatePaymentInputsAndOutputs`, `bIssue` becomes `true` because the message contains an issue input, so `arrCondition = objAsset.issue_condition` is evaluated instead of `objAsset.transfer_condition` [6](#0-5) . Since the attacker's signature satisfies the permissive `issue_condition`, the whole message — including the transfer of the restricted coins — passes validation and is accepted by all nodes, even though the actual `transfer_condition` gating the transferred coins was never checked.

### Citations

**File:** validation.js (L2202-2202)
```javascript
	var bIssue = false;
```

**File:** validation.js (L2237-2238)
```javascript
	// max 1 issue must come first, then transfers, then hc, then witnessings
	// no particular sorting order within the groups
```

**File:** validation.js (L2321-2327)
```javascript
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
					if (bIssue)
						return cb("only one issue per message allowed");
					bIssue = true;
```

**File:** validation.js (L2643-2658)
```javascript
					function(cb){
						var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
						if (!arrCondition)
							return cb();
						Definition.evaluateAssetCondition(
							conn, payload.asset, arrCondition, objUnit, objValidationState, 
							function(cond_err, bSatisfiesCondition){
								if (cond_err)
									return cb(cond_err);
								if (!bSatisfiesCondition)
									return cb("transfer or issue condition not satisfied");
								console.log("validatePaymentInputsAndOutputs with transfer/issue conditions done");
								cb();
							}
						);
					}
```

**File:** validation.js (L2725-2731)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
```
