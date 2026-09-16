## Title
Front-runnable capped-asset issuance can permanently DoS an AA's token-issuance/finalization logic - (File: `aa_composer.js`)

### Summary
The Autonomous Agent (AA) engine's automatic asset-issuance logic in `handleTrigger()`'s `issueAsset()` assumes that a capped asset can only ever be issued once and that, when the AA itself performs that issuance, it is the sole possible issuer. This assumption is not enforced when the underlying asset is defined with `issued_by_definer_only: false`. In that case, any unprivileged wallet can post an ordinary `issue`-type payment unit for the same capped asset before the AA gets to run its own issuance message. The AA's "already issued" check is global (not scoped to the AA's address), so the pre-emptive external issuance permanently blocks the AA from ever completing its designed issuance step — mirroring the reported Uniswap `pool.initialize()` front-running DoS, where a one-time initialization action, meant to be performed as part of a controlled finalization flow, can instead be completed early by an outsider, permanently breaking the finalizer.

### Finding Description
In `aa_composer.js`, when an AA response message issues a capped asset, the code checks whether the asset has already been issued via a query that is **not** scoped to the AA's own address: [1](#0-0) 

The guard `if (objAsset.issued_by_definer_only && address !== objAsset.definer_address) return cb2("not a definer");` only prevents non-definer issuance when `issued_by_definer_only` is `true`. The comment `// only our AA can issue, no unstable consensus-breaking issues possible` on the `objAsset.cap` branch reveals the code's implicit assumption that "capped" implies "definer-only issuance" — but nothing enforces that pairing.

`validateAssetDefinition()` allows `cap` and `issued_by_definer_only: false` to coexist; it only forbids the combination `issued_by_definer_only === true` together with `is_private`/`fixed_denominations`: [2](#0-1) 

When `issued_by_definer_only` is `false`, ordinary (non-AA) issuers are explicitly allowed to submit `type: "issue"` inputs, since the "definer-only" restriction in payment validation is skipped: [3](#0-2) 

For a capped asset, `serial_number` must be `1` for any issuer: [4](#0-3) 

Once such an outside issuance unit becomes stable/good, `aa_composer.js`'s `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` (line 1196) finds a matching row and permanently returns `'already issued'` for every future attempt by the AA to run its own issuance message — the AA's issuance logic can never succeed again for that asset. The AA-authored sample scripts in the codebase (`test/samples/create_an_asset.oscript`, `ico_with_milestones.oscript`, `futures_contract.oscript`, `fundraising_proxy.oscript`) all rely on this same asset-definition/issuance pattern and expose `cap`/`issued_by_definer_only` as constants or, in `create_an_asset.oscript`, directly from `trigger.data`, showing this is a standard AA idiom that a developer can easily misconfigure (or that a malicious trigger can influence) into the vulnerable `cap + issued_by_definer_only:false` combination: [5](#0-4) 

This is the direct analog of the reported bug: a one-time "initializer" (issuing the fixed, capped total supply — analogous to `UniswapV3Pool.initialize()`) that is supposed to happen only inside a controlled orchestration step (the AA's finalization logic) can instead be completed by an unprivileged third party ahead of time, permanently DoSing the orchestrator's own completion path.

### Impact Explanation
Any AA that defines a capped asset without restricting issuance to itself (`issued_by_definer_only:false` + `cap`) can be permanently denied the ability to issue that asset. Because many AA templates use capped assets to represent a fixed total supply distributed to depositors/investors (ICO-style flows, fundraising proxies, token launches), a griefer can:
1. Observe the AA definition (public) and identify the future asset id (deterministic from the defining unit).
2. Race the AA and submit their own `issue` unit for that asset with `serial_number=1`, `amount=cap`, before the AA's issuance trigger fires.
3. Permanently break the AA's issuance logic — the AA response bounces with `'already issued'` every time thereafter.

This freezes AA logic that depends on that asset ever being issued (e.g., distribution of the fixed-supply token to contributors), which is a concrete AA fund-freezing/denial-of-service impact, matching the accepted impact classes (AA fund loss or freezing).

### Likelihood Explanation
Likelihood is Medium: it requires the AA author to expose (or a trigger to control) the `issued_by_definer_only:false` + `cap` combination, which the validation layer explicitly permits and which the AA-composer code comments show was not anticipated (`// only our AA can issue, no unstable consensus-breaking issues possible`). No special privileges are required by the attacker — they only need to post an ordinary payment unit with a standard `issue` input, something any unprivileged wallet can do.

### Recommendation
- Enforce that `cap` can only be combined with `issued_by_definer_only: true` at the asset-definition validation layer (`validateAssetDefinition` in `validation.js`), closing off the vulnerable combination entirely, or
- In `aa_composer.js`'s `issueAsset()`, when `objAsset.cap` is set but `issued_by_definer_only` is `false`, scope the "already issued" check and/or refuse to issue if the AA is not the guaranteed sole issuer, so the AA's own accounting cannot be permanently blocked by external issuers.

### Proof of Concept
1. Deploy an AA whose `asset` message defines an asset with `cap: 1e6`, `issued_by_definer_only: false` (as is technically permitted by `create_an_asset.oscript`-style templates, `validation.js:2725-2743`).
2. As soon as the asset-defining unit is known (its unit hash is the asset id, computable immediately after the AA's response), submit an ordinary wallet-composed unit with a payment message: `asset: <new_asset_id>, inputs: [{type:"issue", amount:1e6, serial_number:1}], outputs: [...]`.
3. Once this unit is validated (`validation.js:2311-2324`, `2099-2111` allow it because `issued_by_definer_only` is `false`), the `inputs` table has a `type='issue'` row for the asset.
4. Trigger the AA's intended issuance message; `aa_composer.js:1195-1200` finds the pre-existing row and returns `'already issued'`, permanently bouncing the AA's issuance logic for that asset.

### Citations

**File:** aa_composer.js (L1175-1201)
```javascript
			function issueAsset(cb2) {
				var objAsset = assetInfos[asset];
				if (objAsset.issued_by_definer_only && address !== objAsset.definer_address)
					return cb2("not a definer");
				var issue_amount = objAsset.cap || (target_amount - total_amount);

				function addIssueInput(serial_number){
					var input = {
						type: "issue",
						amount: issue_amount,
						serial_number: serial_number
					};
					payload.inputs.unshift(input);
					total_amount += issue_amount;
					var change_amount = total_amount - target_amount;
					if (change_amount > 0)
						payload.outputs.push({ address: address, amount: change_amount });
					cb2();
				}
				
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
				}
```

**File:** validation.js (L2099-2111)
```javascript
		var bIssue = (payload.inputs[0].type === "issue");
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

**File:** validation.js (L2311-2324)
```javascript
					if (input_index !== 0)
						return cb("issue must come first");
					if (hasFieldsExcept(input, ["type", "address", "amount", "serial_number"]))
						return cb("unknown fields in issue input");
					if (!isPositiveInteger(input.amount))
						return cb("amount must be positive");
					if (input.amount > constants.MAX_CAP)
						return cb("issue amount too large: " + input.amount)
					if (!isPositiveInteger(input.serial_number))
						return cb("serial_number must be positive");
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
```

**File:** validation.js (L2725-2743)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");

	if (objValidationState.bAA) {
		if (payload.cosigned_by_definer !== false)
			return callback("cosigned_by_definer must be false because AAs can't cosign");
		if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
			return callback("assets issued by AA definer cannot be private or fixed denominations");
	}
```

**File:** test/samples/create_an_asset.oscript (L1-24)
```text
{
	bounce_fees: { base: 11000 },
	messages: {
		cases: [
			{
				if: "{trigger.data.define}",
				messages: [
					{
						app: 'asset',
						payload: {
							cap: "{trigger.data.cap otherwise ''}",
							is_private: false,
							is_transferrable: true,
							auto_destroy: "{!!trigger.data.auto_destroy}",
							fixed_denominations: false,
							issued_by_definer_only: "{!!trigger.data.issued_by_definer_only}",
							cosigned_by_definer: false,
							spender_attested: "{!!trigger.data.attestor1}",
							attestors: [
								"{trigger.data.attestor1 otherwise ''}",
								"{trigger.data.attestor2 otherwise ''}",
								"{trigger.data.attestor3 otherwise ''}",
							]
						}
```
