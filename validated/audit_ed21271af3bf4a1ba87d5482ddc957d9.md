### Title
Capped-asset issuance in AA responses can be permanently front-run/DOSed, diverting or freezing the AA's one-time issuance - (File: aa_composer.js)

### Summary
`TpdaLiquidationPair.swapExactAmountOut()` was DOSable because the "available balance" it checks against (`liquidatableBalanceOf`) is a single shared, globally-capped resource (a vault's mint limit) that any unprivileged actor could race to consume, causing legitimate callers to revert. The closest reachable analog in `ocore` is the capped-asset issuance path executed inside AA responses in `aa_composer.js`'s `issueAsset()`. For a capped asset, the code treats "has anyone ever issued this asset" as a single, permanently-exhaustible, address-independent flag, checked with `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` [1](#0-0) . Whoever's trigger causes the AA to execute this code path *first* consumes the entire capped supply forever; every other (including the intended/legitimate) trigger that later reaches the same `issueAsset()` call for the same asset unconditionally fails.

### Finding Description
When an AA response includes a payment message for a capped asset (`objAsset.cap` truthy), the composer computes `issue_amount = objAsset.cap || (target_amount - total_amount)` and, for capped assets, only allows the amount to be issued once, ever, regardless of which trigger/address caused it: [2](#0-1) 

```js
function issueAsset(cb2) {
    var objAsset = assetInfos[asset];
    if (objAsset.issued_by_definer_only && address !== objAsset.definer_address)
        return cb2("not a definer");
    var issue_amount = objAsset.cap || (target_amount - total_amount);
    ...
    if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
        conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
            if (rows.length > 0) // already issued
                return cb2('already issued');
            addIssueInput(1);
        });
    }
```

Because `issued_by_definer_only` is mandatory for any capped asset (`if (payload.cap && !payload.issued_by_definer_only) return callback("if capped, must be issued by definer only")` [3](#0-2) ), issuance is gated on `address === objAsset.definer_address`, i.e. the AA itself, but the trigger that *causes* the AA to reach this code path can come from any unprivileged sender. Multiple concurrent/independent triggers to the same AA — sent by different, unrelated users, or by a single attacker deliberately racing a legitimate user's trigger — can each independently cause the AA to attempt issuing the same capped asset in the same execution window before either is stabilized. Whichever trigger's AA-response unit gets included/stabilized first wins the entire capped supply; the `"already issued"` check makes every subsequent attempt fail (`'not enough funds for X of asset Y'` from the caller `issueAsset(function(err){...return cb('not enough funds for ' + target_amount + ' of asset ' + asset);})` at [4](#0-3) ), forcing the AA response to bounce for the legitimate trigger.

This mirrors the reported bug class precisely: a globally shared, capped, one-shot resource (`liquidatableBalanceOf`'s mint-limit ↔ ocore's "already issued" capped-asset flag) that is checked by amount/availability rather than by caller identity or intended recipient, so any unprivileged party who can post a trigger unit can race to consume it and permanently deny/redirect the resource away from the intended, honest trigger sender.

### Impact Explanation
An attacker who can predict or observe that an AA is about to issue a capped asset (e.g., a one-time token sale/airdrop/ICO-style AA that issues capped shares/tokens in response to a deposit trigger) can send their own qualifying trigger to the same AA so that their own trigger's response consumes the capped issuance first. The legitimate user's trigger then bounces (loses at minimum its bounce fee, and does not receive the capped asset it paid for), while the attacker walks away with the entire capped supply of the asset for a fraction of the intended cost/effort, or the AA becomes permanently unable to fulfill its intended one-time issuance to anyone else. This is a concrete case of unauthorized diversion of AA-controlled asset issuance / fund loss for the intended trigger sender, and a form of permanent DOS of a specific AA feature (one-time capped issuance) for all future callers, matching the "AA fund loss or freezing" and "unable to confirm intended issuance" impact categories.

### Likelihood Explanation
Any address can post a trigger unit to a public AA; no special privilege, key leak, or malicious-node/hub behavior is required — this is purely a self-issued unit racing another self-issued unit, exactly the kind of "unprivileged AA trigger sender" scenario within scope. The race requires the attacker to be aware of the AA's capped-issuance logic and to structure their own trigger to satisfy the AA's conditions for issuing the capped asset (which is discoverable by reading the AA's public `oscript`/definition), making this a realistic, low-capital attack (unlike the original Solidity bug, which needed large capital to approach `type(uint96).max`). This makes the ocore analog arguably *easier* to trigger than the original finding.

### Recommendation
For capped assets issued from within an AA, do not treat "already issued" as a single global flag decoupled from the specific trigger/state that authorizes it. Options:
- Gate capped issuance behind an AA state variable (e.g., an explicit "already_issued" flag stored and checked/set atomically within the same AA execution, tied to specific trigger data/recipient) rather than relying purely on a database query for any existing `type='issue'` input for the asset, so that only the intended trigger (as determined by the AA's own oscript logic) can cause the one-time issuance, and races between unrelated triggers are resolved deterministically by the AA's own state rather than by pure MCI/inclusion order of unrelated units.
- Document explicitly that AAs designed to issue capped assets once in response to a trigger must implement double-issuance protection via their own state variables (checking/setting a var before calling the issuing payment message) rather than depending on `aa_composer.js`'s low-level `"already issued"` guard as their sole double-spend protection, since that guard is asset-scoped, not trigger/recipient-scoped.

### Proof of Concept
1. Deploy an AA whose `oscript` defines a capped asset (`cap: <fixed or trigger-derived formula>`, `issued_by_definer_only: true`) and, upon receiving a qualifying trigger (e.g., `trigger.data.buy` present and `trigger.output[[asset=base]] >= X`), sends a payment message for that asset to `trigger.address`.
2. User A sends unit U_A (a valid, qualifying trigger) intending to receive the capped supply.
3. Attacker observes U_A in the network (before it is included in a stable MC unit) and immediately sends unit U_B with an equally qualifying trigger, engineered to be picked up and stabilized before or in the same batch as U_A.
4. Whichever trigger's AA response reaches `issueAsset()` first succeeds; the "already issued" query `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` [1](#0-0)  then makes the other trigger's AA response fail with `'not enough funds for ... of asset ...'` [4](#0-3) , causing it to bounce.
5. Repeat with different attacker addresses/units to reliably win the race against any specific victim trigger, since the check depends only on the asset (not the trigger's identity), and only the AA (`definer_address`) is required as the input address in the resulting `issue` input, not any specific trigger sender.

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

**File:** aa_composer.js (L1236-1240)
```javascript
					issueAsset(function (err) {
						if (err) {
							console.log("issue failed: " + err);
							return cb('not enough funds for ' + target_amount + ' of asset ' + asset);
						}
```

**File:** validation.js (L2802-2803)
```javascript
	if (payload.cap && !payload.issued_by_definer_only)
		return callback("if capped, must be issued by definer only");
```
