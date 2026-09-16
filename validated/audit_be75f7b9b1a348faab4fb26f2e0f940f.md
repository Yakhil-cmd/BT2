### Title
Uncapped/definer-optional AA-issued asset cap can be front-run by any address, permanently blocking the AA's own issuance - (File: aa_composer.js)

### Summary
An AA that defines a capped asset (`app: 'asset'`, `cap: N`) and later issues it via its own trigger flow relies on a single global fact - "has anyone issued this asset yet" - exactly the same class of bug as the reported `NFTMintSale` issue, where a shared, externally-influenced counter (`nft.totalSupply()`) determines how many tokens are still available. In ocore, when `issued_by_definer_only` is not forced to `true`, any unprivileged address can post an ordinary `issue` input for the capped asset before the AA does, permanently consuming the one-time issuance slot that `aa_composer.js` checks via a bare `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` query that is **not** filtered by issuer address.

### Finding Description
When an AA composes a payment message that issues its own asset, `issueAsset()` in `aa_composer.js` treats a capped asset as "single-shot": if any `issue` input for that asset already exists anywhere on the DAG, the AA's own issuance attempt is rejected with `'already issued'`. [1](#0-0) 

The comment on this code explicitly assumes "only our AA can issue" for capped assets, but that assumption is only true if `issued_by_definer_only` is `true`. Nothing in the AA-definition validator (`aa_validation.js`) or the generic asset-definition validator (`validation.js`) forces `issued_by_definer_only: true` for capped assets - it only imposes constraints when `issued_by_definer_only === true` (no private/fixed-denomination assets), leaving `issued_by_definer_only: false` combined with `cap` a legal configuration. [2](#0-1) 

For such an asset, the base-layer payment/issue validation only requires `serial_number === 1` for any capped asset and lets any author address issue it (the address restriction is only added to the double-spend WHERE clause `when issued_by_definer_only` is true): [3](#0-2) [4](#0-3) 

This means an unprivileged, unrelated unit poster can construct and broadcast an ordinary (non-AA) unit that issues 1 unit of the AA's capped asset for themselves, the moment the asset is defined (its unit/hash is knowable as soon as the AA's `app:'asset'` response unit is public). Once that external `issue` input lands, the global "already issued" check in `aa_composer.js` will forever reject the AA's own subsequent issuance attempt for that asset, exactly mirroring the `NFTMintSale` bug where an external, uncontrolled actor's mint reduces/exhausts a shared counter that a contract's core logic depends on for availability.

Several test/sample oscripts in this codebase (`test/samples/51_attack_game.oscript`, `ico_with_milestones.oscript`, `fundraising_proxy.oscript`) define AA-issued capped assets and set `issued_by_definer_only: true`, which does avoid this issue - but this is a convention, not an enforced invariant. The engine itself does not require `issued_by_definer_only: true` whenever `cap` is set for an AA asset definition, so any AA author who omits that flag (or sets it to `false`/a formula that can evaluate `false`) exposes the exact "external mint interferes with availability" bug class.

### Impact Explanation
If an AA is defined to issue a capped supply of its asset later (e.g., after a fundraising target or milestone is met, as in the `ico_with_milestones.oscript` / `fundraising_proxy.oscript` patterns) and does not set `issued_by_definer_only: true`, any single unprivileged unit poster can pre-empt the on-chain "issue" slot for that asset before the AA acts. This permanently prevents the AA from ever issuing its own capped token, freezing whatever payout/reward logic depended on the issuance (funds already collected/locked by the AA can become undistributable, i.e., AA fund freezing), and can force every subsequent trigger relying on that message to bounce/fail, disagreement-free but functionally broken.

### Likelihood Explanation
Likelihood depends on the AA author's own asset-definition choices, but the engine provides no protection: `aa_validation.js` never mandates `issued_by_definer_only: true` for capped assets, so any AA that separates "define capped asset" from "issue capped asset" into two different trigger-handling stages (a common and recommended oscript pattern seen repeatedly in this same codebase's sample AAs) is exposed unless the author remembers to add the flag. Exploitation requires only knowledge of the asset's unit hash (which becomes public as soon as the `app:'asset'` message is stabilized) and a single ordinary `issue` unit from any address - no privileged role, no race against consensus, and no light-client/network trickery are needed.

### Recommendation
Enforce, at the engine level in `aa_validation.js`'s `asset` case validator, that any AA-defined asset with `cap` set (whether the cap is a literal number or formula) must also have `issued_by_definer_only` evaluate to `true`. Alternatively, in `aa_composer.js`'s `issueAsset()`, change the "already issued" check for capped assets to filter by `address=?` (the AA's own address) in addition to `asset=?`, so a capped asset that permits third-party issuance does not let an external issuer block the AA's own bookkeeping/serial-number-1 slot. The safest fix is the former, since it removes the false assumption embedded in the current comment ("only our AA can issue") by making it a validated invariant rather than a convention.

### Proof of Concept
1. Deploy an AA whose oscript, in one trigger branch, issues a capped asset without `issued_by_definer_only: true`:
```
{ app: 'asset', payload: { cap: 1e6, is_private: false, is_transferrable: true,
  auto_destroy: false, fixed_denominations: false, issued_by_definer_only: false,
  cosigned_by_definer: false, spender_attested: false } },
{ app: 'state', state: "{ var['asset'] = response_unit; }" }
```
   (structure analogous to the two-stage pattern already used in `test/aa_composer.test.js`'s "issue recently defined asset" test, lines 450-554, but with `issued_by_definer_only` left `false`.)
2. Wait for this response unit to stabilize; the asset unit hash (`var['asset']`) is now public.
3. As an unrelated unprivileged address, compose and broadcast an ordinary payment unit with `payload.asset = <that hash>`, `inputs: [{type:'issue', amount: 1e6, serial_number: 1}]`, `outputs: [{address: <attacker>, amount: 1e6}]`. Standard validation accepts this per `validation.js:2321-2373` because `issued_by_definer_only` is false.
4. Trigger the AA's second stage that calls `issueAsset()` for the same asset. `aa_composer.js:1195-1200`'s query `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` now returns a row from the attacker's unit, so the AA's issuance bounces with `'already issued'`, permanently blocking the AA's intended token distribution.

### Citations

**File:** aa_composer.js (L1195-1200)
```javascript
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
```

**File:** aa_validation.js (L297-300)
```javascript
					if (payload.cosigned_by_definer !== false)
						return cb2("cosigned_by_definer must be false because AA can't cosign");
					if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
						return cb2("asset issued by AA definer cannot be private or fixed denominations");
```

**File:** validation.js (L2321-2324)
```javascript
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
```

**File:** validation.js (L2366-2373)
```javascript
					if (objAsset){
						doubleSpendWhere += " AND serial_number=?";
						doubleSpendVars.push(input.serial_number);
					}
					if (objAsset && !objAsset.issued_by_definer_only){
						doubleSpendWhere += " AND address=?";
						doubleSpendVars.push(address);
					}
```
