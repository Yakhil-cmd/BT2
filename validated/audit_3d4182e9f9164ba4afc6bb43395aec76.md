### Title
AA payment composer omits `cosigned_by_definer` / `spender_attested` checks before building outgoing asset payments, causing permanent bounce/freeze of AA-held assets - (File: `aa_composer.js`)

### Summary
When an Autonomous Agent (AA) composes a `payment` message for a non-base asset in response to a trigger, `aa_composer.js` only pre-checks `fixed_denominations` and `is_private` before adding the payment to the response unit. It never checks whether the asset requires `cosigned_by_definer` or `spender_attested` cosigning/attestation, conditions an AA can never satisfy on its own. The resulting response unit is only rejected later, during full unit validation, forcing the whole primary trigger to bounce.

### Finding Description
In `handleTrigger`'s `sendUnit` routine, each non-base payment message is completed like this: [1](#0-0) 
Only `fixed_denominations` (deferred) and `is_private` (rejected) are checked here; `cosigned_by_definer` and `spender_attested` are not evaluated at all before `completePaymentPayload`/`completeMessage` build the message and it is added to the unit.

Later, full unit validation enforces these asset rules that were skipped during composition: [2](#0-1)  and again per-input in `validatePaymentInputsAndOutputs`: [3](#0-2) 

Crucially, an AA structurally cannot satisfy `cosigned_by_definer` for *any* asset, because AAs can only single-author (no additional signature can ever be supplied), and this is explicitly acknowledged elsewhere in the codebase for AA-*defined* assets: [4](#0-3) 
That rule only prevents an AA from defining a self-cosigned asset; it does nothing to stop the AA from later trying to pay out a *different*, pre-existing asset (defined by someone else) that has `cosigned_by_definer:true` or `spender_attested:true` (with the AA address not attested). If an AA's oscript (whether hard-coded or driven by attacker-controlled trigger data, e.g. `trigger.data.asset`) ever composes a payment in such an asset, the check is skipped at composition time and only fails at full validation time.

When `validateAndSaveUnit` reports an error, the AA calls `bounce(err)`: [5](#0-4) 
`bounce()` reverts all state changes from the primary trigger and only consumes `bounce_fees`; the attempted payment never leaves the AA. Because the underlying condition (asset requires cosigning/attestation the AA cannot provide) never changes, every subsequent trigger that causes the AA to try paying out that asset will bounce identically, forever.

### Impact Explanation
Any AA logic (e.g. a bank/vault/DEX-style AA in `oscript`, as illustrated by the withdraw patterns in `test/samples/a_bank_without_percent.oscript` and `order_book_exchange.oscript`) that accepts a third-party asset with `cosigned_by_definer` or `spender_attested` set, and later attempts to pay it back out, will have those funds permanently stuck: the AA can receive the asset (payments into an AA are validated by the normal payment rules against the *sender*, not the AA) but can never emit a compliant outgoing payment for it. This is a fund-freezing condition within the AA's own balance — every withdrawal attempt bounces, consuming only bounce fees while leaving the user's recorded balance/state unable to be redeemed in that asset.

### Likelihood Explanation
This can be triggered by any unprivileged user: simply send the AA an asset that requires `cosigned_by_definer` or `spender_attested` (attributes that are visible/queryable and can be crafted by the depositor/issuer), then invoke the AA's withdraw/payout logic for that asset. Because the composer performs no pre-check, the bug manifests deterministically on the first payout attempt and repeats on every future attempt for that asset — no race condition or special privilege is required, only that the AA's `oscript` logic permits arbitrary/attacker-influenced asset payouts (a common pattern, as seen in the bank/exchange samples where `trigger.data.asset` selects the payout asset).

### Recommendation
Extend the pre-check block in `aa_composer.js` (around the `storage.loadAssetWithListOfAttestedAuthors` callback at lines 1323-1330) to also reject or gracefully skip payment messages for assets where `objAsset.cosigned_by_definer` is true, or where `objAsset.spender_attested` is true and the AA address is not in `objAsset.arrAttestedAddresses`, mirroring the checks already performed in `divisible_asset.js`/`indivisible_asset.js` composer functions. Optionally surface this as a well-defined bounce reason ("asset requires cosigning/attestation, cannot be paid out by an AA") early, and document in AA-authoring guidance that assets with these flags cannot be safely handled by AAs, so oscript authors can validate the asset definition before accepting/holding such assets.

### Proof of Concept
1. Address `D` (not an AA) defines asset `X` with `cosigned_by_definer: true` (or `spender_attested: true` with an attestor list that never attests the target AA).
2. A user sends asset `X` to AA `A` whose oscript records the deposit in a state var (pattern per `test/samples/a_bank_without_percent.oscript`).
3. The user later triggers `A` with `{withdraw: true, asset: X, amount: ...}`.
4. `A`'s response composes a `payment` message for asset `X` at `aa_composer.js:1323-1331`; the `cosigned_by_definer`/`spender_attested` check is skipped, so the message is built and added to the response unit.
5. `validateAndSaveUnit` runs full validation; `validatePayment` (`validation.js:2112-2121`) rejects the unit because `A` cannot supply the definer's cosignature or attestation.
6. `bounce(err)` fires (`aa_composer.js:1408-1411`), reverting the withdrawal's state changes; the user's recorded balance for asset `X` remains, but every future withdrawal attempt bounces identically — the asset is permanently stuck in the AA.

### Citations

**File:** aa_composer.js (L1323-1331)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
					completePaymentPayload(payload, 0, function (err) {
```

**File:** aa_composer.js (L1408-1411)
```javascript
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```

**File:** validation.js (L2109-2121)
```javascript
			if (objAsset.issued_by_definer_only && issuer_address !== objAsset.definer_address)
				return callback("only definer can issue this asset");
		}
		if (objAsset.cosigned_by_definer && arrAuthorAddresses.indexOf(objAsset.definer_address) === -1)
			return callback("must be cosigned by definer");
		
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
```

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

**File:** aa_validation.js (L297-298)
```javascript
					if (payload.cosigned_by_definer !== false)
						return cb2("cosigned_by_definer must be false because AA can't cosign");
```
