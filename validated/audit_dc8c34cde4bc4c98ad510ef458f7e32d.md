### Title
AA Payment Composer Omits `cosigned_by_definer`/`spender_attested` Checks, Letting a Third-Party Asset Issuer Permanently Freeze Funds Held by an Autonomous Agent - (File: aa_composer.js)

### Summary
This is a valid analog. The Solana report describes a pool that accepts an arbitrary input-token mint without checking whether the mint's issuer retains control (freeze authority) that can later block the pool's own vault from moving funds, causing DoS and permanent user losses. In Obyte's `ocore`, the equivalent "issuer-retained control" primitives on a custom asset are `cosigned_by_definer` and `spender_attested`. An Autonomous Agent (AA) — the reachable, unprivileged, user-triggerable "pool"/"vault" analog — can receive a deposit of *any* third-party asset via a normal trigger payment, but the code that composes the AA's own outgoing payments never checks these two asset invariants before trying to pay that asset back out.

### Finding Description
When an AA's oscript emits a `payment` message for a non-base asset, `aa_composer.js`'s `sendUnit` loads the asset's metadata via `storage.loadAssetWithListOfAttestedAuthors` and only special-cases `fixed_denominations` and `is_private`: [1](#0-0) 
It does not check `objAsset.cosigned_by_definer` or `objAsset.spender_attested` at composition time.

`aa_validation.js` only forces `cosigned_by_definer` to `false` for assets **defined by the AA itself** ("AA can't cosign"), because an AA is single-authored and can never have a second signer cosign its response unit: [2](#0-1) 
This restriction has no effect on **third-party** assets that already exist with `cosigned_by_definer: true` and/or `spender_attested: true` and which any user can simply pay into the AA as part of a normal trigger.

When the AA later composes a response that pays that asset back out (change, swap-back, withdrawal, AMM payout, etc.), the response unit is authored solely by the AA address and is checked by the same protocol-wide `validatePayment` logic used for every payment: [3](#0-2) 
Because `arrAuthorAddresses` for an AA-authored unit is just the single AA address:
- If `cosigned_by_definer` is `true`, the check `arrAuthorAddresses.indexOf(objAsset.definer_address) === -1` is always true (an AA cannot be, or add, the definer as a cosigning author) → `"must be cosigned by definer"`.
- If `spender_attested` is `true` and the AA address itself was never attested by the asset's attestor(s), `objAsset.arrAttestedAddresses.length === 0` (or the AA isn't in it) → `"none of the authors is attested"`.

`validatePaymentInputsAndOutputs` also re-checks that every output address is attested when `spender_attested` is set: [4](#0-3) 

Both checks are structural properties of the asset set once by its (external, unprivileged-to-the-AA) definer/attestor and are outside the AA's control forever, exactly mirroring a mint's freeze authority in the Solana report: an external actor's persistent authority (definer cosignature requirement / attestor gatekeeping) can unilaterally and permanently block a downstream contract's ability to move funds it legitimately received.

### Impact Explanation
Any AA that acts as a general-purpose vault/pool/AMM/exchange and accepts deposits of arbitrary user-supplied assets — a common and encouraged AA pattern shown in the repo's own samples (`uniswap_like_market_maker.oscript`, `fundraising_proxy.oscript`, `create_an_asset.oscript`) — can be tricked or can inadvertently receive a deposit in an asset whose definer set `cosigned_by_definer: true` or `spender_attested: true` with an attestor list that will never include the AA's address. Every subsequent attempt by the AA to pay that asset back out will fail validation and the AA response will bounce, while the balance remains recorded in `aa_balances` for that asset with no code path that can ever satisfy the definer-cosignature or attestation requirement (an AA cannot obtain a second signature, and cannot get itself attested without the external attestor's cooperation). This is a permanent, unrecoverable freeze of user-deposited AA funds — directly matching the "AA fund loss or freezing" acceptance criterion, and structurally identical to the freeze-authority DoS/permanent-loss pattern in the source report.

### Likelihood Explanation
Any unprivileged asset issuer can define such an asset (`cosigned_by_definer`/`spender_attested` are ordinary, fully-permitted fields in `validateAssetDefinition`), and any unprivileged trigger sender can pay that asset into a target AA that has no logic (and no ocore-level primitive) to reject/inspect these invariants before accepting or later re-spending the asset. No special privilege beyond normal unit/trigger posting is required to create the freezing condition; the AA developer's oversight (not filtering incoming assets by these flags) is the only prerequisite, which is realistic for generic multi-asset pool/AMM designs the codebase itself demonstrates.

### Recommendation
- In `aa_composer.js`, when composing/validating an AA's outgoing `payment` message for a non-base asset (around the `storage.loadAssetWithListOfAttestedAuthors` callback at aa_composer.js:1323), explicitly check `objAsset.cosigned_by_definer` and `objAsset.spender_attested` (with the AA's own address against `objAsset.arrAttestedAddresses`) and bounce early with a clear diagnostic instead of silently composing a doomed response.
- Provide an oscript-level getter (e.g. `asset[...].cosigned_by_definer`, `asset[...].spender_attested`) so AA authors can defensively reject deposits of such assets in `trigger`-time logic before crediting them to internal accounting/state, preventing funds from ever becoming stuck.
- Document prominently (as the original report's "Team Response" recommends for token allow-listing) that AAs accepting arbitrary third-party assets must screen for `cosigned_by_definer`/`spender_attested` before treating them as freely transferable pool assets.

### Proof of Concept
1. Attacker (or any unprivileged asset issuer) defines asset `X` with `cosigned_by_definer: true` (or `spender_attested: true` with an attestor list excluding the target AA), per `validateAssetDefinition` (validation.js:2725-2755) — this passes ordinary validation since these are legitimate fields for non-AA-defined assets.
2. A user sends a trigger to a pool/vault AA (e.g., the AMM pattern in `test/samples/uniswap_like_market_maker.oscript`) with a deposit output in asset `X`. This payment succeeds because the depositing user (not the AA) is the payment's author and can self-satisfy any cosign/attestation requirement.
3. The AA's oscript logic later emits a `payment` message paying asset `X` back to a user (e.g., swap payout or withdrawal). `aa_composer.js` composes this message without checking `cosigned_by_definer`/`spender_attested` (aa_composer.js:1323-1344).
4. `validatePayment` (validation.js:2109-2122) rejects the response unit: `"must be cosigned by definer"` or `"none of the authors is attested"`, since the AA is single-authored and cannot satisfy either condition.
5. The AA response bounces. Every future attempt to pay out asset `X` fails identically — the AA's `aa_balances` entry for asset `X` is permanently stuck, and any user funds represented by that entry (e.g., other users' pooled shares denominated against this balance) are permanently unrecoverable, matching the "permanent loss of funds" impact in the analog report.

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

**File:** aa_validation.js (L297-300)
```javascript
					if (payload.cosigned_by_definer !== false)
						return cb2("cosigned_by_definer must be false because AA can't cosign");
					if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
						return cb2("asset issued by AA definer cannot be private or fixed denominations");
```

**File:** validation.js (L2109-2122)
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
		}
```

**File:** validation.js (L2630-2641)
```javascript
				async.series([
					function(cb){
						if (!objAsset.spender_attested)
							return cb();
						storage.filterAttestedAddresses(
							conn, objAsset, objValidationState.last_ball_mci, arrOutputAddresses, 
							function(arrAttestedOutputAddresses){
								if (arrAttestedOutputAddresses.length !== arrOutputAddresses.length)
									return cb("some output addresses are not attested");
								cb();
							}
						);
```
