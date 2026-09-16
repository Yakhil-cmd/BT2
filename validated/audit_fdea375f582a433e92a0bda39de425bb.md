The linked report concerns arbitrary ERC20 configurability (fee-on-transfer, pausable, blocklist, decimals, zero-transfer) breaking a lending protocol's assumptions about token behavior. The closest analog in `ocore` is Obyte's own configurable-asset system, where user-defined assets carry properties (`is_transferrable`, `is_private`, `fixed_denominations`, `issue_condition`/`transfer_condition`, `spender_attested`) that AAs (Autonomous Agents) do not fully validate before accepting deposits, leading to permanently frozen user funds.

### Title
Generic AAs accepting arbitrary user-supplied assets can permanently freeze depositor funds due to unchecked `is_transferrable`/`fixed_denominations`/`is_private` asset properties - (File: aa_composer.js, validation.js)

### Summary
AAs that act as generic multi-asset vaults, exchanges, or banks (patterns shown throughout the bundled oscript samples, e.g. `a_bank_without_percent.oscript`, `order_book_exchange.oscript`, `uniswap_like_market_maker.oscript`) credit an internal balance for *any* asset a user deposits, without inspecting the asset's definition. Obyte assets, unlike a plain fungible token, can be defined with restrictive properties: `is_transferrable: false`, `fixed_denominations: true`, `is_private: true`, or custom `transfer_condition`/`issue_condition`. When the AA later tries to pay this balance back out to the depositor (a normal `payment` message), the protocol-level payment validation can reject the AA's outgoing payment, and there is no way for the AA to satisfy the condition, so the deposited value becomes permanently stuck in the AA.

### Finding Description
Sample AAs accept unvalidated deposits purely based on `trigger.output[[asset!=base]]`: [1](#0-0) 

No check is made on the asset's `is_transferrable`, `fixed_denominations`, `is_private`, or `transfer_condition` fields before crediting the balance.

When the AA subsequently composes an outgoing `payment` message for that asset, `aa_composer.js` only special-cases `fixed_denominations` (skips it) and `is_private` (aborts that message), but never checks `is_transferrable` or `transfer_condition`: [2](#0-1) 

The actual protocol-level restriction is enforced later in `validatePaymentInputsAndOutputs`, where a non-transferrable asset can only be spent if the definer is among the sole input/output addresses: [3](#0-2) 

Since the AA address is not the asset's definer, and the depositor is (in the general case) not the definer either, this validation fails with `"the asset is not transferrable"`, causing `validateAndSaveUnit` to fail and the whole AA response to bounce: [4](#0-3) 

A bounce reverts the AA's *state* changes for that trigger, but it does **not** return the previously-deposited asset balance recorded from an earlier successful deposit trigger — that balance was already durably committed to `aa_balances`/state vars in a prior unit. The depositor has no way to ever redeem it because every future withdrawal attempt hits the same `is_transferrable` failure.

The same class of problem applies to `transfer_condition`-restricted assets (which the AA can never satisfy autonomously since it cannot produce arbitrary signatures/definitions required by a custom condition) and to `is_private` assets, which `aa_composer.js` explicitly refuses to send from an AA (`"sending private asset from AA"`) at line 1330 of the snippet above, yet nothing prevents an AA from accepting such assets as a deposit in the first place via `trigger.outputs`.

### Impact Explanation
Any generic AA that credits internal accounting for arbitrary incoming assets (a broadly encouraged and demonstrated pattern in the codebase's own sample AAs) can have user funds permanently locked once a user deposits an asset with `is_transferrable: false`, a restrictive `transfer_condition`, or `is_private: true`. This is a genuine, irreversible loss of funds for the depositor and is exactly analogous to the referenced report's concern that "different kinds of losses...losing collateral due to defaulting" arise when a protocol accepts arbitrary token configurations without a whitelist or capability check.

### Likelihood Explanation
Likelihood is moderate-to-high: any third party can define an asset with `is_transferrable: false` or a `transfer_condition` and then interact with a public AA that blindly accepts `trigger.output[[asset!=base]]` deposits, as shown in multiple first-party oscript examples. No special privileges or malicious node/peer behavior is required — this is reachable by a single ordinary AA trigger sender defining an asset and sending it to an existing AA.

### Recommendation
AAs that hold balances of arbitrary user-supplied assets should validate the asset's definition (via `is_transferrable`, `is_private`, `fixed_denominations`, `issue_condition`/`transfer_condition`, `spender_attested`, `cap`) before crediting a withdrawable balance, and should reject/bounce deposits of assets whose properties prevent them from ever being paid back out by an AA. Alternatively, `ocore` could document/enforce this constraint at the framework level (e.g., surfacing asset flags to oscript via a getter so AA authors can guard deposits), since AAs cannot satisfy transfer conditions or send private/non-transferrable assets on their own.

### Proof of Concept
1. Define asset `X` with `is_transferrable: false`, `issued_by_definer_only: true`, `is_private: false`.
2. Send a trigger to `a_bank_without_percent.oscript`-style AA with `trigger.output[[asset=X]] = 100000`; the "silently accept coins" branch credits `var[$asset_key] += 100000` without validating `X`'s properties, per `test/samples/a_bank_without_percent.oscript` lines 31-49.
3. Attempt to withdraw: the AA composes `payment` with `asset: X`, `outputs: [{address: <depositor>, amount: 100000}]`.
4. `aa_composer.js` (lines 1323-1344) does not reject this because `X` is neither `fixed_denominations` nor `is_private`.
5. `validateAndSaveUnit` invokes `validatePaymentInputsAndOutputs`, which fails with `"the asset is not transferrable"` (`validation.js` lines 2613-2629), since neither the AA address nor the depositor is `X`'s definer.
6. The response bounces; the deposited 100000 units of `X` remain forever recorded in the AA's state/`aa_balances` with no valid withdrawal path.

### Citations

**File:** test/samples/a_bank_without_percent.oscript (L31-49)
```text
			{ // silently accept coins
				if: "{!trigger.data.withdraw}",
				messages: [{
					app: 'state',
					state: `{
						$asset = trigger.output[[asset!=base]].asset;
						if ($asset == 'ambiguous')
							bounce('ambiguous asset');
						if (trigger.output[[asset=base]] > 10000){
							$base_key = 'balance_'||trigger.address||'_'||'base';
							var[$base_key] = var[$base_key] + trigger.output[[asset=base]];
							$response_base = trigger.output[[asset=base]] || ' bytes\n';
						}
						if ($asset != 'none'){
							$asset_key = 'balance_'||trigger.address||'_'||$asset;
							var[$asset_key] = var[$asset_key] + trigger.output[[asset=$asset]];
							$response_asset = trigger.output[[asset=$asset]] || ' of ' || $asset || '\n';
						}
						response['message'] = 'accepted coins:\n' || ($response_base otherwise '') || ($response_asset otherwise '');
```

**File:** aa_composer.js (L1323-1344)
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
						if (err)
							return cb(err);
						addOutputAddresses(payload.outputs);
						if (payload.outputs.length > 0) // send-all output might get removed while being the only output
							try {
								completeMessage(message);
							}
							catch (e) {
								return cb("completeMessage failed: " + e.toString());
							}
						cb();
					});
				});
```

**File:** aa_composer.js (L1405-1411)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```

**File:** validation.js (L2613-2629)
```javascript
			if (objAsset){
				if (total_input !== total_output)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output);
				if (!objAsset.is_transferrable){ // the condition holds for issues too
					if (arrInputAddresses.length === 1 && arrInputAddresses[0] === objAsset.definer_address
					   || arrOutputAddresses.length === 1 && arrOutputAddresses[0] === objAsset.definer_address
						// sending payment to the definer and the change back to oneself
					   || !(objAsset.fixed_denominations && objAsset.is_private) 
							&& arrInputAddresses.length === 1 && arrOutputAddresses.length === 2 
							&& arrOutputAddresses.indexOf(objAsset.definer_address) >= 0
							&& arrOutputAddresses.indexOf(arrInputAddresses[0]) >= 0
					   ){
						// good
					}
					else
						return callback("the asset is not transferrable");
				}
```
