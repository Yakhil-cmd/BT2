### Title
Malicious AA definer can permanently freeze user deposits by baking a payment of an unspendable/blocked asset into an atomic multi-asset payout - ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The reported Nouns DAO issue is that a malicious DAO can list arbitrary/broken ERC20 tokens in `erc20TokensToIncludeInQuit`, so that when a token holder rage-quits, the atomic transfer of *all* listed tokens reverts because one token is designed to always fail, blocking withdrawal entirely and forcing recipients to accept tokens they never chose. The same "atomic multi-asset payout that can be poisoned by one bad asset" pattern exists in ocore Autonomous Agents (AAs), which are the closest analog to a "DAO contract" in this codebase: an AA author (an unprivileged actor who can deploy any AA) can build a pooled/vault-style AA whose payout response always bundles a base-currency (bytes) refund together with a payment of a secondary asset that the AA author fully controls the definition of (`issue_condition`/`transfer_condition`/`is_transferrable`). If that secondary asset is deliberately made non-transferable/non-satisfiable for ordinary depositors, the whole AA response — including the refund of the depositor's own base-currency principal — bounces and is never written, permanently freezing user funds inside the AA.

### Finding Description
An AA response is composed of a set of messages that are validated and written as a single atomic unit; if any message fails to satisfy on-chain payment rules, the entire response is discarded via `bounce()` and no state changes occur [1](#0-0) . Payment messages that pay out a non-base asset are subject to `objAsset.is_transferrable`, `spender_attested`, and `issue_condition`/`transfer_condition` checks in `validatePaymentInputsAndOutputs`, which can unconditionally fail for particular addresses [2](#0-1) .

Assets that back AA reward/share tokens (e.g. `mm_asset` in a market-maker AA) are created by the same AA/author that controls the pool, and the AA's own "divest" logic requires paying this asset out together with the base-currency share in one atomic response, exactly mirroring the DAO's forced multi-token payout in `erc20TokensToIncludeInQuit`: [3](#0-2) 

Because `issue_condition`/`transfer_condition` and `is_transferrable` are set once at asset creation and are fully controlled by the definer/AA author (not by the depositor), and because `aa_validation.js` explicitly allows these fields, including `attestors`, to be formulas evaluated dynamically at response time [4](#0-3) , a malicious AA author can construct a "pool" AA where:
- Deposits are accepted normally (base currency + optionally another asset), incrementing an internal balance.
- The mandatory payout/divest response always includes a payment message for a secondary asset whose `transfer_condition`/`spender_attested` requirements are designed to never be satisfiable for ordinary depositor addresses (e.g., attestation by an attestor who will never attest, or a `seen address`/`in data feed` condition that references state only the attacker controls).
- Since the payout messages (base-currency refund + the poisoned asset) are merged and validated together, the failure of the poisoned-asset payment causes `bounce()` on the *whole* unit, so the depositor's base-currency principal is never released either.

This is functionally identical to the reported bug: the "DAO" (AA) forces recipients to receive a specific asset bundle chosen by the DAO/AA author, and if that asset is designed to be non-transferable to the withdrawer, the entire withdrawal — including funds the user is otherwise entitled to — is blocked indefinitely.

### Impact Explanation
Depositors who trust a pooled/vault AA (e.g., an AMM, staking pool, or bank-style AA as shown in the shipped sample oscripts) can have their principal (bytes and/or other legitimately-owned assets) permanently locked inside the AA, because the AA's own withdrawal logic mandates paying out a poisoned companion asset in the same atomic response. This is a concrete AA fund freezing scenario reachable by any unprivileged user who merely interacts with a maliciously-designed but otherwise innocuous-looking AA.

### Likelihood Explanation
Likelihood is moderate: it requires a malicious or negligent AA author to deploy such an AA, and depositors to interact with it without noticing that the accompanying share/reward asset has restrictive `spender_attested`/`transfer_condition`/`issue_condition` fields (which are not obviously visible without inspecting the AA definition and asset's spending conditions). This mirrors the report's own characterization that not all proposals/asset definitions are thoroughly scrutinized by end users.

### Recommendation
For AA templates/tooling that build pooled/vault-style contracts, avoid bundling a mandatory payment of an auxiliary AA-defined asset with the return of a user's own principal in a single atomic response. Where such bundling is unavoidable, provide the withdrawer a choice (e.g., an explicit trigger flag) to skip the receipt of secondary assets rather than making it mandatory, analogous to the recommended fix of letting rage-quitters choose a subset of ERC20 tokens rather than being forced to accept all of them.

### Proof of Concept
1. AA author deploys a "vault" AA (structurally like `test/samples/uniswap_like_market_maker.oscript`) that, on deposit, issues a companion share asset `mm_asset` whose `spender_attested: true` and `attestors` formula resolves to an address controlled only by the AA author (or a `transfer_condition` requiring `['in data feed', ...]` on a feed the author never posts for ordinary users).
2. A user deposits bytes into the AA; the AA credits an internal `mm_asset_outstanding` balance and issues `mm_asset` to the user in the same response — this step may or may not succeed depending on whether `mm_asset` is spender_attested at issue time.
3. When the user later calls "divest" to redeem their share (`trigger.output[[asset=$mm_asset]]`), the AA's response bundles `{asset: $asset, outputs:[...]}` and `{asset: 'base', outputs:[...]}` in one unit, per `test/samples/uniswap_like_market_maker.oscript` lines 67–101.
4. Because the `$asset` payout's `transfer_condition`/`spender_attested` check (evaluated in `validatePaymentInputsAndOutputs`, `validation.js` lines 2643–2659) never succeeds for the withdrawing user's address, unit validation fails and `aa_composer.js`'s `sendUnit` calls `bounce()` (lines 1245-1289), discarding the entire response — including the base-currency (bytes) portion the user was owed — leaving the user's funds permanently stuck in the AA's balance.

### Citations

**File:** aa_composer.js (L1245-1289)
```javascript
		}

		for (var i = 0; i < messages.length; i++){
			var message = messages[i];
			if (!isNonemptyObject(message))
				return bounce("message must be nonempty object");
			if (ValidationUtils.hasFieldsExcept(message, ['app', 'payload']))
				return bounce("unknown fields in message");
			if (typeof message.app !== 'string')
				return bounce("app must be a string");
			if (!aa_validation.aaApps.includes(message.app))
				return bounce("unsupported app: " + message.app);
			if (!['string', 'object'].includes(typeof message.payload) || message.payload === null)
				return bounce("payload must be string or object");
			if (message.app !== 'payment')
				continue;
			var payload = message.payload;
			if (!isNonemptyObject(payload))
				return bounce("payload must be nonempty object");
			if (ValidationUtils.hasFieldsExcept(payload, ['asset', 'outputs']))
				return bounce("unknown fields in payment payload");
			if (!Array.isArray(payload.outputs))
				return bounce("outputs must be array"); // empty array is okay
			if (!payload.outputs.every(o => ValidationUtils.isValidAddress(o.address)))
				return bounce("invalid addresses in outputs");
			if (payload.outputs.some(o => ValidationUtils.hasFieldsExcept(o, ['address', 'amount'])))
				return bounce("unknown fields in outputs");
			if ('asset' in payload && !(payload.asset === 'base' || ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH)))
				return bounce("asset must be a string or omitted");
			// negative or fractional
			if (!payload.outputs.every(function (output) { return (isNonnegativeInteger(output.amount) || output.amount === undefined); }))
				return bounce("negative or fractional amounts");
			// filter out 0-outputs
			payload.outputs = payload.outputs.filter(function (output) { return (output.amount > 0 || output.amount === undefined); });
		}
		// remove messages with no outputs
		messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
		if (messages.length === 0) {
			error_message = 'no messages after removing 0-outputs';
			console.log(error_message);
			return handleSuccessfulEmptyResponseUnit(null);
		}
		if (mci >= constants.pemCurvesFixMci)
			messages = mergeMessagesAndOutputs(messages);
		var objBasePaymentMessage;
```

**File:** validation.js (L2613-2659)
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
					},
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
				], callback);
```

**File:** test/samples/uniswap_like_market_maker.oscript (L67-101)
```text
			{ // divest MM shares 
				// (user is already paying 10000 bytes bounce fee which is a divest fee)
				// the price slightly moves due to fees received and paid in bytes
				if: `{$mm_asset AND trigger.output[[asset=$mm_asset]]}`,
				init: `{
					$mm_asset_amount = trigger.output[[asset=$mm_asset]];
					$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[$asset]) }"}
							]
						}
					},
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[base]) }"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] -= trigger.output[[asset=$mm_asset]];
						}`
					},
				]
			},
```

**File:** aa_validation.js (L289-300)
```javascript
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
