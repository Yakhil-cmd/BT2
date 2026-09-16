### Title
Fixed-denomination assets sent to an Autonomous Agent become permanently unspendable, locking user funds in the AA forever - (File: `aa_composer.js`)

### Summary
Analogous to the reported issue where the Knox proxy contracts accept native coin deposits but provide no code path to move that coin back out, `ocore`'s AA (Autonomous Agent) response-composer explicitly accepts payments of *fixed-denomination* (indivisible) assets into an AA's balance, but structurally can never construct an outgoing `payment` message for that asset class. Any fixed-denomination asset sent to an AA — whether as a normal trigger payment or as part of a bounce refund — is credited to `aa_balances` yet can never leave the AA, becoming permanently stuck.

### Finding Description
When an AA composes a response unit, `sendUnit()` iterates over the messages to be sent and, for every `payment` message with a non-base asset, loads the asset's properties and short-circuits handling for fixed-denomination assets: [1](#0-0) 

Right after that, a second filtering pass removes *any* payment message whose asset is fixed-denomination, unconditionally: [2](#0-1) 

If this filtering leaves no messages, the composer treats it as a normal "no messages" case and simply commits the state changes without ever sending the asset back — the coins "silently" stay in the AA's balance: [3](#0-2) 

Crucially, this filtering path is shared by every response the AA can ever produce, including its own `bounce()` refund logic, which likewise builds `payment` messages per `trigger.outputs` asset and hands them to `sendUnit()`: [4](#0-3) 

Because `bounce()` and every ordinary "cases" response funnel through the same `sendUnit()` → fixed-denomination filter, there is no code path anywhere in `aa_composer.js` that lets an AA emit a `payment` message carrying a fixed-denomination asset. Meanwhile, `updateInitialAABalances()` happily credits `trigger.outputs[asset]` (including fixed-denomination assets) to the AA's `aa_balances` regardless of asset type: [5](#0-4) 

There is no validation anywhere (in `aa_validation.js` or `validation.js`) that rejects a trigger unit paying a fixed-denomination asset to an AA address — the deposit is fully valid and accepted, but the withdrawal path is unconditionally dead code for that asset class.

### Impact Explanation
Any indivisible/fixed-denomination asset (e.g., an NFT-like or coin-denominated custom asset issued via `app: 'asset'` with `fixed_denominations: true`) sent to any AA address is permanently locked:
- The AA's oscript logic cannot pay it back to the sender, to any other address, or even bounce it, because `sendUnit()` strips out every payment message that references a fixed-denomination asset before the response unit is built.
- The AA's `aa_balances` table shows a nonzero balance for that asset forever, with the underlying real asset outputs remaining un-spendable (`is_spent=0`) permanently, since no unit can ever be produced that spends them from the AA address (an AA can only be triggered/spend via `sendUnit`, and manual signing is impossible because AA addresses have no private key).
- This is a direct, unconditional loss of funds for the depositor (a High severity “AA fund loss / freezing” per the audit rules), reachable by simply issuing a fixed-denomination asset and sending a payment of it to any live AA — no special privilege, cooperation from the AA author, or malicious behavior needed.

### Likelihood Explanation
Likelihood is high: any user (unprivileged unit poster / asset issuer) can create a `fixed_denominations` asset via a normal `asset` message and pay it into any AA in a single, valid transaction. The bug triggers on the very first deposit, with no dependency on AA-writer behavior, oracle data, or race conditions — the composer's filtering logic is unconditional and asset-type based, not developer-mistake based.

### Recommendation
Either:
1. Reject/refuse fixed-denomination-asset outputs sent to AA addresses at validation/trigger time (treat such deposits as invalid `payment` targets for AA addresses, similar to how private assets sent from AAs are already rejected: `if (objAsset.is_private) return cb("sending private asset from AA");`), so the funds never leave the sender in the first place; or
2. Implement true support for AAs to compose fixed-denomination outputs (tracking serial numbers/denominations per asset instance in `aa_balances` and constructing valid indivisible-asset payment messages in `sendUnit()`), removing the blanket filter at `aa_composer.js:1356`.

### Proof of Concept
1. Issue a fixed-denomination asset: post an `asset` message with `fixed_denominations: true` and appropriate `denominations`.
2. Deploy or use any existing AA (e.g. the sample `simple_aa.oscript`/`just_a_bouncer.oscript`) whose logic includes a `payment` response case for `trigger.output[[asset!=base]].asset`.
3. Send a trigger unit that pays units of the fixed-denomination asset to the AA address (also include sufficient `base` bytes to cover `bounce_fees`).
4. Observe (via `dryRunPrimaryAATrigger` or a live network) that:
   - `updateInitialAABalances` credits `aa_balances[address][asset]` with the deposited amount.
   - `sendUnit()` filters out the payment message intended to return/forward the fixed-denomination asset at `aa_composer.js:1356`, resulting in `messages.length === 0` and `handleSuccessfulEmptyResponseUnit(null)` being invoked at `aa_composer.js:1358-1360`.
   - No unit is ever produced spending the fixed-denomination outputs owned by the AA; `is_spent` for those outputs remains `0` indefinitely, and repeated triggers/bounces cannot recover them either, since `bounce()` uses the identical `sendUnit()` path.

### Citations

**File:** aa_composer.js (L474-490)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
```

**File:** aa_composer.js (L930-944)
```javascript
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
```

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** aa_composer.js (L1350-1361)
```javascript
				messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
				if (messages.length === 0) {
					error_message = 'no messages after removing 0-outputs (2nd pass)';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
				messages = messages.filter(function (message) { return (message.app !== 'payment' || !message.payload.asset || !assetInfos[message.payload.asset].fixed_denominations); });
				if (messages.length === 0) {
					error_message = 'no messages after removing fixed denominations';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
```

**File:** aa_composer.js (L1873-1877)
```javascript
			if (messages.length === 0) { // eat the received coins and send no response, state changes are still performed
				error_message = 'no messages after filtering';
				console.log(error_message);
				return handleSuccessfulEmptyResponseUnit(null);
			}
```
