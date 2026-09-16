### Title
Private-asset payments sent to an AA address are permanently unspendable - ([File: aa_composer.js])

### Summary
Any private asset (e.g. blackbytes / any asset with `is_private=true`) that is paid into an Autonomous Agent's address becomes permanently stuck. The AA protocol has no mechanism by which an AA can generate the `spend_proof`/blinding data required to move a private output, so any attempt by the AA's own response logic to forward or pay out that asset is explicitly rejected.

### Finding Description
When an AA composes its response unit, `sendUnit()` iterates over the AA-authored `payment` messages and, for any message referencing a non-base asset, loads the asset's properties and explicitly bails out if the asset is private: [1](#0-0) 

The comment on that line ("it'll fail validation anyway due to lack of spend_proofs") documents the root cause: private payments require a `spend_proof` computed from a secret `blinding` factor that is exchanged off-chain between counterparties over an encrypted device channel (see `indivisible_asset.js` `validatePrivatePayment`/`spend_proof` construction, and `network.js` `handleOnlinePrivatePayment`/`handleSavedPrivatePayments` for how private payment chains and their blinding data are only ever transmitted peer-to-peer between wallets): [2](#0-1) [3](#0-2) 

An AA has no wallet, no device address, and cannot participate in this off-chain private-payment protocol — it can only execute oscript defined at AA-creation time and emit deterministic messages via `sendUnit()`/`handleTrigger()`. Nothing in AA definition validation (`aa_validation.js`) or in the general validation of AA-authored units (`validation.js` `validatePayment`) prevents a normal user from sending a private-asset payment to an AA address in the first place — the restriction is only enforced on the *outgoing* side, when the AA itself tries to compose a payment of that asset. Once received, the AA has no code path capable of producing a valid spend proof, so any oscript payment message trying to move that balance is simply skipped and the whole trigger response gets bounced (funds are eaten as bounce fee, remaining private balance stays locked at the AA forever), while state variables tracking that balance can never be reduced to zero via an actual on-chain output.

This mirrors the reported DAO bug class: value is unconditionally routable *into* a protocol-defined "smart contract" address (the AA), but the contract-execution layer (the AA response composer, analogous to `updateProposalAndExecution()`) has no supported code path to move that specific class of value back out, regardless of what the AA author writes in oscript.

### Impact Explanation
High. Any private-asset balance sent to an AA is permanently and irrecoverably locked at that address — there is no way, in-protocol, for the AA (nor anyone controlling it, since AAs have no controlling keys) to spend it out. This is total, unconditional loss of the deposited private-asset funds, matching a "AA fund loss/freezing" outcome.

### Likelihood Explanation
High. This does not depend on any special attacker capability — it is triggered simply by a normal user (or wallet) sending a private-asset (e.g. blackbytes) payment to any existing AA address, which is a normal, unrestricted wallet operation. Any DeFi-style AA that is designed to also accept/exchange private assets (or any AA address that a user mistakenly pays a private asset to) will suffer permanent loss of that value.

### Recommendation
- Reject private-asset payments to AA addresses at validation time (in `validatePayment`/`validatePaymentInputsAndOutputs` in `validation.js`, when the receiving address is a known AA per `aa_addresses`), so that senders get an immediate validation error instead of silently losing funds.
- Alternatively/additionally, surface a clear wallet-side warning before sending any private asset to an address that is registered as an AA (`aa_addresses` table), since the funds cannot be moved out again.

### Proof of Concept
1. Issue or acquire a private asset (`is_private: true`, e.g. blackbytes).
2. Send a private payment of this asset to an existing AA's address (a normal `sendMultiPayment` with a private asset works exactly like a payment to any regular address; nothing in `validatePayment` distinguishes AA addresses).
3. The AA's `aa_balances` entry for that asset is credited (via `updateInitialAABalances`), so the oscript can see and account for the balance.
4. Have the AA oscript attempt to pay that asset back out (e.g. `{app:'payment', payload:{asset:"<private_asset>", outputs:[...]}}`).
5. In `sendUnit()`, `completePaymentPayload` is never reached for that message because `objAsset.is_private` short-circuits with `cb("sending private asset from AA")`, causing the whole trigger to bounce: [4](#0-3) 
6. The private-asset balance remains permanently held at the AA address with no code path in the codebase capable of spending it out.

### Citations

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

**File:** indivisible_asset.js (L106-124)
```javascript
				var src_output = objPrevPrivateElement.output;
				var prev_hidden_output = objPrevPrivateElement.payload.outputs[input.output_index];
				if (!prev_hidden_output)
					return callbacks.ifError("no prev hidden output");
				input_address = src_output.address;
				try {
					spend_proof = objectHash.getBase64Hash({
						asset: payload.asset,
						unit: input.unit,
						message_index: input.message_index,
						output_index: input.output_index,
						address: src_output.address,
						amount: prev_hidden_output.amount,
						blinding: src_output.blinding
					});
				}
				catch (e) {
					return callbacks.ifError("failed to calc transfer spend proof: " + e.message);
				}
```

**File:** network.js (L2375-2402)
```javascript
// handles one private payload and its chain
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
	if (!ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH))
		return callbacks.ifError("invalid unit");
	if (!ValidationUtils.isNonnegativeInteger(message_index))
		return callbacks.ifError("invalid message_index");
	if (!(ValidationUtils.isNonnegativeInteger(output_index) || output_index === -1))
		return callbacks.ifError("invalid output_index");

	var savePrivatePayment = function(cb){
		// we may receive the same unit and message index but different output indexes if recipient and cosigner are on the same device.
		// in this case, we also receive the same (unit, message_index, output_index) twice - as cosigner and as recipient.  That's why IGNORE.
		db.query(
			"INSERT "+db.getIgnore()+" INTO unhandled_private_payments (unit, message_index, output_index, json, peer) VALUES (?,?,?,?,?)", 
			[unit, message_index, output_index, JSON.stringify(arrPrivateElements), bViaHub ? '' : ws.peer], // forget peer if received via hub
			function(){
				callbacks.ifQueued();
				if (cb)
					cb();
			}
		);
	};
```
