## Analog Found

### Title
Private assets sent to an Autonomous Agent (AA) address are permanently locked because AAs can never construct the spend proofs needed to move them - ([File: aa_composer.js, storage.js])

### Summary
The Sherlock report describes ETH sent to `SwapRouter.sol` becoming permanently unrecoverable because the contract has a `receive()` function but no logic to ever release the received funds. The equivalent root cause exists in ocore: an Autonomous Agent (AA) address can legally *receive* a private-asset payment (any unprivileged user can address a private-asset output to an AA), but the AA has no code path that lets it ever spend, track, or otherwise dispose of that value, so the funds are permanently stuck.

### Finding Description
Private (hidden) asset payments in ocore are UTXO-style outputs whose owner/amount/blinding are not published on-chain; they are only revealed to the recipient via an off-chain, device-to-device delivery of a "private payment chain" (`wallet_general.js` `sendPrivatePayments`/`forwardPrivateChainsToDevices`, `network.handleOnlinePrivatePayment`). Spending a private output later requires reconstructing a `spend_proof` hash from that secretly-delivered `amount`/`blinding`/`address` data (see `indivisible_asset.js` `validateSpendProof`/`buildPrivateElementsChain`, `divisible_asset.js` `validateDivisiblePrivatePayment`). [1](#0-0) [2](#0-1) 

AA addresses have no device/pairing mechanism — they cannot receive or process these off-chain encrypted private-payment-chain messages at all. This is confirmed structurally in two places:

1. `aa_composer.js` explicitly forbids AAs from sending private assets, because it cannot construct the required `spend_proofs`: [3](#0-2) 

2. The AA balance-accounting logic (`aa_balances` table, populated in `storage.js` `insertAADefinitions` and verified in `aa_composer.js` `checkBalances`) explicitly **excludes** private outputs from the balance calculation with `AND (is_private=0 OR is_private IS NULL)`: [4](#0-3) [5](#0-4) 

Because AA oscript logic can only observe funds through `balance[asset]`, which is backed by the `aa_balances` table (see the formula evaluator's `readBalance`), a private-asset payment to an AA is invisible to the AA's own state/trigger logic, is untrackable through `trigger.output[[asset=...]]` (which is derived from `payment` messages that for private assets don't disclose recipient identity on-chain in the same way), and even if somehow tracked, the AA could never spend it since `aa_composer.js` refuses to build outgoing private-asset payments. [6](#0-5) 

### Impact Explanation
Any unprivileged counterparty in a private-asset payment (the asset issuer, or any wallet performing a private transfer) can address a private-asset output to an existing AA address. Because AAs have no device/pairing channel to receive the off-chain private-chain data, and the protocol code explicitly bars AAs from spending private assets and excludes private outputs from AA balance tracking, the sent value becomes permanently unspendable and unrecoverable — a direct, protocol-level asset freeze equivalent to "AA fund loss or freezing."

### Likelihood Explanation
This requires no privileged access and no cooperation from the AA owner: any user issuing or holding a private asset can simply target an AA's public address as the output address of a private payment message, exactly as they would for any other address. This is a normal, permitted operation from the payer's perspective (the AA address is just another valid address), making the trigger trivially reachable by a single unprivileged private-payment counterparty.

### Recommendation
Either (a) reject private-asset payment outputs whose destination address is a known AA address at validation time (`validatePaymentInputsAndOutputs` / private payment validation paths), returning a clear error so senders don't lose funds, or (b) implement an off-chain-independent mechanism allowing AAs (or their controlling logic) to become aware of and account for privately-received outputs (e.g., requiring the private chain data to be embedded in the triggering unit itself so oscript can process it), and allow AAs to construct valid spend proofs for assets they legitimately hold.

### Proof of Concept
1. Attacker/user creates or holds units of a private, fixed-denomination or divisible asset.
2. They compose a private-asset payment (`divisibleAsset.composeAndSaveDivisibleAssetPaymentJoint` / `indivisibleAsset.composeAndSaveIndivisibleAssetPaymentJoint`) with the output `address` set to any existing AA address instead of a normal wallet address.
3. The payment validates and confirms normally (private-asset validation does not check that the recipient is an AA).
4. Because the private payment chain is delivered off-chain to a "device," and AAs have no device, the AA never learns the spend-proof secrets; `aa_balances` never counts the private output (`storage.js` line 960 / `aa_composer.js` line 1978); and even if it did, `aa_composer.js` line 1330 (`"sending private asset from AA"`) prevents the AA from ever emitting a valid outgoing private-asset payment.
5. The asset units are permanently locked at the AA's address with no path to recovery.

### Citations

**File:** wallet_general.js (L18-28)
```javascript
// unlike similar function in network, this function sends multiple chains in a single package
function sendPrivatePayments(device_address, arrChains, bForwarded, conn, onSaved){
	var body = {chains: arrChains};
	if (bForwarded)
		body.forwarded = true;
	device.sendMessageToDevice(device_address, "private_payments", body, {
		ifOk: function(){},
		ifError: function(){},
		onSaved: onSaved
	}, conn);
}
```

**File:** indivisible_asset.js (L20-42)
```javascript
function validatePrivatePayment(conn, objPrivateElement, objPrevPrivateElement, callbacks){
		
	function validateSpendProof(spend_proof, cb){
		profiler.start();
		conn.query(
			"SELECT spend_proof, address FROM spend_proofs WHERE unit=? AND message_index=?", 
			[objPrivateElement.unit, objPrivateElement.message_index], 
			function(rows){
				profiler.stop('spend_proof');
				if (rows.length !== 1)
					return cb("expected 1 spend proof, found "+rows.length);
				var stored_spend_proof = rows[0].spend_proof;
				var spend_proof_address = rows[0].address;
				if (stored_spend_proof !== spend_proof)
					return cb("spend proof doesn't match");
				if (objPrevPrivateElement && objPrevPrivateElement.output.address !== spend_proof_address)
					return cb("spend proof address does not match src output");
				if (input.address && input.address !== spend_proof_address)
					return cb("spend proof address does not match issuer address");
				cb();
			}
		);
	}
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

**File:** aa_composer.js (L1969-1979)
```javascript
				var sql_fill_temp = "INSERT INTO aa_outputs_balances (address, asset, calculated_balance) \n\
					SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) \n\
					FROM aa_addresses \n\
					CROSS JOIN outputs USING(address) \n\
					CROSS JOIN units ON outputs.unit=units.unit \n\
					LEFT JOIN assets ON outputs.asset=assets.unit \n\
					WHERE is_spent=0 AND sequence='good' AND ( \n\
						is_stable=1 \n\
						OR is_stable=0 AND is_aa_response=1 \n\
					) AND (is_private=0 OR is_private IS NULL) \n\
					GROUP BY address, asset";
```

**File:** storage.js (L954-961)
```javascript
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
```

**File:** formula/evaluation.js (L1510-1528)
```javascript
				function readBalance(param_address, bal_asset, cb2) {
					if (bal_asset !== 'base' && !ValidationUtils.isValidBase64(bal_asset, constants.HASH_LENGTH))
						return setFatalError('bad asset ' + bal_asset, { arr }, false, cb);

					if (!objValidationState.assocBalances[param_address])
						objValidationState.assocBalances[param_address] = {};
					var balance = objValidationState.assocBalances[param_address][bal_asset];
					if (balance !== undefined)
						return cb2(new Decimal(balance));
					conn.query(
						"SELECT balance FROM aa_balances WHERE address=? AND asset=? ",
						[param_address, bal_asset],
						function (rows) {
							balance = rows.length ? rows[0].balance : 0;
							objValidationState.assocBalances[param_address][bal_asset] = balance;
							cb2(new Decimal(balance));
						}
					);
				}
```
