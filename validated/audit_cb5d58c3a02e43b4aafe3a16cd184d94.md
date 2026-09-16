Based on my investigation, I found a concrete analog to CVE-2020-9486 within the private-asset processing path, which is reachable by any unprivileged peer sending a private payment.

### Title
Insertion of Sensitive Private-Payment Data (Blinding Factors, Addresses, Amounts) into Log Output - (File: indivisible_asset.js)

### Summary
`indivisible_asset.js` writes the full contents of private (hidden) payment chains — including output addresses, amounts and blinding factors that are supposed to remain confidential — to the process log via `console.log`, mirroring the NiFi advisory's root cause of printing sensitive flow/property values into log output during normal message processing.

### Finding Description
When a wallet validates a privately-forwarded payment chain for an indivisible (hidden-denomination) asset, `validatePrivatePayment` computes and immediately logs the full spend-proof components, including the `blinding` factor and `address` of the source output: [1](#0-0) 

Shortly after, `validateAndSavePrivatePaymentChain` logs the *entire* `arrPrivateElements` array (the whole received private-payment chain, i.e. every hidden output’s address, amount, and blinding factor) via `JSON.stringify`: [2](#0-1) 

and again logs each individual output object as it is inserted: [3](#0-2) 

This code path is reached whenever any counterparty sends a private payment chain to a wallet — an entirely unprivileged action, exercised via `network.js`'s `handleSavedPrivatePayments`, which calls `privatePayment.validateAndSavePrivatePaymentChain` for every received private-payment chain: [4](#0-3) 

The blinding factor is the core secret that keeps a hidden output's `{address, amount, blinding}` triple unlinkable from its public `output_hash` commitment until the recipient chooses to reveal it (analogous to how the NiFi advisory printed configuration values that were meant to stay confidential/masked). Once written to the log, this "hidden" data is no longer protected by the confidentiality mechanism the indivisible-asset design relies on — a `console.log` sink is broader and less controlled than the database (which the protocol intentionally hides these fields from until spend time).

### Impact Explanation
For private (hidden-denomination) assets, the entire privacy model rests on the address/amount/blinding tuple staying secret until intentionally revealed by the holder (e.g. at spend time). Writing this tuple unconditionally to `console.log`/log files defeats that confidentiality guarantee for every private payment chain a wallet processes, for any counterparty who chooses to send one. This is a High-severity information-disclosure class matching CWE-532/CVE-2020-9486: any process, log-shipping agent, crash reporter, or shared log-viewing mechanism that has access to the node's stdout/log file gains visibility into supposedly-private transaction details it was never meant to see, for potentially every private-asset user who interacts with the affected wallet.

### Likelihood Explanation
High: the vulnerable log lines execute unconditionally in `validatePrivatePayment`/`validateAndSavePrivatePaymentChain` on the normal, unauthenticated processing path for any private payment chain received from any correspondent or peer device — no special privileges, race conditions, or unusual configuration are required to trigger the sensitive log write.

### Recommendation
Remove or gate behind an explicit debug flag (disabled by default) the `console.log` statements in `indivisible_asset.js` that print `spend_proof` details (including `blinding`), `arrPrivateElements`, and individual `output` objects. Sensitive fields (`blinding`, `address`, `amount` of hidden outputs) should never be written to unstructured logs; if debugging is required, redact these fields or route them to a dedicated, access-controlled diagnostic channel.

### Proof of Concept
1. Establish a device/wallet pairing (or any mechanism by which private payment chains are exchanged, e.g. as a payment counterparty for a private/indivisible asset).
2. Send a private payment chain for an indivisible asset to the victim wallet.
3. On the victim node, observe the console/log output produced by `validatePrivatePayment` and `validateAndSavePrivatePaymentChain` — the log will contain the full `{asset, unit, message_index, output_index, address, amount, blinding}` object and the raw `arrPrivateElements` JSON, exposing the confidential blinding factor and output details of the hidden payment before/independently of any explicit reveal. [1](#0-0) [2](#0-1)

### Citations

**File:** indivisible_asset.js (L125-133)
```javascript
				console.log("validation spend proof: "+JSON.stringify({
					asset: payload.asset,
					unit: input.unit,
					message_index: input.message_index,
					output_index: input.output_index,
					address: src_output.address,
					amount: prev_hidden_output.amount,
					blinding: src_output.blinding
				}));
```

**File:** indivisible_asset.js (L239-243)
```javascript
function validateAndSavePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	parsePrivatePaymentChain(conn, arrPrivateElements, {
		ifError: callbacks.ifError,
		ifOk: function(bAllStable){
			console.log("saving private chain "+JSON.stringify(arrPrivateElements));
```

**File:** indivisible_asset.js (L270-272)
```javascript
				for (var output_index=0; output_index<outputs.length; output_index++){
					var output = outputs[output_index];
					console.log("inserting output "+JSON.stringify(output));
```

**File:** network.js (L2478-2480)
```javascript
						var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
						privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
							ifOk: function(){
```
