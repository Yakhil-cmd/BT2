### Title
Private Payment Chain Blinding Secrets Exposed in Service Logs - ([File: indivisible_asset.js])

### Summary
When a device receives an indivisible-asset private payment chain from any counterparty (a private-payment sender), `validateAndSavePrivatePaymentChain` logs the entire chain — including each output's `blinding` value — with plain `console.log` calls before/while it is persisted. `blinding` is a secret that, together with the address and amount, is required to prove ownership/derive the `output_hash` and is treated as confidential data shared only between payer and payee. Writing it unconditionally to logs at info level mirrors CVE-2025-32016's root cause (CWE-532): a credential-like secret that governs asset control being written into logs that are commonly persisted/aggregated in production.

### Finding Description
`validateAndSavePrivatePaymentChain` is invoked whenever a private (indivisible-asset) payment chain arrives at a wallet — e.g., from `network.js`'s `handleSavedPrivatePayments` after being received from a peer/hub, which is reachable by any private-payment counterparty sending private elements to a device: [1](#0-0) 

Once accepted, the full private element list — including `objPrivateElement.output.blinding` — is dumped via `console.log`: [2](#0-1) 
and again per-output: [3](#0-2) 

`blinding` is validated as a required secret field of each private output and is combined with the output's other fields to compute `output_hash` (`objectHash.getBase64Hash(objPrivateElement.output)`), which is the only value publicly recorded on-chain for indivisible-asset outputs: [4](#0-3) 

Because the chain of public outputs only stores `output_hash` (a hash of `address`, `amount`, `blinding`), knowledge of `blinding` (plus `address`/`amount`, which are also present in the same log line) is what lets a party construct/verify the private element and claim/forward the output. Persisting this secret into logs — a class of infrastructure typically retained, shipped to log aggregators, or accessible to lower-privileged operators — creates an unauthorized-disclosure path for a credential-equivalent value, directly analogous to `Microsoft.Identity.Web` logging client secrets/certificate data at `Information` level.

### Impact Explanation
Anyone with read access to these logs (ops staff, log aggregation systems, misconfigured logging sinks, crash-report bundles, etc.) obtains the `blinding` value, address, and amount for private outputs belonging to any counterparty who ever sent a private payment chain to a node. That information, combined with the public `output_hash` visible on-chain, allows an attacker to reconstruct and independently claim/forward the private output ahead of, or in place of, the legitimate recipient — i.e., unauthorized spending / theft of privately-transferred asset funds, and no cryptographic secret beyond log access is needed. This satisfies "concrete unauthorized spending" for private payment chains.

### Likelihood Explanation
Exploitation requires no privileged access beyond reading operational logs of a node that received the private payment (a very common oversight in production deployments — the same precondition the Microsoft advisory itself calls out as the trigger for impact). Any wallet counterparty can trivially cause the vulnerable log line to be written simply by sending it a valid private payment chain, so the "attack" side is fully unprivileged and always reachable; only the exposure of the resulting log line is the gating factor, matching the conditional nature of the referenced CVE.

### Recommendation
Remove or redact `blinding` (and other output secret fields) from all `console.log` statements in `indivisible_asset.js`'s private-chain handling path (`validateAndSavePrivatePaymentChain`, `composeIndivisibleAssetPaymentJoint`, etc.). Where debugging output is needed, log only non-secret identifiers (unit, message_index, output_index, asset) and gate any full-payload logging behind an explicit, disabled-by-default debug flag, never at default/info level.

### Proof of Concept
1. Party A sends Party B a private (indivisible-asset) payment; this arrives at B's node and is routed to `handleSavedPrivatePayments` → `privatePayment.validateAndSavePrivatePaymentChain`. [5](#0-4) 
2. On acceptance, B's node logs the full chain, including `objPrivateElement.output.blinding`, via `console.log("saving private chain "+JSON.stringify(arrPrivateElements));` and `console.log("inserting output "+JSON.stringify(output));`. [6](#0-5) [7](#0-6) 
3. An operator, log-shipping pipeline, or anyone with log access on B's node now has `address`, `amount`, and `blinding` for the output — sufficient to derive/verify `output_hash` and construct a valid claim of the private output, enabling unauthorized spending before/instead of the legitimate recipient.

### Citations

**File:** network.js (L2461-2496)
```javascript
				function(row, cb){
					var arrPrivateElements = JSON.parse(row.json);
					var ws = getPeerWebSocket(row.peer);
					if (ws && ws.readyState !== ws.OPEN)
						ws = null;
					
					var validateAndSave = function(){
						var objHeadPrivateElement = arrPrivateElements[0];
						try {
							var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
						}
						catch (e) {
							console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
							if (ws)
								sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
							deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
						}
						var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
						privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
							ifOk: function(){
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'accepted'});
								if (row.peer) // received directly from a peer, not through the hub
									eventBus.emit("new_direct_private_chains", [arrPrivateElements]);
								assocNewUnits[row.unit] = true;
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								console.log('emit '+key);
								eventBus.emit(key, true);
							},
							ifError: function(error){
								console.log("validation of priv: "+error);
							//	throw Error(error);
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: error});
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								eventBus.emit(key, false);
```

**File:** indivisible_asset.js (L68-79)
```javascript
	if (!ValidationUtils.isValidAddress(objPrivateElement.output.address))
		return callbacks.ifError("bad address in output");
	if (!ValidationUtils.isNonemptyString(objPrivateElement.output.blinding))
		return callbacks.ifError("bad blinding in output");
	try {
		var expected_output_hash = objectHash.getBase64Hash(objPrivateElement.output);
	}
	catch (e) {
		return callbacks.ifError("failed to calc output hash: " + e.message);
	}
	if (expected_output_hash !== our_hidden_output.output_hash)
		return callbacks.ifError("output hash doesn't match, output="+JSON.stringify(objPrivateElement.output)+", hash="+our_hidden_output.output_hash);
```

**File:** indivisible_asset.js (L239-244)
```javascript
function validateAndSavePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	parsePrivatePaymentChain(conn, arrPrivateElements, {
		ifError: callbacks.ifError,
		ifOk: function(bAllStable){
			console.log("saving private chain "+JSON.stringify(arrPrivateElements));
			profiler.start();
```

**File:** indivisible_asset.js (L270-272)
```javascript
				for (var output_index=0; output_index<outputs.length; output_index++){
					var output = outputs[output_index];
					console.log("inserting output "+JSON.stringify(output));
```
