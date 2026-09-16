## Analysis

The PoolTogether bug class is: **a batch of independent claims processed atomically/sequentially, where a single failing/front-run element aborts processing of the remaining (otherwise valid) items in the batch**, causing wasted work and griefing for honest participants.

The closest reachable analog in `ocore--011` is in the **private payment chain batch handler**, `handlePrivatePaymentChains` in `wallet.js`, which is exactly the kind of "private-payment counterparty reachable" surface allowed by scope. [1](#0-0) 

Here, a payer/hub can send several private-payment chains together in one `private_payments` message (`body.chains`), which is precisely the "batch" analogous to `Claimer.claimPrizes`: [2](#0-1) 

Each chain in the array is validated via `network.handleOnlinePrivatePayment` inside `async.eachSeries`. Critically, on any validation error for **one** chain, `cb("an error")` is invoked: [3](#0-2) 

`async.eachSeries` aborts iteration immediately on the first `cb(err)`, so **all subsequent chains in the batch are never even passed to `handleOnlinePrivatePayment`** — they are silently skipped, not queued, not saved. Additionally, the final handler calls `cancelAllKeys()`:

<invoke name="grep_search">
<parameter name="pattern">cancelAllKeys</parameter>
<parameter name="repo_name">Camomtat/ocore--011</parameter>
</invoke>

### Citations

**File:** wallet.js (L955-958)
```javascript
function handlePrivatePaymentChains(ws, body, from_address, callbacks){
	var arrChains = body.chains;
	if (!ValidationUtils.isNonemptyArray(arrChains))
		return callbacks.ifError("no chains found");
```

**File:** wallet.js (L1020-1064)
```javascript
	async.eachSeries(
		arrChains,
		function(arrPrivateElements, cb){ // validate each chain individually
			var objHeadPrivateElement = arrPrivateElements[0];
			if (!!objHeadPrivateElement.payload.denomination !== ValidationUtils.isNonnegativeInteger(objHeadPrivateElement.output_index))
				return cb("divisibility doesn't match presence of output_index");
			var output_index = objHeadPrivateElement.payload.denomination ? objHeadPrivateElement.output_index : -1;
			try {
				var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
			}
			catch (e) {
				return cb("head priv element hash failed " + e.toString());
			}
			var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+output_index;
			assocValidatedByKey[key] = false;
			network.handleOnlinePrivatePayment(ws, arrPrivateElements, true, {
				ifError: function(error){
					console.log("handleOnlinePrivatePayment error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifValidationError: function(unit, error){
					console.log("handleOnlinePrivatePayment validation error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifAccepted: function(unit){
					console.log("handleOnlinePrivatePayment accepted");
					assocValidatedByKey[key] = true;
					cb(); // do not leak unit info to the hub
				},
				// this is the most likely outcome for light clients
				ifQueued: function(){
					console.log("handleOnlinePrivatePayment queued, will wait for "+key);
					eventBus.once(key, function(bValid){
						if (!bValid)
							return cancelAllKeys();
						assocValidatedByKey[key] = true;
						if (bParsingComplete)
							checkIfAllValidated();
						else
							console.log('parsing incomplete yet');
					});
					cb();
				}
			});
		},
```
