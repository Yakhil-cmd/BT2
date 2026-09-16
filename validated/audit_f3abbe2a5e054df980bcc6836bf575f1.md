### Title
Private-payment link-proof lookup leaks payment-chain amounts to an unauthorized light vendor - (File: network.js)

### Summary
When a light client (wallet acting as `conf.bLight`) receives a private-payment chain longer than one element, it forwards the whole chain's unit list to its light vendor via `light/get_link_proofs` in order to validate that each element in the chain includes the previous one. This discloses the full sequence of units belonging to a private payment chain to the light vendor, even though the vendor is not a party to (and has no authorization over) that private payment.

### Finding Description
`updateLinkProofsOfPrivateChain` calls `checkThatEachChainElementIncludesThePrevious`, which sends the list of all unit hashes in the private chain to the light vendor with the `light/get_link_proofs` request: [1](#0-0) 

This is explicitly acknowledged in the code comment: "we are leaking to light vendor information about the full chain. If the light vendor was a party to any previous transaction in this chain, he'll know how much we received." [2](#0-1) 

This code path is triggered directly from `handleOnlinePrivatePayment` whenever a light-mode wallet is sent a multi-hop private-payment chain (`arrPrivateElements.length > 1`), reachable simply by a private-payment counterparty sending such a chain to the recipient: [3](#0-2) 

The light vendor serving `light/get_link_proofs` learns the entire ordered set of unit hashes making up a private divisible/indivisible asset transfer chain — data that under the ocore private-payment design is meant to be known only to the parties directly involved in each hop of the chain (sender/recipient), not to arbitrary previous or unrelated participants who happen to serve as the light vendor. If the light vendor previously received one of these units as a payment (e.g., it is itself a wallet address that took part earlier in the chain, or colludes with someone who did), it can correlate chain membership and infer amounts and recipients further down the chain that it has no right to know, since divisible/indivisible private assets are specifically designed so that a party to one link cannot learn about later links.

### Impact Explanation
This is an information-disclosure issue affecting the confidentiality guarantee of private/confidential assets in ocore — a core selling point of private payments is that a third party (including the very light vendor relaying it) should not learn transaction amounts and payment graph structure beyond what it is a party to. A light vendor that is (or colludes with) a prior party in a private chain can deduce received amounts and downstream flow of funds for chain participants who have no relationship to that vendor for later hops, undermining the confidentiality of the private payment feature. It does not directly cause fund loss, double-spend, or consensus divergence, so it is a confidentiality/information-disclosure issue rather than a fund-safety one, aligning with a Medium-severity classification (in line with the referenced GitLab CVE-2024-10240, which is also a Medium-severity unauthenticated information-disclosure bug).

### Likelihood Explanation
The path is reachable by any private-payment counterparty simply by sending a multi-element private-payment chain to a light wallet; the client automatically calls `updateLinkProofsOfPrivateChain` for any chain with more than one element without any opt-in or warning, and always contacts its configured light vendor with the full unit list. No special privileges beyond initiating a normal private payment (something any user can do) are required to place a light-wallet recipient in a position where its vendor learns the chain. The likelihood of an actively malicious/colluding light vendor observing this data is realistic in the hub/vendor trust model.

### Recommendation
Avoid sending the full unit list of a private chain to the light vendor in one shot. Options: query `light/get_link_proofs` incrementally per hop only for the portion of the chain still unverified and not already known to have passed through this vendor, minimize what is disclosed (e.g., use blinded/hashed identifiers or request only enough information to prove inclusion without unit correlation), or allow using a different, less-trusted node for this specific check rather than the primary light vendor. At minimum, clearly document/warn users that using a light wallet reduces private-payment confidentiality with respect to their light vendor, and consider adding a configuration guard to disable/limit this behavior for privacy-sensitive setups.

### Proof of Concept
1. Operate (or collude with) a hub that also serves as the `light_vendor_url` for a target light wallet.
2. As attacker, participate as a normal recipient in an early hop of a private asset transfer chain (e.g., issue coins to Alice, who transfers to Bob, who transfers to the light-wallet victim), thereby learning `unit`, `message_index`, `output_index` of that hop.
3. When the victim's light wallet later receives the multi-hop chain (from Bob to Victim) via `network.handleOnlinePrivatePayment`, since `arrPrivateElements.length > 1`, `updateLinkProofsOfPrivateChain` is invoked, which calls `checkThatEachChainElementIncludesThePrevious` and sends `arrUnits` (the full list of chain unit hashes) to the attacker's node via `light/get_link_proofs`. [4](#0-3) 
4. The attacker's `light/get_link_proofs` handler on `network.js` now sees the complete unit list for this private chain, correlates it with the earlier hop it was a party to, and can identify the final recipient's amount and address history for a chain it should not have visibility beyond its own hop.

### Citations

**File:** network.js (L2404-2410)
```javascript
	if (conf.bLight && arrPrivateElements.length > 1){
		savePrivatePayment(function(){
			updateLinkProofsOfPrivateChain(arrPrivateElements, unit, message_index, output_index);
			rerequestLostJointsOfPrivatePayments(); // will request the head element
		});
		return;
	}
```

**File:** network.js (L2666-2691)
```javascript
// light only
// Note that we are leaking to light vendor information about the full chain. 
// If the light vendor was a party to any previous transaction in this chain, he'll know how much we received.
function checkThatEachChainElementIncludesThePrevious(arrPrivateElements, handleResult){
	if (arrPrivateElements.length === 1) // an issue
		return handleResult(true);
	var arrUnits = arrPrivateElements.map(function(objPrivateElement){ return objPrivateElement.unit; });
	requestFromLightVendor('light/get_link_proofs', arrUnits, function(ws, request, response){
		if (!response || response.error)
			return handleResult(null); // undefined result
		var arrChain = response;
		if (!ValidationUtils.isNonemptyArray(arrChain))
			return handleResult(null); // undefined result
		light.processLinkProofs(arrUnits, arrChain, {
			ifError: function(err){
				console.log("linkproof validation failed: "+err);
			//	throw Error(err);
				handleResult(false);
			},
			ifOk: function(){
				console.log("linkproof validated ok");
				handleResult(true);
			}
		});
	});
}
```
