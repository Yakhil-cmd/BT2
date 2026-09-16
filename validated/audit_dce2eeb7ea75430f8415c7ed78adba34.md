### Title
Ambiguous "has output" spending condition in shared-address contracts enables one payment to unlock funds from multiple concurrent locked contracts - ([File: arbiter_contract.js])

### Summary
GemPad's `LockV2` exploit stemmed from a lock contract that released funds without binding the unlock check to the specific, unique lock being withdrawn, letting one crafted call drain balances that belonged to a different lock/token. Ocore's `arbiter_contract.js` builds bilateral escrow ("locked") shared addresses whose spending condition is an `["has", {what:"output", asset, amount, address}]` clause. This condition is evaluated only against the *existence* of a matching output inside the spending unit — it is not bound to a specific contract instance/hash. When two shared-address contracts happen to have identical counterparties, amount, and asset, a single output can satisfy the `has` condition of both, letting a party combine them in one transaction and redirect funds that should have gone to the other party.

### Finding Description
`deriveSharedAddress()` in [1](#0-0)  constructs an address definition whose authorization to spend for either party is simply "does this transaction contain an output of amount X, asset Y, to address Z" — there is no reference to the specific contract hash, unlike the private-asset branch which uses `"in data feed"` bound to `"CONTRACT_" + contract.hash` ( [2](#0-1) ). Because `evaluateFilter()` in `definition.js` matches on unit-level payment messages without any linkage to which shared address/contract triggered the check, it treats any output in the same unit satisfying `{what, asset, amount, address}` as proof of payment [3](#0-2) .

The code even documents awareness of a closely related collision: "if their parties, amounts, and assets are identical, the 'has what' above would satisfy both contracts, allowing the attacker to send the change to themselves," and mitigates it only by forbidding extra inputs from "other address" in the same asset within the spending unit [4](#0-3) . This patch narrowly targets the "combine 2 contracts + steal the change" scenario, but the underlying design flaw — an unlock condition not bound to a unique contract identifier — remains the root cause, mirroring the GemPad bug class where withdrawal logic trusted caller-supplied parameters (amount/asset/address) instead of verifying against the specific locked record.

### Impact Explanation
An attacker who is one counterparty in several concurrently pending arbiter/escrow contracts (or who convinces a counterparty to open near-identical contracts, e.g., same amount/asset/pair reused for successive deals) can craft a single settlement unit whose one qualifying output satisfies the `has`-output condition for more than one shared address simultaneously. This can result in unauthorized release of escrowed funds from a locked contract without the corresponding payment actually being made to that contract's counterparty — a direct fund-loss/fund-freezing condition analogous to GemPad's ~$2M loss from a lock whose release check didn't verify the specific token/lock identity.

### Likelihood Explanation
Exploitation requires the attacker to control or influence the parameters of multiple concurrently open arbiter contracts with matching amount/asset/counterparty shape (achievable by a malicious or negligent trading counterparty since contract parameters are user/peer-supplied) and requires them to combine settlement into one transaction, which the code only partially blocks. Because the underlying condition-matching primitive (`has`) in `definition.js` is not contract/context-bound by design, and because it's exposed to any application (AAs, custom wallets, arbiter contracts) that builds "lock"-style address definitions using it, the likelihood of similar constructions elsewhere in the ecosystem re-introducing the same footgun is non-trivial.

### Recommendation
Bind unlock/authorization conditions for escrow/lock-style shared addresses to a unique, non-reusable identifier (e.g., include the contract hash or a unique nonce in the `has`/`has equal` filter, or always prefer the `"in data feed"` binding style already used for private assets) rather than relying solely on `{asset, amount, address}` tuples. Additionally, harden `definition.js`'s `has`/`has equal` evaluation so repeated identical outputs cannot satisfy multiple distinct conditions from the same unit unless explicitly intended (e.g., track and decrement matched outputs, or require `has equal`-style pairing with a per-contract identifier field).

### Proof of Concept
1. Alice and Bob open two arbiter contracts with identical `amount`, `asset`, `me_is_payer`/`peer` roles (e.g., two 100-byte trades between the same pair), producing two shared addresses whose definitions both reduce to `["and",[["address",Bob],["has",{what:"output",asset:"base",amount:100,address:Alice}]]]` per [5](#0-4) .
2. Bob crafts a single spending unit that: (a) spends from both shared addresses, and (b) includes exactly one output of 100 bytes to Alice (satisfying `has` for both, since the check only verifies presence in the unit's messages, not uniqueness per contract) — while sending the second contract's actual entitled amount to himself instead.
3. Because the mitigation only forbids "input from another address" (not duplicate/insufficient outputs across contracts of matching shape), if the "other address" heuristic doesn't cover this exact combination (e.g., inputs are all from Bob-controlled shared addresses, not "other" addresses), `validateAuthentifiers`'s `evaluateFilter` in [6](#0-5)  reports the `has` condition satisfied for both contracts from the single output, and the unit validates, letting Bob withdraw twice while paying once.

### Citations

**File:** arbiter_contract.js (L473-493)
```javascript
						["and", [
							["address", offeror_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
						]],
						["and", [
							["address", acceptor_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", acceptor_address]]
						]]
					]];
				var isPrivate = assetInfo && assetInfo.is_private;
				var isFixedDen = assetInfo && assetInfo.fixed_denominations;
				var hasArbStoreCut = arbstoreInfo.cut > 0;
				if (isPrivate) { // private asset
					arrDefinition[1][1] = ["and", [
						["address", offeror_address],
						["in data feed", [[acceptor_address], "CONTRACT_DONE_" + contract.hash, "=", offeror_address]]
					]];
					arrDefinition[1][2] = ["and", [
						["address", acceptor_address],
						["in data feed", [[offeror_address], "CONTRACT_DONE_" + contract.hash, "=", acceptor_address]]
					]];
```

**File:** arbiter_contract.js (L494-512)
```javascript
				} else {
					arrDefinition[1][1] = ["and", [
						["address", offeror_address],
						["has", {
							what: "output",
							asset: contract.asset || "base",
							amount: offeror_is_payer && !isFixedDen && hasArbStoreCut ? Math.floor(contract.amount * (1 - arbstoreInfo.cut)) : contract.amount,
							address: acceptor_address
						}]
					]];
					arrDefinition[1][2] = ["and", [
						["address", acceptor_address],
						["has", {
							what: "output",
							asset: contract.asset || "base",
							amount: offeror_is_payer || isFixedDen || !hasArbStoreCut ? contract.amount : Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
							address: offeror_address
						}]
					]];
```

**File:** arbiter_contract.js (L513-537)
```javascript
					if (!isFixedDen && hasArbStoreCut) {
						arrDefinition[1][offeror_is_payer ? 1 : 2][1].push(
							["has", {
								what: "output",
								asset: contract.asset || "base",
								amount: contract.amount - Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
								address: arbstoreInfo.address
							}]
						);
					}
					// protect against combining several contracts in a single transaction (if their parties, amounts, and assets are identical, the 'has what' above would satisfy both contracts, allowing the attacker to send the change to themselves)
					arrDefinition[1][1][1].push(
						["not", ["has", {
							what: "input",
							asset: contract.asset || "base",
							address: "other address",
						}]]
					);
					arrDefinition[1][2][1].push(
						["not", ["has", {
							what: "input",
							asset: contract.asset || "base",
							address: "other address",
						}]]
					);
```

**File:** definition.js (L1277-1373)
```javascript
	function evaluateFilter(op, filter, handleResult){
		var arrFoundObjects = [];
		for (var i=0; i<objUnit.messages.length; i++){
			var message = objUnit.messages[i];
			if (message.app !== "payment" || !message.payload) // we consider only public payments
				continue;
			var payload = message.payload;
			if (filter.asset){
				if (filter.asset === "base"){
					if (payload.asset)
						continue;
				}
				else if (filter.asset === "this asset"){
					if (payload.asset !== this_asset)
						continue;
				}
				else{
					if (payload.asset !== filter.asset)
						continue;
				}
			}
			if (filter.what === "input"){
				if (!Array.isArray(payload.inputs))
					continue;
				for (var j=0; j<payload.inputs.length; j++){
					var input = payload.inputs[j];
					if (!isNonemptyObject(input))
						continue;
					if (input.type === "headers_commission" || input.type === "witnessing")
						continue;
					if (filter.type){
						var type = input.type || "transfer";
						if (type !== filter.type)
							continue;
					}
					var augmented_input = objValidationState.arrAugmentedMessages ? objValidationState.arrAugmentedMessages[i].payload.inputs[j] : null;
					if (filter.address){
						if (filter.address === 'this address'){
							if (augmented_input.address !== address)
								continue;
						}
						else if (filter.address === 'other address'){
							if (augmented_input.address === address)
								continue;
						}
						else { // normal address
							if (augmented_input.address !== filter.address)
								continue;
						}
					}
					if (filter.amount && augmented_input.amount !== filter.amount)
						continue;
					if (filter.amount_at_least && augmented_input.amount < filter.amount_at_least)
						continue;
					if (filter.amount_at_most && augmented_input.amount > filter.amount_at_most)
						continue;
					arrFoundObjects.push({...(augmented_input || input), asset: payload.asset || "base", type: input.type || "transfer" });
				}
			} // input
			else if (filter.what === "output"){
				if (!Array.isArray(payload.outputs))
					continue;
				for (var j=0; j<payload.outputs.length; j++){
					var output = payload.outputs[j];
					if (!isNonemptyObject(output))
						continue;
					if (filter.address){
						if (filter.address === 'this address'){
							if (output.address !== address)
								continue;
						}
						else if (filter.address === 'other address'){
							if (output.address === address)
								continue;
						}
						else { // normal address
							if (output.address !== filter.address)
								continue;
						}
					}
					if (filter.amount && output.amount !== filter.amount)
						continue;
					if (filter.amount_at_least && output.amount < filter.amount_at_least)
						continue;
					if (filter.amount_at_most && output.amount > filter.amount_at_most)
						continue;
					arrFoundObjects.push({...output, asset: payload.asset || "base"});
				}
			} // output
		}
		if (arrFoundObjects.length === 0)
			return handleResult(false);
		if (op === "has one" && arrFoundObjects.length === 1)
			return handleResult(true);
		if (op === "has" && arrFoundObjects.length > 0)
			return handleResult(true, arrFoundObjects);
		handleResult(false);
```
