Confirmed: nowhere in `arbiter_contract.js` (`createAndSend`, `getHash`, `getHashSrc`) or in the `wallet.js` handler for `arbiter_contract_offer`/`arbiter_contract_shared` is there any check that `arbiter_address` differs from `my_address` or `peer_address`. This is a direct analog of the `yieldDistributorAddress == admin` self-dealing pattern: the arbiter role (a trusted, privileged fund-releasing party) is not prevented from coinciding with one of the contracting parties.

### Title
Arbiter address is never validated to differ from the contract parties, allowing a self-dealing arbiter to always win disputes and steal the counterparty's funds - (File: `arbiter_contract.js`)

### Summary
When creating or accepting an arbiter contract, neither party's proposed `arbiter_address` is checked against `my_address`/`peer_address`. A malicious contract proposer can set `arbiter_address` equal to their own address (or an address they control), making themselves the sole authority that resolves disputes for funds locked in the shared address, exactly analogous to the `yieldDistributorAddress` being settable to an admin address in the referenced report.

### Finding Description
`createAndSend()` [1](#0-0)  stores `objContract.arbiter_address` without any restriction, and the `getHash`/`getHashSrc` functions used to authenticate the offer only bind the value into the hash, never validate it [2](#0-1) . On the receiving side, the `arbiter_contract_offer` handler in `wallet.js` validates that `arbiter_address` is a syntactically valid address but never checks it is distinct from `my_address`/`peer_address` [3](#0-2) , and the same is true for `arbiter_contract_shared` [4](#0-3) .

The shared address definition built in `deriveSharedAddress()` makes fund release conditional on an `"in data feed"` posted by `contract.arbiter_address` naming the winner [5](#0-4) . Dispute resolution logic in `parseWinnerFromUnit()` accepts any unit whose author matches `contract.arbiter_address` and posts a `CONTRACT_<hash>` data feed value equal to either party's address as the binding "winner" [6](#0-5) . If `arbiter_address === my_address` (or an address controlled by the offering party), that same party can post the data-feed message declaring themselves the winner and unlock the shared funds unilaterally, bypassing the entire dispute process that arbitration is meant to enforce.

### Impact Explanation
This breaks the fundamental trust assumption of the arbiter-contract feature: an arbiter is supposed to be a mutually-trusted, disinterested third party. If a party can silently set the arbiter to themselves, they can guarantee winning any dispute and appropriate the funds locked in `shared_address`, resulting in concrete unauthorized fund loss for the counterparty — a Medium/High severity issue analogous to the reported `yieldDistributorAddress` self-assignment bug.

### Likelihood Explanation
Likelihood is high because the attack requires no special privilege — it can be executed by an ordinary user acting as the contract proposer (`objContract.my_address`) in `createAndSend()`, simply by choosing an `arbiter_address` value equal to their own address before sending the `arbiter_contract_offer` message. No validation on either the sending or receiving side prevents this.

### Recommendation
Add an explicit check, both when composing the offer in `createAndSend()`/`getHash()` and when validating an incoming offer in `wallet.js`'s `arbiter_contract_offer`/`arbiter_contract_shared` handlers, that rejects contracts where `arbiter_address === my_address` or `arbiter_address === peer_address`, e.g.:
```js
if (body.arbiter_address === body.my_address || body.arbiter_address === body.peer_address)
    return callbacks.ifError("arbiter cannot be one of the contract parties");
```

### Proof of Concept
1. Attacker Alice initiates an arbiter contract with Bob via `createAndSend()`, setting `arbiter_address = <Alice's own address>` (or an address she controls) instead of a genuine third-party arbiter's address.
2. Bob's wallet receives the `arbiter_contract_offer` message; the validation in `wallet.js` at lines 617-627 only checks that `arbiter_address` is a syntactically valid address, not that it differs from `my_address`/`peer_address`, so the offer is accepted [7](#0-6) .
3. Bob accepts and funds are locked into the `shared_address` whose spending condition allows release via an `"in data feed"` from `contract.arbiter_address` naming the winner [8](#0-7) .
4. If a dispute arises (or even without one), Alice — acting as her own "arbiter" — posts a unit from `arbiter_address` (= her own address) with a `data_feed` message `{"CONTRACT_<hash>": "<Alice's address>"}`.
5. `parseWinnerFromUnit()` accepts this unit as valid arbiter resolution since `objUnit.authors[0].address === contract.arbiter_address` [9](#0-8) , declaring Alice the winner and allowing her to spend the full locked funds from `shared_address`, stealing Bob's share.

### Citations

**File:** arbiter_contract.js (L21-35)
```javascript
function createAndSend(objContract, cb) {
	objContract = _.cloneDeep(objContract);
	objContract.creation_date = new Date().toISOString().slice(0, 19).replace('T', ' ');
	objContract.hash = getHash(objContract);
	device.getOrGeneratePermanentPairingInfo(pairingInfo => {
		objContract.my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
		db.query("INSERT INTO wallet_arbiter_contracts (hash, peer_address, peer_device_address, my_address, arbiter_address, me_is_payer, my_party_name, peer_party_name, amount, asset, is_incoming, creation_date, ttl, status, title, text, my_contact_info, my_pairing_code, cosigners) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, objContract.arbiter_address, objContract.me_is_payer ? 1 : 0, objContract.my_party_name, objContract.peer_party_name, objContract.amount, objContract.asset, 0, objContract.creation_date, objContract.ttl, status_PENDING, objContract.title, objContract.text, objContract.my_contact_info, objContract.my_pairing_code, JSON.stringify(objContract.cosigners) ... (truncated)
				var objContractForPeer = _.cloneDeep(objContract);
				delete objContractForPeer.cosigners;
				device.sendMessageToDevice(objContract.peer_device_address, "arbiter_contract_offer", objContractForPeer);
				if (cb) {
					cb(objContract);
				}
		});
	});
```

**File:** arbiter_contract.js (L194-207)
```javascript
function getHashSrc(contract) {
	const payer_name = contract.me_is_payer ? contract.my_party_name : contract.peer_party_name;
	const payee_name = contract.me_is_payer ? contract.peer_party_name : contract.my_party_name;
	const payer_address = contract.me_is_payer ? contract.my_address : contract.peer_address;
	const payee_address = contract.me_is_payer ? contract.peer_address : contract.my_address;
	const src = contract.creation_date > exports.NEW_HASH_DATE
		 ? [contract.title, contract.text, contract.creation_date, payer_address, payer_name || '', contract.arbiter_address, payee_address, payee_name || '', contract.amount, contract.asset || 'null'].join(exports.DELIMITER)
		 : [contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("");
	return src;
}

function getHash(contract) {
	return crypto.createHash("sha256").update(getHashSrc(contract), "utf8").digest("base64");
}
```

**File:** arbiter_contract.js (L465-481)
```javascript
				var arrDefinition =
					["or", [
						["and", [
							["address", offeror_address],
							["address", acceptor_address]
						]],
						[], // placeholders [1][1]
						[],	// placeholders [1][2]
						["and", [
							["address", offeror_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
						]],
						["and", [
							["address", acceptor_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", acceptor_address]]
						]]
					]];
```

**File:** arbiter_contract.js (L798-814)
```javascript
function parseWinnerFromUnit(contract, objUnit) {
	if (objUnit.authors[0].address !== contract.arbiter_address) {
		return;
	}
	var key = "CONTRACT_" + contract.hash;
	var winner;
	objUnit.messages.forEach(function(message){
		if (message.app !== "data_feed" || !message.payload || !message.payload[key]) {
			return;
		}
		winner = message.payload[key];
	});
	if (!winner || (winner !== contract.my_address && winner !== contract.peer_address)) {
		return;
	}
	return winner;
}
```

**File:** wallet.js (L617-627)
```javascript
			case 'arbiter_contract_offer':
				body.peer_device_address = from_address;
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.my_pairing_code || !ValidationUtils.isPositiveInteger(body.amount) || !(body.ttl > 0))
					return callbacks.ifError("not all contract fields submitted");
				if (body.status)
					return callbacks.ifError("status must not be submitted in contract offer");
				if (!ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.arbiter_address))
					return callbacks.ifError("either peer_address or address or arbiter_address is not valid in contract");
				if (body.hash !== arbiter_contract.getHash(body)) {
					return callbacks.ifError("wrong contract hash");
				}
```

**File:** wallet.js (L658-666)
```javascript
			case 'arbiter_contract_shared':
				if (!body.title || !body.text || !body.creation_date || !body.arbiter_address || typeof body.me_is_payer === "undefined" || !body.peer_pairing_code || !ValidationUtils.isPositiveInteger(body.amount))
					return callbacks.ifError("not all contract fields submitted");
				if (!ValidationUtils.isValidAddress(body.peer_address) || !ValidationUtils.isValidAddress(body.my_address) || !ValidationUtils.isValidAddress(body.arbiter_address) )
					return callbacks.ifError("either peer_address or address or arbiter_address or shared_address are not valid in contract");
				if (body.hash !== arbiter_contract.getHash(body))
					return callbacks.ifError("wrong contract hash");
				if (!/^\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}$/.test(body.creation_date))
					return callbacks.ifError("wrong contract creation date");
```
