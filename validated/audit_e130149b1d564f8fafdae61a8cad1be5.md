### Title
Ambiguous field concatenation in arbiter contract hash allows content-collision forgery - (File: arbiter_contract.js)

### Summary
`getHashSrc()` in `arbiter_contract.js` builds the preimage for the arbiter-contract hash by concatenating fully user-controlled strings (`title`, `text`, `my_party_name`/`peer_party_name`) with a fixed delimiter, without ever stripping/escaping that delimiter from the input fields. Because the delimiter can itself be embedded inside `title`/`text`, two semantically different contracts can be crafted to produce byte-identical concatenated strings, and therefore an identical SHA-256 hash, at `arbiter_contract.js:194-207`. [1](#0-0) 

### Finding Description
`getHashSrc(contract)` joins an ordered array of contract fields with `exports.DELIMITER = "[|#|]"` (or with no delimiter at all for contracts created before `NEW_HASH_DATE`): [2](#0-1) [1](#0-0) 

`title` and `text` are free-form strings supplied by whichever party creates/offers the contract (`createAndSend`, `store`, `handleNewSharedAddress`-style flows) and are stored verbatim in `wallet_arbiter_contracts` with no validation that they don't contain the delimiter sequence `[|#|]`: [3](#0-2) 

Because the join always inserts the delimiter at the same *positions* regardless of the field contents, an attacker who controls `title`/`text` can choose values that embed the delimiter such that the resulting concatenated byte string is identical to the string produced by a different `(title, text)` pair. For example:
- Contract A: `title = "AB" + DELIM + "C"`, `text = "D"`
- Contract B: `title = "AB"`, `text = "C" + DELIM + "D"`

Both produce the identical joined string `"AB" + DELIM + "C" + DELIM + "D" + DELIM + ...(rest)`, hence the identical `sha256` hash returned by `getHash()`: [4](#0-3) 

This hash (`contract.hash`) is the sole cryptographic commitment used throughout the arbiter-contract lifecycle: it is what the counterparty is shown and asked to sign, what is bound into a "data" message on the DAG (`payload.contract_text_hash`) and checked at `handleReceivedSigningUnit`, and what is later sent to the arbstore/arbiter for dispute resolution and appeal (`openDispute`/`appeal`), where the *actual* `title`/`text` (not just the hash) are resent out-of-band to the arbiter: [5](#0-4) [6](#0-5) 

Because the on-chain commitment (`contract.hash`) does not uniquely determine the `(title, text, party names)` tuple, a malicious party can present one version of the contract text to get the counterparty's signature/on-chain commitment, and later present a different, hash-colliding version of the contract text to the arbiter during `openDispute`/`appeal`, where the dispute outcome (and thus the release of escrowed funds from the shared/arbiter-controlled address) is decided.

This is the same bug class as the reported `registerFunctionSelector` issue: a signature/selector is derived by concatenating attacker-influenced substrings with a delimiter that is not guaranteed to be absent from those substrings, producing an ambiguous/colliding derived value that downstream logic treats as a unique, tamper-evident identifier.

### Impact Explanation
The arbiter contract mechanism secures fund flows through an arbiter-mediated shared address: the `contract.hash` is meant to be an immutable, unambiguous binding of the deal terms that both parties sign and that the arbiter later uses to resolve payment disputes. If the hash can be made to correspond to two different sets of terms, a malicious payer/payee can get the counterparty to accept and sign one version of the contract (governing escrow release conditions) while later supplying a different, colliding version of the text to the arbiter during dispute/appeal — misleading the arbiter's ruling and causing the counterparty to lose the escrowed funds, or letting the attacker plausibly deny the terms actually agreed. This is a concrete AA/escrow fund-loss vector reachable by any private-payment counterparty negotiating an arbiter contract, not merely a griefing/DoS nuisance.

### Likelihood Explanation
Both parties to an arbiter contract are, by design, mutually distrusting counterparties (this is the entire purpose of using an arbiter). Crafting a `title`/`text` pair with an embedded `[|#|]` sequence requires no special privilege — it's plain text supplied through the normal contract-creation UI/API path (`createAndSend`), and any attacker acting as either the payer or payee in a P2P arbiter deal can attempt this. No cryptographic break is required — only string construction — and the delimiter string is a fixed, publicly known constant (`"[|#|]"`), so this is a Medium-to-High likelihood issue whenever arbiter contracts are used for real value.

### Recommendation
- Avoid free-form delimiter-based concatenation for hash preimages of variable-length/user-controlled fields. Instead, use length-prefixed encoding or `JSON.stringify`/canonical structured hashing (as done elsewhere in the codebase via `object_hash.getSourceString`/`getJsonSourceString`) so that field boundaries cannot be manipulated by the field contents.
- Alternatively, explicitly reject or escape any occurrence of `exports.DELIMITER` inside `title`, `text`, `my_party_name`, and `peer_party_name` before hashing.
- Apply the same fix to the pre-`NEW_HASH_DATE` branch (`join("")`), which has no delimiter at all and is even more trivially ambiguous, and to `getContactsHash()` which has the same pattern with `"|"`.
- Consider a similar audit of `prosaic_contract.js`'s hash construction, which uses the same historical concatenation pattern.

### Proof of Concept
```js
const arbiter_contract = require('./arbiter_contract.js');

const common = {
  creation_date: '2027-01-01 00:00:00', // > NEW_HASH_DATE, uses DELIM branch
  me_is_payer: true,
  my_address: 'PAYER_ADDR',
  peer_address: 'PAYEE_ADDR',
  arbiter_address: 'ARBITER_ADDR',
  amount: 1000,
  asset: null,
};

const DELIM = arbiter_contract.DELIMITER; // "[|#|]"

// Contract A: title="AB[|#|]C", text="D"
const contractA = { ...common, title: 'AB' + DELIM + 'C', text: 'D', my_party_name: '', peer_party_name: '' };

// Contract B: title="AB", text="C[|#|]D"  -- different logical terms
const contractB = { ...common, title: 'AB', text: 'C' + DELIM + 'D', my_party_name: '', peer_party_name: '' };

console.log(arbiter_contract.getHashSrc ? arbiter_contract.getHashSrc(contractA) : 'exported internally');
// Both produce the identical hash despite different title/text content:
// hashA === hashB
```
(Note: `getHashSrc`/`getHash` are not exported in the current module; the PoC requires either exporting them for testing or reproducing the exact array-join logic shown at `arbiter_contract.js:194-207` to demonstrate the collision, since the underlying `join(DELIMITER)` construction is fully deterministic and requires no randomness or race condition to exploit.)

### Citations

**File:** arbiter_contract.js (L16-19)
```javascript
var status_PENDING = "pending";
exports.CHARGE_AMOUNT = 4000;
exports.NEW_HASH_DATE = '2026-11-01';
exports.DELIMITER = "[|#|]";
```

**File:** arbiter_contract.js (L21-36)
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
}
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

**File:** arbiter_contract.js (L277-296)
```javascript
					var data = {
						contract_hash: hash,
						unit: objContract.unit,
						my_address: objContract.my_address,
						peer_address: objContract.peer_address,
						me_is_payer: objContract.me_is_payer,
						my_pairing_code: objContract.my_pairing_code,
						peer_pairing_code: objContract.peer_pairing_code,
						encrypted_contract: device.createEncryptedPackage({
							title: objContract.title,
							text: objContract.text,
							creation_date: objContract.creation_date,
							plaintiff_party_name: objContract.my_party_name,
							respondent_party_name: objContract.peer_party_name,
							my_contact_info: objContract.my_contact_info,
							peer_contact_info: objContract.peer_contact_info,
						}, objArbiter.device_pub_key),
						my_contact_info: objContract.my_contact_info,
						peer_contact_info: objContract.peer_contact_info
					};
```

**File:** arbiter_contract.js (L339-344)
```javascript
				var data = JSON.stringify({
					contract_hash: hash,
					my_pairing_code: objContract.my_pairing_code,
					my_address: objContract.my_address,
					contract: {title: objContract.title, text: objContract.text, creation_date: objContract.creation_date, me_is_payer: objContract.me_is_payer, my_address: objContract.my_address, peer_address: objContract.peer_address, my_party_name: objContract.my_party_name, peer_party_name: objContract.peer_party_name, arbiter_address: objContract.arbiter_address, amount: objContract.amount, asset: objContract.asset},
				});
```
