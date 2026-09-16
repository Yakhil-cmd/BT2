### Title
Textcoin Claim-back Mnemonic (Private Key Equivalent) Logged in Plaintext - (File: wallet.js)

### Summary
`wallet.js`'s `claimBackOldTextcoins()` function unconditionally logs the raw BIP39 mnemonic of unclaimed textcoins via `console.log`, exposing the equivalent of a private key that fully controls the funds locked at that textcoin address.

### Finding Description
Textcoins are a private-payment primitive: `sendMultiPayment()` generates a mnemonic for each output whose address starts with the `"textcoin:"` prefix, derives a one-time signing address from it (`mnemonic.toHDPrivateKey().derive(...)`), and stores the mnemonic in the `sent_mnemonics` table so the payment can later be claimed by the mnemonic holder. [1](#0-0) 

If the recipient never claims the textcoin, the sender's own node periodically reclaims the funds via `claimBackOldTextcoins()`, which reads back the mnemonic from `sent_mnemonics` and calls `receiveTextCoin(row.mnemonic, ...)`. On both the success and failure paths, the **raw mnemonic** is written straight to the log with `console.log`: [2](#0-1) 

`expandMnemonic()` shows exactly what this mnemonic controls: it is turned directly into an `xPrivKey`, from which the `pubkey`, `definition` (`["sig", {"pubkey": ...}]`), and `address` are derived — i.e., possessing the mnemonic is equivalent to possessing the private key of that address. [3](#0-2) 

Unlike the address definitions/authentifiers that are safely handled elsewhere in the codebase (e.g., `signed_message.js` masks placeholder authentifiers with dashes before certain operations, and `object_hash.js`'s naked-unit helpers strip sensitive fields before hashing), this log statement dumps the credential-equivalent value with no redaction whatsoever, and — worse than the original report's `--v=2` gate — it is logged at the default `console.log` level with no verbosity guard at all.

### Impact Explanation
Anyone with access to the node's logs (log aggregation, shared debug dumps, `stdout` capture, support tickets) can read the plaintext mnemonic and immediately derive the private key for the textcoin address. Since `receiveTextCoin()` only requires the mnemonic to construct a valid `signer` and spend the funds, an attacker can race the node (or simply act before the node's own reclaim transaction confirms) and steal the outstanding textcoin balance — a concrete case of unauthorized spending of funds that were meant to go either to the original recipient or back to the sender.

### Likelihood Explanation
This code runs automatically as part of ordinary textcoin usage — a documented, commonly used private-payment feature (sending funds to an email/mnemonic-based address) — not a rare misconfiguration. Any node that sends textcoins and has been running long enough for an unclaimed textcoin to expire will trigger this log line without any special action, making exposure highly likely wherever logs are collected or shared.

### Recommendation
Remove the mnemonic from the log statements in `claimBackOldTextcoins()`; log only non-sensitive identifiers such as the derived address, unit, or asset:
```js
receiveTextCoin(row.mnemonic, to_address, function(err, unit, asset){
    if (err)
        console.log("failed claiming back old textcoin for address " + row.address + ": " + err);
    else
        console.log("claimed back textcoin for address " + row.address + ", unit " + unit + ", asset " + asset);
    cb();
});
```
If diagnostic visibility into the mnemonic is ever required, gate it behind an explicit debug flag and mask/redact it by default, mirroring the safe patterns already used elsewhere in the codebase for other sensitive fields.

### Proof of Concept
1. Send a payment to a `textcoin:` address (or an email address) via `sendMultiPayment`; the node generates a mnemonic, derives a one-time address, and stores the mnemonic in `sent_mnemonics`. [4](#0-3) 
2. Do not claim the textcoin before the configured expiry (`days`).
3. When the node's maintenance job calls `claimBackOldTextcoins(to_address, days)`, it queries `sent_mnemonics` for the expired, unclaimed mnemonic and logs it verbatim:
```
claimed back mnemonic correct-horse-battery-staple, unit XXXX..., asset base
``` [5](#0-4) 
4. Anyone with access to this log line can run `expandMnemonic("correct-horse-battery-staple")` to derive the private key/address and spend the corresponding funds ahead of the legitimate reclaim transaction. [3](#0-2)

### Citations

**File:** wallet.js (L2213-2233)
```javascript
			function generateNewMnemonicIfNoAddress(output_asset, outputs) {
				var generated = 0;
				outputs.forEach(function(output){
					if (output.address.indexOf(prefix) !== 0)
						return false;

					var address = output.address.slice(prefix.length);
					var strMnemonic = assocMnemonics[output.address] || "";
					var mnemonic = new Mnemonic(strMnemonic.replace(/-/g, " "));
					if (!strMnemonic) {
						while (!Mnemonic.isValid(mnemonic.toString()))
							mnemonic = new Mnemonic();
						strMnemonic = mnemonic.toString().replace(/ /g, "-");
					}
					if (!opts.do_not_email && ValidationUtils.isValidEmail(address)) {
						assocPaymentsByEmail[address] = {mnemonic: strMnemonic, amount: output.amount, asset: output_asset};
					}
					assocMnemonics[output.address] = strMnemonic;
					var pubkey = mnemonic.toHDPrivateKey().derive("m/44'/0'/0'/0/0").publicKey.toBuffer().toString("base64");
					assocAddresses[output.address] = objectHash.getChash160(["sig", {"pubkey": pubkey}]);
					output.address = assocAddresses[output.address];
```

**File:** wallet.js (L2643-2655)
```javascript
function expandMnemonic(mnemonic) {
	var addrInfo = {};
	mnemonic = mnemonic.toLowerCase().split('-').join(' ');
	if ((mnemonic.split(' ').length % 3 !== 0) || !Mnemonic.isValid(mnemonic)) {
		throw new Error("invalid mnemonic: "+mnemonic);
	}
	mnemonic = new Mnemonic(mnemonic);
	addrInfo.xPrivKey = mnemonic.toHDPrivateKey().derive("m/44'/0'/0'/0/0");
	addrInfo.pubkey = addrInfo.xPrivKey.publicKey.toBuffer().toString("base64");
	addrInfo.definition = ["sig", {"pubkey": addrInfo.pubkey}];
	addrInfo.address = objectHash.getChash160(addrInfo.definition);
	return addrInfo;
}
```

**File:** wallet.js (L2818-2839)
```javascript
function claimBackOldTextcoins(to_address, days){
	if (typeof days !== 'number')
		throw Error("bad days: " + days);
	db.query(
		"SELECT mnemonic FROM sent_mnemonics LEFT JOIN unit_authors USING(address) \n\
		WHERE mnemonic!='' AND unit_authors.address IS NULL AND creation_date<"+db.addTime("-"+days+" DAY"),
		function(rows){
			async.eachSeries(
				rows,
				function(row, cb){
					receiveTextCoin(row.mnemonic, to_address, function(err, unit, asset){
						if (err)
							console.log("failed claiming back old textcoin "+row.mnemonic+": "+err);
						else
							console.log("claimed back mnemonic "+row.mnemonic+", unit "+unit+", asset "+asset);
						cb();
					});
				}
			);
		}
	);
}
```
