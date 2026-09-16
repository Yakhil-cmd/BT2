### Title
Textcoin mnemonics (spending private keys) written in plaintext to console/log output - ([File: wallet.js])

### Summary
`wallet.js`'s textcoin claim-back logic logs the full textcoin mnemonic — the seed from which the textcoin address's private key is derived — via `console.log`, the same class of issue as CVE-2023-1550 (sensitive key material inserted into a log file). Anyone with read access to the node's log output (stdout/log file) can recover the mnemonic and steal the funds sitting at that textcoin address.

### Finding Description
Textcoins are wallet-less payments in which the sender generates a BIP39 `Mnemonic`, derives an address from it, and sends funds to that address; whoever holds the mnemonic can derive `xPrivKey`/`privateKey` and spend the funds [1](#0-0) . The mnemonic itself is therefore equivalent to a private key controlling on-chain funds.

The periodic sweep function `claimBackOldTextcoins` retries claiming unclaimed textcoins and logs the raw mnemonic string on both the failure and success paths: [2](#0-1) 

Additionally, `deriveAddress` in `wallet_defined_by_keys.js` logs full extended public keys used for cosigner address derivation, which — while not itself a private key — reveals xpub material tied to specific wallets/devices: [3](#0-2) .

The relevant reachable code path is: an unprivileged unit poster/AA-triggered textcoin sender creates the textcoin (`sendMultiPayment` → `generateNewMnemonicIfNoAddress`) [4](#0-3) , and the recipient never claims it; the node's own periodic job `claimBackOldTextcoins` then emits the mnemonic into the process's standard log stream [5](#0-4) . This is analogous to the NGINX Agent bug where sensitive credential-equivalent data was written to log files by design, only exposed under certain conditions (trace logging there; unclaimed-textcoin retry here).

### Impact Explanation
Whoever can read the node's console/log output (log aggregation systems, shared hosting, misconfigured permissions, crash reporters that capture stdout, support/ops staff) obtains the mnemonic and can derive the private key for the address, resulting in unauthorized spending / theft of the textcoin funds before the intended recipient claims them. This is a direct, concrete unauthorized-spending vector, not merely an information leak.

### Likelihood Explanation
This code path executes automatically and unconditionally (not behind a debug/trace flag) whenever a wallet host runs `claimBackOldTextcoins` on any created-but-unclaimed textcoin, so exposure does not require an attacker-controlled debug setting — it is always logged as ordinary operational output at `console.log` level (the default, non-trace, non-suppressible level in Node.js). Any actor with log-file/stdout access (a common trust boundary weaker than direct wallet-file access, e.g., log-shipping services, hosting providers, or other local users) can read it.

### Recommendation
- Remove or redact the mnemonic from `console.log` output in `claimBackOldTextcoins` (`wallet.js`); log only the unit/address/asset, never the mnemonic itself.
- Similarly avoid logging derived pubkeys/xpubs verbatim in `wallet_defined_by_keys.js`'s `deriveAddress`.
- Route any necessary diagnostic detail through a debug-gated logger that defaults to off and is documented as security-sensitive, and audit other `console.log` call sites in `device.js`/`wallet.js` that reference `priv_key`, decrypted device messages, etc., for similar leakage.

### Proof of Concept
1. Sender calls `sendMultiPayment` with an output using the `textcoin:` address prefix (e.g., an email-based recipient) — this generates a mnemonic and funds the derived address [4](#0-3) .
2. The recipient never claims it within the configured number of days.
3. The node's scheduled job invokes `claimBackOldTextcoins(to_address, days)`, which queries unclaimed `sent_mnemonics` and logs each mnemonic verbatim via `console.log("claimed back mnemonic "+row.mnemonic+...)` or the failure branch [2](#0-1) .
4. Any party with access to the node's stdout/log files (log shipping, hosting provider, other local users) reads the mnemonic, reconstructs the `Mnemonic`/`HDPrivateKey`, and spends the funds at the derived address before/instead of the legitimate owner.

### Citations

**File:** wallet.js (L2213-2236)
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
					generated++;
				});
				return generated;
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

**File:** wallet_defined_by_keys.js (L559-564)
```javascript
				rows.forEach(function(row){
					if (!row.extended_pubkey)
						throw Error("no extended_pubkey for wallet "+wallet);
					params['pubkey@'+row.device_address] = derivePubkey(row.extended_pubkey, path);
					console.log('pubkey for wallet '+wallet+' path '+path+' device '+row.device_address+' xpub '+row.extended_pubkey+': '+params['pubkey@'+row.device_address]);
				});
```
