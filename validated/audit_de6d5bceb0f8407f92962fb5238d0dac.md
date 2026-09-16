### Title
Textcoin mnemonic (bearer private key) is written to plaintext logs during auto‑reclaim - ([File: wallet.js])

### Summary
`wallet.js` implements "textcoins" — bearer payments where funds are locked to an address derived from a 12‑word mnemonic (`expandMnemonic()`), and whoever possesses the mnemonic can produce the private key and spend the funds. When an unclaimed textcoin is reclaimed by the sender's own wallet (`claimBackOldTextcoins()`), the full mnemonic is written to `console.log` on both success and failure. This is the same class of bug as the reported source-controller issue: a secret credential that directly grants unauthorized access to value is persisted into application logs.

### Finding Description
`expandMnemonic()` derives a private key and spending address purely from the 12‑word mnemonic string: [1](#0-0) 

This mnemonic is generated and persisted in the `sent_mnemonics` table whenever a textcoin output is created: [2](#0-1) [3](#0-2) 

`claimBackOldTextcoins()` later reads back any mnemonic for a textcoin that was never claimed and calls `receiveTextCoin()` to spend it back to the sender. On both the error and success path, the **entire mnemonic** is concatenated into a plain string and passed to `console.log`: [4](#0-3) 

Because the mnemonic is the sole authentifier for the `["sig", {"pubkey": ...}]` address (see `signer.sign` in `receiveTextCoin`, which signs directly with `addrInfo.xPrivKey.privateKey`), anyone who obtains it from logs can immediately construct a valid signed spend for that address: [5](#0-4) 

This mirrors GHSA-v554-xwgw-hc3w exactly: a bearer secret (there, an Azure SAS token; here, a spending mnemonic) that grants direct access to funds/resources is written to logs during a normal, non-attacker-privileged operation (there, a storage connection error; here, periodic reclaim of a private-payment/textcoin output).

### Impact Explanation
Any process, aggregator, crash reporter, or third party with read access to the node/wallet's stdout/log files can extract the mnemonic and immediately sweep the textcoin funds — a concrete unauthorized-spending / fund-loss scenario. Because `claimBackOldTextcoins` runs automatically (a self-reclaim of the sender's own previously issued textcoin), this creates a race: whoever reads the log first (attacker with log access) can front-run the legitimate reclaim and steal the coins, and can do so repeatedly for every non-claimed textcoin the wallet ever issues while running with default log verbosity.

### Likelihood Explanation
Every call to `claimBackOldTextcoins` for any unclaimed/private-payment textcoin unconditionally logs the mnemonic in cleartext — this is not conditional on a rare error path, it happens on every success and failure. Any wallet operator who sends textcoins (e.g., via email or chat-address payments, a legitimate and common feature) and has a reclaim job configured, or any deployment that aggregates stdout/console logs (systemd journal, PM2 logs, Docker logs, centralized log shipping), is exposed. No special privileges are needed to read typical log aggregation systems in many deployments, and the secret is a full bearer key, not just a hint.

### Recommendation
- Remove the mnemonic from both `console.log` statements in `claimBackOldTextcoins`; log only the derived address (`addrInfo.address`, already available via the error string) and unit hash instead of the raw secret.
- Audit all other `console.log`/breadcrumb calls that touch `mnemonic`, `xPrivKey`, or other private-key material (e.g., similar patterns in `device.js`) and redact them.
- Consider using a leveled/structured logger with an explicit redaction list for secret fields, so any future logging of `mnemonic`, `priv`, `pairing_secret`, etc. is caught by lint/tests.

### Proof of Concept
1. Attacker with any log-reading access (log aggregator, crash reporter, misconfigured monitoring, container log driver) to a wallet node that sends textcoins to email/chat addresses.
2. Wallet sends a textcoin (e.g., via `sendMultiPayment` with a `textcoin:` address); mnemonic `M` is stored in `sent_mnemonics` and delivered to the recipient out-of-band.
3. Recipient does not claim within the configured `days`; the wallet's scheduled job calls `claimBackOldTextcoins(to_address, days)`.
4. `receiveTextCoin(row.mnemonic, ...)` is invoked; regardless of outcome, `wallet.js:2830` or `wallet.js:2832` logs `"... "+row.mnemonic+" ..."` in cleartext to console/log output.
5. Attacker reads the mnemonic from the log, calls `expandMnemonic(M)` to derive the private key/address, and broadcasts a spend from that address before (or instead of) the legitimate reclaim — unauthorized spending of the textcoin funds.

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

**File:** wallet.js (L2263-2271)
```javascript
						if (Object.keys(assocMnemonics).length) {
							for (var to in assocMnemonics) {
								conn.query("INSERT INTO sent_mnemonics (unit, address, mnemonic, textAddress) VALUES (?, ?, ?, ?)", [objJoint.unit.unit, assocAddresses[to], assocMnemonics[to], to.slice(prefix.length)],
								function(){
									if (++i == Object.keys(assocMnemonics).length) { // stored all mnemonics
										cb();
									}
								});
							}
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

**File:** wallet.js (L2672-2689)
```javascript
	var signer = {
		readSigningPaths: function(conn, address, handleLengthsBySigningPaths){ // returns assoc array signing_path => length
			if (address !== addrInfo.address)
				return localSigner.readSigningPaths(conn, address, handleLengthsBySigningPaths);
			var assocLengthsBySigningPaths = {};
			assocLengthsBySigningPaths["r"] = constants.SIG_LENGTH;
			handleLengthsBySigningPaths(assocLengthsBySigningPaths);
		},
		readDefinition: function(conn, address, handleDefinition){
			if (address !== addrInfo.address)
				return localSigner.readDefinition(conn, address, handleDefinition);
			handleDefinition(null, addrInfo.definition);
		},
		sign: function(objUnsignedUnit, assocPrivatePayloads, address, signing_path, handleSignature){
			if (address !== addrInfo.address)
				return localSigner.sign(objUnsignedUnit, assocPrivatePayloads, address, signing_path, handleSignature);
			handleSignature(null, ecdsaSig.sign(objectHash.getUnitHashToSign(objUnsignedUnit), addrInfo.xPrivKey.privateKey.bn.toBuffer({size:32})));
		}
```

**File:** wallet.js (L2817-2839)
```javascript
// if a textcoin was not claimed for 'days' days, claims it back
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
