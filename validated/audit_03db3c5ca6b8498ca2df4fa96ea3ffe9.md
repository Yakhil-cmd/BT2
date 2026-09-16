### Title
Textcoin bearer-secret mnemonic embedded in clickable URI leaks via logging/link-scanning, enabling theft of funds - (File: wallet.js, uri.js, email_template.html)

### Summary
Obyte "textcoins" (fund transfers to non-Obyte recipients, e.g. email addresses) are secured solely by a 12-word mnemonic that acts as a private key. This mnemonic is delivered by embedding it as a URI parameter/fragment (`https://obyte.org/#textcoin?{{mnemonic}}`, or `byteball:textcoin?<mnemonic>` for deep-linking) rather than out-of-band. Placing a value that grants full, no-further-authentication spending rights directly inside a URI is the same anti-pattern as CVE‑2018‑8764 (CSRF token placed in a URI `sec_token` parameter), where putting a sensitive token in a URL makes it far easier for a third party to obtain it "by leveraging logging" (mail gateway/AV link scanners, browser history sync, proxy/CDN access logs, referrer leaks from any page that later loads that link). Anyone who obtains the mnemonic from such logs can claim the textcoin before the intended recipient.

### Finding Description
When a payment is sent to a non-Obyte address (email, phone, etc.), `sendMultiPayment` generates a fresh BIP39 mnemonic and derives a single-sig address from it: [1](#0-0) 

This mnemonic is the sole "credential" for the funds — anyone who supplies it to `receiveTextCoin`/`expandMnemonic` derives the private key and can sign a spend with no other authentication: [2](#0-1) [3](#0-2) 

The mnemonic is delivered to the recipient by placing it directly inside a clickable URL, both in the transactional email template and in the plain-text fallback constructed by `replaceInTextcoinTemplate`: [4](#0-3) [5](#0-4) 

The same secret-in-URI pattern is also the canonical way ocore parses textcoin claim links from any client (deep link `byteball:textcoin?<mnemonic>` or the 12-word dash-joined form), confirming this is a first-class, wallet-reachable protocol feature, not an incidental email artifact: [6](#0-5) 

Because the bearer secret travels as a URI parameter/fragment rather than through a channel that cannot be silently fetched by intermediaries, it is exposed to exactly the class of leakage CVE‑2018‑8764 describes: corporate/consumer email security gateways and antivirus products that pre-fetch or "click" links in incoming mail for safety scanning, browser/OS link-preview and history-sync features, and HTTP/CDN/proxy access logs that record full request URLs (query strings, and in some environments even fragments once JS re-submits them to a server) — any of which can capture the plaintext mnemonic without any interactive action by the legitimate recipient. Once captured, the fetcher has the same rights as the legitimate recipient: full authority to construct and broadcast a spending unit for the addressed value.

### Impact Explanation
Unlike the referenced CVE (a CSRF-mitigation bypass), the value protected by the leaked secret here is directly monetary: the mnemonic is a bearer private key over posted, real value on the DAG. Leakage through logging/link-scanning lets an unrelated third party claim (spend) the textcoin before, or instead of, the intended recipient — a concrete unauthorized-spending/theft-of-funds outcome, matching the required impact bar (unauthorized spending of live funds).

### Likelihood Explanation
Email link-scanning/prefetching by security gateways and antivirus products is common and automatic, requiring no action from the attacker beyond the sender/recipient using the built-in "email a textcoin" feature or sharing a textcoin deep link through any channel that logs or previews URLs (chat apps generating link previews, SMS gateways, browser history sync). No privileged access or victim mistake beyond normal use of the shipped feature is required, making exploitation plausible for any textcoin sent via email or shared as a link.

### Recommendation
Do not place the bearer mnemonic directly in a URL that can be transmitted through channels subject to third-party fetching/logging (email bodies, deep links, previews). Instead, require an additional recipient-only secret/interaction (e.g., a one-time claim code delivered separately from the link, or a server-side redemption step gated by recipient confirmation) before the mnemonic's derived address can be spent from, or shorten the exposure window drastically and monitor/alert on claim attempts from IPs inconsistent with the recipient, and warn users prominently that forwarding or previewing textcoin links can result in loss of funds.

### Proof of Concept
1. Wallet A sends a textcoin payment to `victim@example.com` via `sendMultiPayment`, which calls `generateNewMnemonicIfNoAddress` to create a mnemonic-derived address and funds it (wallet.js:2213-2234).
2. `sendTextcoinEmail`/`replaceInTextcoinTemplate` emails the victim a link of the form `https://obyte.org/#textcoin?word1-word2-...-word12` (wallet.js:2605-2641; email_template.html:91,103).
3. The victim's corporate email gateway or antivirus performs automated "safe link" prefetching of every URL in the email (a widely deployed, standard mail-security behavior), and its access logs (or those of any intermediate CDN/proxy) record the full URL including the mnemonic.
4. An attacker with access to those logs (or who intercepts the prefetch traffic) extracts the mnemonic and calls the equivalent of `receiveTextCoin(mnemonic, attacker_address, ...)` (wallet.js:2657), deriving the private key via `expandMnemonic` (wallet.js:2643) and broadcasting a spend to their own address before the victim claims it.
5. The victim's later claim attempt fails ("This textcoin either was already claimed or never existed", wallet.js:2748), confirming the attacker obtained unauthorized spending of the posted funds purely from a leaked URL.

### Citations

**File:** wallet.js (L2219-2234)
```javascript
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
```

**File:** wallet.js (L2627-2641)
```javascript
function replaceInTextcoinTemplate(params, handleText){
	var fs = require('fs');
	fs.readFile(__dirname + '/email_template.html', 'utf8', function(err, template) {
		if (err)
			throw Error("failed to read template: "+err);
		_.forOwn(params, function(value, key){
			var re = new RegExp('\\{\\{' + key + '\\}\\}',"g");
			template = template.replace(re, value);
		});
		template = template.replace(/\{\{\w*\}\}/g, '');

		var text = "Here is your link to receive " + params.amount + " " + params.asset + params.usd_amount_str + ": https://obyte.org/#textcoin?" + params.mnemonic;
		handleText(template, text);
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

**File:** wallet.js (L2672-2690)
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
	};
```

**File:** email_template.html (L91-103)
```html
            <span class="preheader" style="color: transparent; display: none; height: 0; max-height: 0; max-width: 0; opacity: 0; overflow: hidden; mso-hide: all; visibility: hidden; width: 0;">Here is your link to receive {{amount}} {{asset}} {{usd_amount_str}}: https://obyte.org/#textcoin?{{mnemonic}}</span>
            <table class="main" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%; background: #ffffff; border-radius: 3px;">

              <!-- START MAIN CONTENT AREA -->
              <tr>
                <td class="wrapper" style="font-family: sans-serif; font-size: 14px; vertical-align: top; box-sizing: border-box; padding: 20px;">
                  <table border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;">
                    <tr>
                      <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">
                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">Hello,</p>
                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">Here is your link to receive <b>{{amount}} {{asset}}</b> {{usd_amount_str}}:</p>
                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-left: 0px; Margin-bottom: 15px;">
                        	<a href="https://obyte.org/#textcoin?{{mnemonic}}">https://obyte.org/#textcoin?{{mnemonic}}</a>
```

**File:** uri.js (L90-102)
```javascript
	// claim textcoin using mnemonic
	var arrMnemonicMatches = value.match(/^textcoin\?(.+)$/);
	if (arrMnemonicMatches){
		objRequest.type = "textcoin";
		var mnemonic = arrMnemonicMatches[1].split('-').join(' ');
		return handleMnemonic(mnemonic);
	}
	var arrWords = value.split('-');
	if (arrWords.length === 12){
		objRequest.type = "textcoin";
		mnemonic = arrWords.join(' ');
		return handleMnemonic(mnemonic);
	}
```
