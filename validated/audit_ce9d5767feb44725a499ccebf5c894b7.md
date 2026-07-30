### Title
Missing zero-address validation on bridge `target_address` / `recipientAddress` allows permanent burn of bridged ETH - ([File: bridge/evm/contracts/SuiBridge.sol])

### Summary
The Sui native bridge never validates that the destination-chain recipient address supplied by an ordinary (unprivileged) bridge user is non-zero. On the Sui side, `send_token`/`send_token_v2` in `crates/sui-framework/packages/bridge/sources/bridge.move` only assert the `target_address` byte-length equals `EVM_ADDRESS_LENGTH` (20 bytes); on the EVM side, `_transferTokensFromVault` in `bridge/evm/contracts/SuiBridge.sol` and `SuiBridgeV2.sol` also never checks `recipientAddress != address(0)` before invoking `vault.transferETH`. Because `BridgeVault.transferETH` moves ETH via a raw low-level `call` (which succeeds when sent to `address(0)`), an all-zero 20-byte target address is a structurally valid message that the committee will happily sign and that will permanently burn the bridged ETH once claimed.

### Finding Description
`send_token`/`send_token_v2` accept an arbitrary `target_address: vector<u8>` from any Sui token holder and only check the length: [1](#0-0) 

The committee's `verify_signatures` (both Move and Solidity implementations) validates only ECDSA signatures, voting power, and blocklist status of signers — never the semantic content (e.g., zero-ness) of the recipient address embedded in the message: [2](#0-1) [3](#0-2) 

On the EVM claim side, `_transferTokensFromVault` decodes the recipient from the approved message and checks only that the *token* address is non-zero, not the *recipient*: [4](#0-3) 

`BridgeVault.transferETH` unwraps WETH and forwards ETH with a raw `call`, which does not revert when the target is `address(0)`: [5](#0-4) 

The same pattern also exists in `SuiBridgeV2.sol`'s `_transferTokensFromVault`: [6](#0-5) 

This is the same root cause as the referenced Aave `BridgeExecutorBase.sol` report: an address-typed value derived from unvalidated input is used directly in a value-transferring call without a zero-address guard. The difference here is the consequence is not merely "the transaction reverts" — for ETH it is a **silent, low-level success that permanently destroys funds**, since `address(0)` has no controlling key on the destination chain.

### Impact Explanation
Any unprivileged Sui token holder can call `send_token`/`send_token_v2` with a 20-byte all-zero `target_address`. The message passes every existing structural check (length, chain id, signature/stake threshold) and is approved by the committee like any legitimate transfer. When claimed on the EVM side for the `BridgeUtils.ETH` token type, `vault.transferETH(payable(address(0)), amount)` succeeds, permanently locking/burning the bridged ETH with no recovery path. This matches the in-scope **High** impact class "permanent fund lock." (For ERC20 tokens, OpenZeppelin's `SafeERC20.safeTransfer` to `address(0)` typically reverts, so the impact is confined to the ETH/WETH transfer path.)

### Likelihood Explanation
Reachable entirely from unprivileged, public input — no validator, admin, or bridge-authority collusion required. The attacker only needs to call the standard `send_token`/`send_token_v2` entry point with a zero-filled 20-byte address and pay normal bridge fees/limits; the committee has no reason to reject a structurally valid message.

### Recommendation
Add an explicit non-zero check on the decoded/target recipient address at message-creation time (Move `send_token`/`send_token_v2`) and again at claim time (`_transferTokensFromVault` in both `SuiBridge.sol` and `SuiBridgeV2.sol`), e.g. `require(recipientAddress != address(0), "SuiBridge: Invalid recipient address")`, mirroring the existing `tokenAddress != address(0)` check.

### Proof of Concept
1. Attacker calls `bridge::send_token<T>(bridge, target_chain, x"0000000000000000000000000000000000000000", coin, ctx)` on Sui with a genuine `Coin<SUI>`/WETH-backed token — this passes `assert!(target_address.length() == EVM_ADDRESS_LENGTH, ...)` since the zero address is still 20 bytes.
2. Bridge committee members observe a structurally valid `TokenDepositedEvent` and sign it normally (their verification logic never inspects recipient content).
3. Anyone submits `claimToken`/`transferBridgedTokensWithSignatures` on the EVM `SuiBridge` contract with the approved message; `_transferTokensFromVault` calls `vault.transferETH(payable(address(0)), amount)`.
4. `BridgeVault.transferETH` unwraps WETH and does `recipientAddress.call{value: amount}("")` to `address(0)`, which succeeds, permanently destroying the ETH.

### Citations

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L228-232)
```text
    let token_id = inner.treasury.token_id<T>();
    let token_amount = token.balance().value();
    assert!(target_address.length() == EVM_ADDRESS_LENGTH, EInvalidEvmAddress);
    assert!(token_amount > 0, ETokenValueIsZero);

```

**File:** crates/sui-framework/packages/bridge/sources/committee.move (L89-120)
```text
public fun verify_signatures(
    self: &BridgeCommittee,
    message: BridgeMessage,
    signatures: vector<vector<u8>>,
) {
    let (mut i, signature_counts) = (0, vector::length(&signatures));
    let mut seen_pub_key = vec_set::empty<vector<u8>>();
    let required_voting_power = message.required_voting_power();
    // add prefix to the message bytes
    let mut message_bytes = SUI_MESSAGE_PREFIX;
    message_bytes.append(message.serialize_message());

    let mut threshold = 0;
    while (i < signature_counts) {
        let pubkey = ecdsa_k1::secp256k1_ecrecover(&signatures[i], &message_bytes, 0);

        // check duplicate
        // and make sure pub key is part of the committee
        assert!(!seen_pub_key.contains(&pubkey), EDuplicatedSignature);
        assert!(self.members.contains(&pubkey), EInvalidSignature);

        // get committee signature weight and check pubkey is part of the committee
        let member = &self.members[&pubkey];
        if (!member.blocklisted) {
            threshold = threshold + member.voting_power;
        };
        seen_pub_key.insert(pubkey);
        i = i + 1;
    };

    assert!(threshold >= required_voting_power, ESignatureBelowThreshold);
}
```

**File:** bridge/evm/contracts/BridgeCommittee.sol (L75-106)
```text
    function verifySignatures(bytes[] memory signatures, BridgeUtils.Message memory message)
        external
        view
        override
    {
        uint32 requiredStake = BridgeUtils.requiredStake(message);

        uint16 approvalStake;
        address signer;
        uint256 bitmap;

        // Check validity of each signature and aggregate the approval stake
        for (uint16 i; i < signatures.length; i++) {
            bytes memory signature = signatures[i];
            // recover the signer from the signature
            (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);

            (signer,,) = ECDSA.tryRecover(BridgeUtils.computeHash(message), v, r, s);

            require(!blocklist[signer], "BridgeCommittee: Signer is blocklisted");
            require(committeeStake[signer] > 0, "BridgeCommittee: Signer has no stake");

            uint8 index = committeeIndex[signer];
            uint256 mask = 1 << index;
            require(bitmap & mask == 0, "BridgeCommittee: Duplicate signature provided");
            bitmap |= mask;

            approvalStake += committeeStake[signer];
        }

        require(approvalStake >= requiredStake, "BridgeCommittee: Insufficient stake amount");
    }
```

**File:** bridge/evm/contracts/SuiBridge.sol (L244-265)
```text
    function _transferTokensFromVault(
        uint8 sendingChainID,
        uint8 tokenID,
        address recipientAddress,
        uint256 amount
    ) private whenNotPaused limitNotExceeded(sendingChainID, tokenID, amount) {
        address tokenAddress = committee.config().tokenAddressOf(tokenID);

        // Check that the token address is supported
        require(tokenAddress != address(0), "SuiBridge: Unsupported token");

        // transfer eth if token type is eth
        if (tokenID == BridgeUtils.ETH) {
            vault.transferETH(payable(recipientAddress), amount);
        } else {
            // transfer tokens from vault to target address
            vault.transferERC20(tokenAddress, recipientAddress, amount);
        }

        // update amount bridged
        limiter.recordBridgeTransfers(sendingChainID, tokenID, amount);
    }
```

**File:** bridge/evm/contracts/BridgeVault.sol (L52-64)
```text
    function transferETH(address payable recipientAddress, uint256 amount)
        external
        override
        onlyOwner
        nonReentrant
    {
        // Unwrap the WETH
        wETH.withdraw(amount);

        // Transfer the unwrapped ETH to the target address
        (bool success,) = recipientAddress.call{value: amount}("");
        require(success, "ETH transfer failed");
    }
```

**File:** bridge/evm/contracts/SuiBridgeV2.sol (L187-206)
```text
    function _transferTokensFromVault(
        uint8 sendingChainID,
        uint8 tokenID,
        address recipientAddress,
        uint256 amount,
        uint256 timestampSeconds
    ) private whenNotPaused limitNotExceededV2(sendingChainID, tokenID, amount, timestampSeconds) {
        address tokenAddress = committee.config().tokenAddressOf(tokenID);

        // Check that the token address is supported
        require(tokenAddress != address(0), "SuiBridge: Unsupported token");

        // transfer eth if token type is eth
        if (tokenID == BridgeUtils.ETH) {
            vault.transferETH(payable(recipientAddress), amount);
        } else {
            // transfer tokens from vault to target address
            vault.transferERC20(tokenAddress, recipientAddress, amount);
        }
    }
```
