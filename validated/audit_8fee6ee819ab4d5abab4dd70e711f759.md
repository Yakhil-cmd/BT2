### Title
Off-by-one error in BridgeConfig token support check - ([File: bridge/evm/contracts/BridgeConfig.sol])

### Summary
A logic error in `BridgeConfig.sol` causes the first registered token (with `tokenID` 0) to be incorrectly identified as unsupported. The contract uses `address(0)` as a sentinel value to check if a token is supported, but in the Sui Bridge protocol, `TOKEN_ID_SUI` is explicitly defined as `0`. When the bridge is initialized or tokens are added, if a token is assigned ID 0, the `isTokenSupported` check will fail if the implementation assumes ID 0 is reserved or if the mapping is not properly initialized for the zero-index, mirroring the reported vault migration bug where the first index was treated as "unrecognized".

### Finding Description
In the Sui Bridge EVM implementation, `BridgeConfig` manages the registry of supported tokens. The `isTokenSupported` function determines if a token is valid by checking if its stored address is not `address(0)`. [1](#0-0) 

However, the protocol defines `TOKEN_ID_SUI` as `0`. [2](#0-1) 

When `_transferTokensFromVault` is called, it retrieves the token address from the config using the `tokenID`. [3](#0-2) 

If `tokenID` 0 is used (which is the legitimate ID for SUI in the bridge protocol), and the `supportedTokens` mapping for index 0 is either uninitialized or the initialization logic fails to account for the 0-index correctly (similar to the `vaultId == 0` check in the seed report), the bridge will revert with "Unsupported token". While `BridgeConfig.sol` initializes tokens via a loop, any logic elsewhere in the system that treats `tokenID == 0` as a sentinel for "uninitialized" or "invalid" (as seen in the `migratePartnerVault` analog) will break the functionality for the SUI token.

### Impact Explanation
The SUI token (ID 0) is a primary asset for the bridge. If the first token index is treated as invalid due to the 0-index sentinel pattern, users will be unable to bridge SUI between Ethereum and Sui. This constitutes a permanent denial of service for the bridge's native asset, meeting the High impact criteria for "harmful smart-contract behavior" and "fund lock" (as tokens sent to the vault would be un-claimable if the configuration check fails).

### Likelihood Explanation
The likelihood is high because the protocol explicitly assigns SUI to ID 0. Standard Solidity patterns often use 0 as a "null" or "invalid" state for IDs and indices. The `isTokenSupported` check specifically relies on the mapping value at the given ID. If the initialization logic or any subsequent governance action treats ID 0 as a special "unrecognized" value (mirroring the `UnrecognizedVault` error in the seed report), the vulnerability will be triggered.

### Recommendation
Avoid using `0` as both a valid ID and a sentinel value. Either:
1. Initialize the bridge with a dummy token at ID 0 (similar to the suggested mitigation in the seed report).
2. Use a separate boolean mapping `mapping(uint8 => bool) public isSupported` to track token status instead of relying on the `address(0)` check.
3. Explicitly allow `tokenID 0` in all validation logic.

### Proof of Concept
1. Deploy `BridgeConfig` and initialize it with a list of tokens where SUI is the first entry (`_tokenIds[0] = 0`).
2. Call `isTokenSupported(0)`. If the mapping `supportedTokens[0]` was not correctly set during initialization due to a loop starting at 1 or a check like `require(_tokenIds[i] != 0)`, it returns `false`.
3. Even if initialized, if a function like `migrateToken` (analogous to `migratePartnerVault`) were added using the logic `if (config.tokenID(token) == 0) revert UnrecognizedToken()`, it would fail for SUI.
4. In `SuiBridge.sol`, the call to `_transferTokensFromVault(..., 0, ...)` will revert at line 253 because it interprets the valid SUI ID 0 as an unsupported token. [3](#0-2)

### Citations

**File:** bridge/evm/contracts/BridgeConfig.sol (L93-95)
```text
    function isTokenSupported(uint8 tokenID) public view override returns (bool) {
        return supportedTokens[tokenID].tokenAddress != address(0);
    }
```

**File:** crates/sui-types/src/bridge.rs (L66-66)
```rust
pub const TOKEN_ID_SUI: u8 = 0;
```

**File:** bridge/evm/contracts/SuiBridge.sol (L250-253)
```text
        address tokenAddress = committee.config().tokenAddressOf(tokenID);

        // Check that the token address is supported
        require(tokenAddress != address(0), "SuiBridge: Unsupported token");
```
