Looking at the external report's vulnerability class — **missing minimum/protection parameter validation** (passing `0` as a minimum amount to a critical operation, bypassing slippage protection) — I need to find an analog where a critical protection parameter is unvalidated in the threshold-signatures codebase.

Let me examine the key validation paths across all protocol entry points.