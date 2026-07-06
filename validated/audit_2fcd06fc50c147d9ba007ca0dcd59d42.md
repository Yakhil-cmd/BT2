Looking at the external report's vulnerability class — **accounting state updated without a corresponding asset transfer, gated by a boolean flag** — I need to find an analog in the Starknet Staking codebase where a flag bypasses an actual state-changing operation but still updates accounting.

Let me trace the relevant code paths.