Q4543: hook-order hole in pool-parameter validation when the packed bin arrays sit near the documented 128-entry safety boundary

Question
Can an unprivileged attacker enter through `metric-core/contracts/MetricOmmPoolFactory.sol::createPool` with repeated public pool-creation attempts that reuse salts, tokens, or provider identities while the packed bin arrays sit near the documented 128-entry safety boundary, so that an extension set looks enabled but a reachable order gap or duplicate causes a required hook not to run along `createPool -> _validatePoolParameters -> deploy-time state binding`, corrupting the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions? Any validation gap here lets a fully public caller mint a pool shape the rest of the system later trusts as safe. Deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path.

Target
- File/function: metric-core/contracts/MetricOmmPoolFactory.sol::_validatePoolParameters
- Entrypoint: metric-core/contracts/MetricOmmPoolFactory.sol::createPool
- Attacker controls: repeated public pool-creation attempts that reuse salts, tokens, or provider identities
- Exploit idea: Reach `createPool -> _validatePoolParameters -> deploy-time state binding` in a live public flow and show that deploy a pool whose extensions initialize successfully while one protection is skipped, shadowed, or reordered on the real swap path. The exact value at risk is the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Invariant to test: Every configured hook must execute exactly as declared and in the validated order on live user flows. The concrete assertion should cover the legitimacy of admin values, fee caps, token pair ordering, provider tokens, and pool setup assumptions.
- Expected Immunefi impact: High direct loss if an allowlist or oracle guard silently fails open on a production pool.
- Fast validation: Generate malformed but standard-ERC20 pool configs and assert every one that would later break swap/liquidity safety is rejected before deployment.
