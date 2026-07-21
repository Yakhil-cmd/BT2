Looking at the external report's core invariant: **when a fallback path is taken (swap fails), the fallback bypasses a constraint (slippage/minOutputAmount) that the primary path would have enforced**. I need to find an analog where a fallback/skip path in the Sequencer bypasses a constraint that the primary path enforces.

Let me trace the gateway stateful validation path carefully.