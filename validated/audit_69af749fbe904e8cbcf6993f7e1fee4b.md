Looking at the external bug class — **missing state-flag check before a critical operation** — I need to find an analog in Cronos where a state that is supposed to gate bridge/conversion operations is never checked, allowing an unprivileged user to continue operating even after an admin attempts to halt them.

Let me examine the bridge control surface and conversion entry points.