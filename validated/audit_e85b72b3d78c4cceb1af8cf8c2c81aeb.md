Looking at the vulnerability class — **missing access control modifier on a privileged function** — I need to find ZKsync OS functions that should restrict callers but don't.

Let me trace the full access control pattern across all system hooks.