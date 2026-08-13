# Q3797: Hookify hook executor fail open import error via main

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `main` via `UserPromptSubmit hook on new prompt` and control hook JSON delivered through a normal PreToolUse, PostToolUse, Stop, or UserPromptSubmit event so that the codebase induce an import or parse error that causes the hook to print a message but still allow the protected operation, breaking the invariant that event classification must map every dangerous tool to the intended rule set and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/hookify/hooks/userpromptsubmit.py` / `main`
- Entrypoint: `UserPromptSubmit hook on new prompt`
- Attacker controls: hook JSON delivered through a normal PreToolUse, PostToolUse, Stop, or UserPromptSubmit event
- Exploit idea: Drive `UserPromptSubmit hook on new prompt` with attacker-controlled hook JSON delivered through a normal PreToolUse, PostToolUse, Stop, or UserPromptSubmit event and test whether `main` changes security behavior in a way that induce an import or parse error that causes the hook to print a message but still allow the protected operation.
- Invariant to test: event classification must map every dangerous tool to the intended rule set
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: run the hook entrypoint with crafted but normal-looking hook JSON and assert errors do not silently downgrade a deny to allow
