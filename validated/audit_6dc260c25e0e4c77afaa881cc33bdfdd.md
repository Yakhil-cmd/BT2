### Title
`/commit` command grants unrestricted `Bash(git add:*)` with no secret-file exclusion logic, contradicting README's documented "avoids committing files with secrets" claim - (File: plugins/commit-commands/commands/commit.md)

### Summary
The `/commit` slash command's frontmatter grants the model unrestricted `Bash(git add:*)`, and the task body contains no instruction whatsoever to exclude secret-bearing files (`.env`, `credentials.json`, etc.) from staging. This contradicts the plugin's own `README.md`, which advertises "Avoids committing files with secrets" as a feature, meaning the claimed protection does not exist at the tool-permission layer or at the prompt-instruction layer for this command.

### Finding Description
The `commit.md` frontmatter declares `allowed-tools: Bash(git add:*), Bash(git status:*), Bash(git commit:*)` [1](#0-0) , which is an unrestricted wildcard permitting the model to `git add` any path in the working tree. The task instructions only say to inspect `git status`/`git diff`/`git log` context and then "Stage and create the commit using a single message" [2](#0-1)  — there is no mention of secrets, `.env`, `credentials.json`, or any exclusion logic anywhere in the command file. Meanwhile, `plugins/commit-commands/README.md` explicitly lists "Avoids committing files with secrets (.env, credentials.json)" as a feature of `/commit` [3](#0-2) . Since the enforcement mechanism the README describes does not exist in the actual command's tool-allowlist or prompt text, if a secret-bearing file is present as an untracked/unstaged change in the working tree when `git status` is captured as context, nothing in the command prevents the model from including that path in its `git add` invocation and subsequently `git commit`, persisting the secret into git history (and potentially pushing it publicly via the companion `/commit-push-pr` command).

### Impact Explanation
If a `.env`/credentials file is left in the working tree (e.g., in a shared dev checkout, CI runner, or a workspace where a PR/branch checkout drops such a file) and `/commit` is invoked, the unrestricted `git add:*` allowlist combined with the absence of any secret-exclusion instruction means the resulting commit can capture and persist that secret into git history — a "secret disclosure" class impact, especially severe if followed by `/commit-push-pr`, which pushes the branch and opens a PR (potentially to a shared/public remote) [4](#0-3) .

### Likelihood Explanation
This requires a secret-bearing file to exist in the working tree as an uncommitted change at the time `/commit` is invoked — a realistic but not universal precondition (e.g., a `.env` not covered by `.gitignore`, or a file introduced by a branch/PR checkout). Because the only "protection" advertised is a documentation claim with zero corresponding enforcement in the actual command frontmatter or prompt body, this is not a bypass of an existing control — no control exists to bypass. The behavior is fully deterministic and reproducible on any repo where such a file is untracked/unstaged.

### Recommendation
Either (a) remove the misleading "Avoids committing files with secrets" claim from `README.md` until real enforcement exists, or (b) implement actual enforcement: add explicit instructions in `commit.md` directing the model to inspect `git status` output and refuse to `git add` any path matching common secret patterns (`.env*`, `*credentials*`, `*.pem`, `*secret*`, etc.), and/or scope the `Bash(git add:*)` allowlist more narrowly (e.g., requiring explicit per-file `git add <path>` rather than a wildcard that also implicitly permits `git add -A`/`git add .`), and add a pre-commit hook-level secret scan rather than relying purely on prompt instruction.

### Proof of Concept
Integration test plan:
1. Initialize a temp git repo; create a tracked source file with a legitimate change and an untracked `.env` file containing a dummy secret (`API_KEY=dummy123`).
2. Run `git status` to confirm `.env` appears as an untracked file.
3. Invoke the `/commit` command's underlying instructions (via a harness that feeds the `commit.md` prompt/context to the model or a stub emulating its tool calls).
4. Assert that the resulting `Bash(git add ...)` tool-call arguments never include `.env`, and that after `Bash(git commit ...)`, `git show --stat HEAD` does not include `.env`.
5. Expected current behavior (failing/vulnerable): because `commit.md` contains no secret-exclusion instruction and `allowed-tools` permits unrestricted `git add:*`, no mechanism blocks staging `.env`, so the test should fail — demonstrating the gap between the README's documented safeguard and actual enforcement.

### Citations

**File:** plugins/commit-commands/commands/commit.md (L1-4)
```markdown
---
allowed-tools: Bash(git add:*), Bash(git status:*), Bash(git commit:*)
description: Create a git commit
---
```

**File:** plugins/commit-commands/commands/commit.md (L13-18)
```markdown
## Your task

Based on the above changes, create a single git commit.

You have the capability to call multiple tools in a single response. Stage and create the commit using a single message. Do not use any other tools or do anything else. Do not send any other text or messages besides these tool calls.
```

**File:** plugins/commit-commands/README.md (L41-45)
```markdown
**Features:**
- Automatically drafts commit messages that match your repo's style
- Follows conventional commit practices
- Avoids committing files with secrets (.env, credentials.json)
- Includes Claude Code attribution in commit message
```

**File:** plugins/commit-commands/README.md (L47-56)
```markdown
### `/commit-push-pr`

Complete workflow command that commits, pushes, and creates a pull request in one step.

**What it does:**
1. Creates a new branch (if currently on main)
2. Stages and commits changes with an appropriate message
3. Pushes the branch to origin
4. Creates a pull request using `gh pr create`
5. Provides the PR URL
```
