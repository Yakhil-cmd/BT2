# Q0707: `GEM_PATH` in a `git` invocation in `StackCommands#fetch`/`#git_clone` on a allow_all review stack

## Question
When a review stack provisioned by an unprivileged PR under `allow_all` runs a `git` invocation in `StackCommands#fetch`/`#git_clone`, can an attacker-set `GEM_PATH` (via label or fork shipit.yml) achieve execution because the git subprocess inherits the merged env and honours attacker-set git variables?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: env key `GEM_PATH` under provisioning_behavior `allow_all`, executed via a `git` invocation in `StackCommands#fetch`/`#git_clone`
- Exploit idea: the git subprocess inherits the merged env and honours attacker-set git variables; `GEM_PATH` adds an attacker gem path consulted by `require`/`bundle`; no key allowlist exists in Command#unbundled_env
- Invariant to test: No fork-controllable environment key alters any interpreter/tool the deploy spawns.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: assemble the allow_all review-stack task, inject `GEM_PATH`, assert it reaches the spawned `git` env.
