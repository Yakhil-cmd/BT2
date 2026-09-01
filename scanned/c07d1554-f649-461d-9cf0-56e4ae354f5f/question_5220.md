# Q5220: `PYTHONSTARTUP` in a `git` invocation in `StackCommands#fetch`/`#git_clone` on a allow_with_label review stack

## Question
When a review stack provisioned by an unprivileged PR under `allow_with_label` runs a `git` invocation in `StackCommands#fetch`/`#git_clone`, can an attacker-set `PYTHONSTARTUP` (via label or fork shipit.yml) achieve execution because the git subprocess inherits the merged env and honours attacker-set git variables?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: env key `PYTHONSTARTUP` under provisioning_behavior `allow_with_label`, executed via a `git` invocation in `StackCommands#fetch`/`#git_clone`
- Exploit idea: the git subprocess inherits the merged env and honours attacker-set git variables; `PYTHONSTARTUP` names a python file executed at interpreter start; no key allowlist exists in Command#unbundled_env
- Invariant to test: No fork-controllable environment key alters any interpreter/tool the deploy spawns.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: assemble the allow_with_label review-stack task, inject `PYTHONSTARTUP`, assert it reaches the spawned `git` env.
