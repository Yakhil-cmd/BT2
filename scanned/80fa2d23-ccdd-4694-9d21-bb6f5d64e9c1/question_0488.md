# Q0488: `PROMPT_COMMAND` in a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` on a prevent_with_label review stack

## Question
When a review stack provisioned by an unprivileged PR under `prevent_with_label` runs a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`, can an attacker-set `PROMPT_COMMAND` (via label or fork shipit.yml) achieve execution because the ruby toolchain honours loader variables in the inherited env?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: env key `PROMPT_COMMAND` under provisioning_behavior `prevent_with_label`, executed via a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`
- Exploit idea: the ruby toolchain honours loader variables in the inherited env; `PROMPT_COMMAND` names a command bash runs before each prompt in an interactive-ish step; no key allowlist exists in Command#unbundled_env
- Invariant to test: No fork-controllable environment key alters any interpreter/tool the deploy spawns.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: assemble the prevent_with_label review-stack task, inject `PROMPT_COMMAND`, assert it reaches the spawned `ruby`/`bundle` env.
