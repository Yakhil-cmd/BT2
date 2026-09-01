# Q5302: `GIT_PROXY_COMMAND` in a shell-interpreted `shipit.yml` step on a prevent_with_label review stack

## Question
When a review stack provisioned by an unprivileged PR under `prevent_with_label` runs a shell-interpreted `shipit.yml` step, can an attacker-set `GIT_PROXY_COMMAND` (via label or fork shipit.yml) achieve execution because `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: env key `GIT_PROXY_COMMAND` under provisioning_behavior `prevent_with_label`, executed via a shell-interpreted `shipit.yml` step
- Exploit idea: `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell; `GIT_PROXY_COMMAND` names an arbitrary command git runs to open transport connections; no key allowlist exists in Command#unbundled_env
- Invariant to test: No fork-controllable environment key alters any interpreter/tool the deploy spawns.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: assemble the prevent_with_label review-stack task, inject `GIT_PROXY_COMMAND`, assert it reaches the spawned shell-interpreted env.
