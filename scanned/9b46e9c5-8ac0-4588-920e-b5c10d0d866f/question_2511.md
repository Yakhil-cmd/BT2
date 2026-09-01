# Q2511: `GIT_TEMPLATE_DIR` in a shell-interpreted `shipit.yml` step on a allow_all review stack

## Question
When a review stack provisioned by an unprivileged PR under `allow_all` runs a shell-interpreted `shipit.yml` step, can an attacker-set `GIT_TEMPLATE_DIR` (via label or fork shipit.yml) achieve execution because `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: env key `GIT_TEMPLATE_DIR` under provisioning_behavior `allow_all`, executed via a shell-interpreted `shipit.yml` step
- Exploit idea: `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell; `GIT_TEMPLATE_DIR` supplies a template dir whose hooks are copied into and run on the next `git clone`; no key allowlist exists in Command#unbundled_env
- Invariant to test: No fork-controllable environment key alters any interpreter/tool the deploy spawns.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: assemble the allow_all review-stack task, inject `GIT_TEMPLATE_DIR`, assert it reaches the spawned shell-interpreted env.
