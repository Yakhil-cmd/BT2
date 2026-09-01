# Q2208: `RUBYLIB` in a shell-interpreted `shipit.yml` step on a allow_with_label review stack

## Question
When a review stack provisioned by an unprivileged PR under `allow_with_label` runs a shell-interpreted `shipit.yml` step, can an attacker-set `RUBYLIB` (via label or fork shipit.yml) achieve execution because `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: env key `RUBYLIB` under provisioning_behavior `allow_with_label`, executed via a shell-interpreted `shipit.yml` step
- Exploit idea: `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell; `RUBYLIB` prepends an attacker load path so `require` in a ruby step loads attacker code; no key allowlist exists in Command#unbundled_env
- Invariant to test: No fork-controllable environment key alters any interpreter/tool the deploy spawns.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: assemble the allow_with_label review-stack task, inject `RUBYLIB`, assert it reaches the spawned shell-interpreted env.
