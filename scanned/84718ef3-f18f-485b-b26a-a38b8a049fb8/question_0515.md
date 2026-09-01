# Q0515: `RUBYOPT` in a shell-interpreted `shipit.yml` step on a allow_all review stack

## Question
When a review stack provisioned by an unprivileged PR under `allow_all` runs a shell-interpreted `shipit.yml` step, can an attacker-set `RUBYOPT` (via label or fork shipit.yml) achieve execution because `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: env key `RUBYOPT` under provisioning_behavior `allow_all`, executed via a shell-interpreted `shipit.yml` step
- Exploit idea: `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell; `RUBYOPT` injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup; no key allowlist exists in Command#unbundled_env
- Invariant to test: No fork-controllable environment key alters any interpreter/tool the deploy spawns.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: assemble the allow_all review-stack task, inject `RUBYOPT`, assert it reaches the spawned shell-interpreted env.
