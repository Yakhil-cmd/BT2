# Q3276: `NODE_OPTIONS` in a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` on a allow_all review stack

## Question
When a review stack provisioned by an unprivileged PR under `allow_all` runs a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`, can an attacker-set `NODE_OPTIONS` (via label or fork shipit.yml) achieve execution because the ruby toolchain honours loader variables in the inherited env?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: env key `NODE_OPTIONS` under provisioning_behavior `allow_all`, executed via a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`
- Exploit idea: the ruby toolchain honours loader variables in the inherited env; `NODE_OPTIONS` injects `--require /path/to/evil` so any node step loads attacker code; no key allowlist exists in Command#unbundled_env
- Invariant to test: No fork-controllable environment key alters any interpreter/tool the deploy spawns.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: assemble the allow_all review-stack task, inject `NODE_OPTIONS`, assert it reaches the spawned `ruby`/`bundle` env.
