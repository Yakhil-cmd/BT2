# Q4784: `BUNDLE_GEMFILE` env-key injection via a `machine.environment` entry in the fork branch's `shipit.yml` reaches a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies`

## Question
Can an unprivileged fork PR author set `BUNDLE_GEMFILE` through a `machine.environment` entry in the fork branch's `shipit.yml`, which `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch, so when Shipit runs a `ruby`/`bundle` dependency step in `TaskCommands#install_dependencies` the value points bundler at an attacker Gemfile whose evaluated code runs, achieving code execution on the deploy host?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack provisioning -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: the env KEY `BUNDLE_GEMFILE` and its value via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `Command#unbundled_env` merges attacker-controlled keys with no allowlist over BASE_ENV, then the ruby toolchain honours loader variables in the inherited env; `BUNDLE_GEMFILE` points bundler at an attacker Gemfile whose evaluated code runs
- Invariant to test: The set of keys in the environment hash passed to PTY.spawn is restricted to the deploy spec's machine_env and declared VariableDefinition names.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build a ReviewStack/task whose env contains `BUNDLE_GEMFILE`, assert `Command#unbundled_env` includes it and that `interpolated_arguments`/PTY.spawn would inherit it.
