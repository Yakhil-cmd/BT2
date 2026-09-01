# Q4579: `DYLD_INSERT_LIBRARIES` env-key injection via a `machine.environment` entry in the fork branch's `shipit.yml` reaches a shell-interpreted `shipit.yml` step

## Question
Can an unprivileged fork PR author set `DYLD_INSERT_LIBRARIES` through a `machine.environment` entry in the fork branch's `shipit.yml`, which `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch, so when Shipit runs a shell-interpreted `shipit.yml` step the value preloads an attacker dylib on macOS deploy hosts, achieving code execution on the deploy host?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack provisioning -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: the env KEY `DYLD_INSERT_LIBRARIES` and its value via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `Command#unbundled_env` merges attacker-controlled keys with no allowlist over BASE_ENV, then `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell; `DYLD_INSERT_LIBRARIES` preloads an attacker dylib on macOS deploy hosts
- Invariant to test: The set of keys in the environment hash passed to PTY.spawn is restricted to the deploy spec's machine_env and declared VariableDefinition names.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build a ReviewStack/task whose env contains `DYLD_INSERT_LIBRARIES`, assert `Command#unbundled_env` includes it and that `interpolated_arguments`/PTY.spawn would inherit it.
