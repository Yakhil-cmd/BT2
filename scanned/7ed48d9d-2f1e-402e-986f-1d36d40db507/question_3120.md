# Q3120: `SSH_ASKPASS` env-key injection via a `machine.environment` entry in the fork branch's `shipit.yml` reaches a `git` invocation in `StackCommands#fetch`/`#git_clone`

## Question
Can an unprivileged fork PR author set `SSH_ASKPASS` through a `machine.environment` entry in the fork branch's `shipit.yml`, which `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch, so when Shipit runs a `git` invocation in `StackCommands#fetch`/`#git_clone` the value names a program executed to answer ssh password prompts, achieving code execution on the deploy host?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack provisioning -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: the env KEY `SSH_ASKPASS` and its value via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `Command#unbundled_env` merges attacker-controlled keys with no allowlist over BASE_ENV, then the git subprocess inherits the merged env and honours attacker-set git variables; `SSH_ASKPASS` names a program executed to answer ssh password prompts
- Invariant to test: The set of keys in the environment hash passed to PTY.spawn is restricted to the deploy spec's machine_env and declared VariableDefinition names.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build a ReviewStack/task whose env contains `SSH_ASKPASS`, assert `Command#unbundled_env` includes it and that `interpolated_arguments`/PTY.spawn would inherit it.
