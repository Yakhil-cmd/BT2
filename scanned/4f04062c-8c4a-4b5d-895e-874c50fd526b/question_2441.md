# Q2441: [allow_all] `BUNDLE_GEMFILE` in a `git` invocation in `StackCommands#fetch`/`#git_clone` via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_all`, when the review stack runs a `git` invocation in `StackCommands#fetch`/`#git_clone`, can `BUNDLE_GEMFILE` set through a `machine.environment` entry in the fork branch's `shipit.yml` cause execution because the git subprocess inherits the merged env and honours attacker-set git variables and points bundler at an attacker Gemfile whose evaluated code runs?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `BUNDLE_GEMFILE` via a `machine.environment` entry in the fork branch's `shipit.yml` under `allow_all`, executed via a `git` invocation in `StackCommands#fetch`/`#git_clone`
- Exploit idea: the git subprocess inherits the merged env and honours attacker-set git variables; `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `BUNDLE_GEMFILE` points bundler at an attacker Gemfile whose evaluated code runs
- Invariant to test: No fork-controllable key alters a `git` invocation in `StackCommands#fetch`/`#git_clone`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: inject `BUNDLE_GEMFILE` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert it reaches the a `git` invocation in `StackCommands#fetch`/`#git_clone` process env.
