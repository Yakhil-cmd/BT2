# Q5425: [allow_with_label] `GIT_ASKPASS` in a shell-interpreted `shipit.yml` step via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_with_label`, when the review stack runs a shell-interpreted `shipit.yml` step, can `GIT_ASKPASS` set through a `machine.environment` entry in the fork branch's `shipit.yml` cause execution because `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell and points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `GIT_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml` under `allow_with_label`, executed via a shell-interpreted `shipit.yml` step
- Exploit idea: `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell; `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `GIT_ASKPASS` points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands
- Invariant to test: No fork-controllable key alters a shell-interpreted `shipit.yml` step.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: inject `GIT_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert it reaches the a shell-interpreted `shipit.yml` step process env.
