# Q5510: [allow_all] `GIT_SSH` in a shell-interpreted `shipit.yml` step via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
On provisioning_behavior=`allow_all`, when the review stack runs a shell-interpreted `shipit.yml` step, can `GIT_SSH` set through a `machine.environment` entry in the fork branch's `shipit.yml` cause execution because `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell and names an arbitrary program git executes for ssh transport?

## Target
- File/function: lib/shipit/command.rb + lib/shipit/task_commands.rb + app/models/shipit/review_stack.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start
- Attacker controls: `GIT_SSH` via a `machine.environment` entry in the fork branch's `shipit.yml` under `allow_all`, executed via a shell-interpreted `shipit.yml` step
- Exploit idea: `Command#parse_arguments` keeps the step as one string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell; `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `GIT_SSH` names an arbitrary program git executes for ssh transport
- Invariant to test: No fork-controllable key alters a shell-interpreted `shipit.yml` step.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: inject `GIT_SSH` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert it reaches the a shell-interpreted `shipit.yml` step process env.
