# Q3173: [allow_all] `PROMPT_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `provision.handler_name` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `PROMPT_COMMAND` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `provision.handler_name` section the deploy process names a command bash runs before each prompt in an interactive-ish step?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `PROMPT_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `provision.handler_name` section of the fork shipit.yml under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `provision.handler_name` step inherits `PROMPT_COMMAND` from Command#unbundled_env and names a command bash runs before each prompt in an interactive-ish step
- Invariant to test: The `provision.handler_name` step inherits no fork-controllable key such as `PROMPT_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `provision.handler_name` step, inject `PROMPT_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
