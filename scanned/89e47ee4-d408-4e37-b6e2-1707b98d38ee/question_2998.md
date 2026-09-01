# Q2998: [allow_all] `PYTHONSTARTUP` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `tasks.<name>.steps` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `PYTHONSTARTUP` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `tasks.<name>.steps` section the deploy process names a python file executed at interpreter start?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `PYTHONSTARTUP` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `tasks.<name>.steps` section of the fork shipit.yml under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `tasks.<name>.steps` step inherits `PYTHONSTARTUP` from Command#unbundled_env and names a python file executed at interpreter start
- Invariant to test: The `tasks.<name>.steps` step inherits no fork-controllable key such as `PYTHONSTARTUP`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `tasks.<name>.steps` step, inject `PYTHONSTARTUP` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
