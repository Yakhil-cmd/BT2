# Q3711: [allow_all] `GEM_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `dependencies.override` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `GEM_PATH` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `dependencies.override` section the deploy process adds an attacker gem path consulted by `require`/`bundle`?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `GEM_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `dependencies.override` section of the fork shipit.yml under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `dependencies.override` step inherits `GEM_PATH` from Command#unbundled_env and adds an attacker gem path consulted by `require`/`bundle`
- Invariant to test: The `dependencies.override` step inherits no fork-controllable key such as `GEM_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `dependencies.override` step, inject `GEM_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
