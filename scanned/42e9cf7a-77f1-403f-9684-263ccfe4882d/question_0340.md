# Q0340: [allow_all] `RUBYLIB` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `fetch` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `RUBYLIB` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `fetch` section the deploy process prepends an attacker load path so `require` in a ruby step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `RUBYLIB` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `fetch` section of the fork shipit.yml under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `fetch` step inherits `RUBYLIB` from Command#unbundled_env and prepends an attacker load path so `require` in a ruby step loads attacker code
- Invariant to test: The `fetch` step inherits no fork-controllable key such as `RUBYLIB`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `fetch` step, inject `RUBYLIB` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
