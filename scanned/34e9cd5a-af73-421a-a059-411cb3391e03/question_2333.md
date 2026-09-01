# Q2333: [allow_all] `RUBYOPT` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `fetch` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `RUBYOPT` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `fetch` section the deploy process injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `RUBYOPT` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `fetch` section of the fork shipit.yml under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `fetch` step inherits `RUBYOPT` from Command#unbundled_env and injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup
- Invariant to test: The `fetch` step inherits no fork-controllable key such as `RUBYOPT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `fetch` step, inject `RUBYOPT` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
