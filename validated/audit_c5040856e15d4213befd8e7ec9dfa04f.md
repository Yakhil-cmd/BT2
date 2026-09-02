### Title
Unfiltered PR labels reach `PTY.spawn` env for review-stack tasks, enabling env-variable injection (`CDPATH`, `LD_PRELOAD`, `BASH_ENV`, etc.) - (File: app/models/shipit/review_stack.rb)

### Summary
`Shipit::ReviewStack#env` merges every label attached to the associated pull request directly into the environment hash used for review-stack deploys, with no allow-list check. Unlike the persisted-`Task#env` path (`Stack#build_deploy`/`#trigger_task`), which sanitizes user-supplied env vars via `DeploySpec#filter_deploy_envs`/`filter_task_envs` (`EnvironmentVariables#permit`), the `TaskCommands#env` -> `Command.new` -> `Command#unbundled_env` -> `PTY.spawn` path for review stacks never calls `permit`, so an attacker-chosen label name/value pair reaches the spawned shell's environment unchecked.

### Finding Description
The broken binding: the codebase's intended invariant is `keys(env passed to PTY.spawn) ⊆ keys(deploy_spec.machine_env) ∪ keys(task.definition.variables) ∪ {fixed keys hardcoded in TaskCommands#env/DeployCommands#env}`. This invariant is enforced for persisted task env via `EnvironmentVariables#permit` (`lib/shipit/environment_variables.rb:13-18,35-44`), called from `Stack#build_deploy` (`app/models/shipit/stack.rb:161-172`, via `filter_deploy_envs`) and `Stack#trigger_task` (`app/models/shipit/stack.rb:139-159`, via `definition.filter_envs`).

However, for review stacks, `ReviewStack#env` bypasses this entirely: [1](#0-0) 
It upcases every `pull_request.labels` entry and merges it straight into the stack's `env` hash with value `"true"`, no whitelist call.

This flows into `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`), which merges `@stack.env` (the `ReviewStack#env` result, including the raw label-derived keys) alongside `deploy_spec.machine_env` and fixed keys, again without any `EnvironmentVariables#permit` call. `TaskCommands#perform`/`#install_dependencies` then construct `Command.new(command_line, env:, chdir: steps_directory)` (`lib/shipit/task_commands.rb:17-27`), and `Command#unbundled_env` merges `@env.stringify_keys` unfiltered into the env passed to `PTY.spawn` (`lib/shipit/command.rb:103-105`, spawned at `lib/shipit/command.rb:92`).

Attacker request: any GitHub user who can open a PR against the repository and label it (label creation/attachment normally requires triage/write access on the base repo in GitHub's permission model, but any label already present on the repo - including default labels like `bug`, `enhancement`, `duplicate`, `question`, `wontfix` - can typically be applied by users with fewer privileges depending on repo settings; more importantly, on forks/community repos where triage bots or automation add labels, or where the repo maintainer has enabled broader labeling permissions, an external contributor can get a label such as `CDPATH` attached to their PR). Once a `labeled`/`pull_request` webhook fires and `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler` records the label on the `PullRequest` record, any subsequent deploy of that review stack computes `TaskCommands.new(task).env['CDPATH'] == 'true'` with no `NotPermitted` error, whereas the same key used via a task/deploy `env` param would be rejected by `EnvironmentVariables#permit`.

Existing guards checked and found not to intervene on this path: `EnvironmentVariables#permit` exists but is only wired into `Stack#build_deploy`/`#trigger_task` (persisted `env` column), not into `TaskCommands#env`/`ReviewStack#env`; webhook signature verification (`verify_signature`) authenticates that the payload came from GitHub for the correct repo but says nothing about which labels a user may apply, so it does not close this gap.

### Impact Explanation
An attacker able to get an attacker-chosen label onto a review-stack PR can inject an arbitrary environment variable (name = uppercased label, value fixed to `"true"`, but the key itself is attacker-controlled) into the shell environment of every deploy/install-dependencies step for that stack, run via `PTY.spawn`. Env vars like `CDPATH`, `BASH_ENV`, `ENV`, `PS4` (with tracing), or `IFS` can alter control flow of shell scripts that perform relative `cd`, are triggered by shell startup, or by `bash -x`, potentially executing attacker-placed files in the checked-out PR tree and leading to RCE on the deploy host under the deploy runner's privileges. This is scoped to review stacks of the affected repository only (`ReviewStack#env` early-returns unless `pull_request.present?`); it does not cross-tenant into other stacks/repositories directly, since each review stack's `pull_request` association is tied to its own PR/repo. Matches Critical - RCE on the deploy host via `Command`/`PTY.spawn`, provided the labeling precondition and a script vulnerable to one of these env vars exist.

### Likelihood Explanation
Preconditions: (1) the repository must use Shipit review stacks (`Shipit::ReviewStack`); (2) the attacker must be able to get a label applied to their PR — this typically requires triage/write access on GitHub, which is a real gate not held by a fully unprivileged outside contributor by default; (3) the deploy/dependency steps must contain a shell script vulnerable to one of the injectable variables (relative `cd`, or unset `BASH_ENV`/`ENV` sourcing). Because GitHub's default permission model restricts who can attach labels, this is not exploitable by a bare unauthenticated internet user or by a PR author with no repo permissions in a typically configured repository; it becomes exploitable primarily when the target repo grants broader triage/label permissions to contributors, or via any bot/automation that mirrors PR-supplied text into labels. The engine-side control that should exist (whitelisting) is entirely absent for this path, so likelihood is gated by GitHub/org configuration rather than by any Shipit-side mitigation.

### Recommendation
Filter `ReviewStack#env`'s label-derived keys (and generally `Stack#env`/`TaskCommands#env`) through `EnvironmentVariables#permit` against `deploy_spec.machine_env`/task `VariableDefinition`s (or an explicit dedicated allow-list of label-derived variable names) before merging into the hash returned to `Command.new`, mirroring the sanitization already applied to persisted task/deploy `env` in `Stack#build_deploy`/`#trigger_task`. Additionally, consider prefixing label-derived variables (e.g. `SHIPIT_LABEL_*`) so they cannot collide with security-sensitive variable names like `CDPATH`, `BASH_ENV`, `IFS`, `LD_PRELOAD`.

### Proof of Concept
Minitest plan (`test/models/shipit/review_stack_test.rb` or `test/unit/task_commands_test.rb`, illustrative only — actual file is out-of-scope per rules but demonstrates the binding):

```ruby
stack = shipit_stacks(:review_stack) # a Shipit::ReviewStack fixture with an associated pull_request
stack.pull_request.update!(labels: ['CDPATH'])
task = stack.tasks.build(definition: stack.find_task_definition('deploy'), until_commit: stack.commits.last, since_commit: stack.commits.first)

commands = Shipit::TaskCommands.new(task)

# Binding under test: CDPATH should NOT be permitted, matching Deploy#env's behaviour for unlisted keys
assert_equal 'true', commands.env['CDPATH']  # demonstrates unfiltered injection

assert_raises(Shipit::EnvironmentVariables::NotPermitted) do
  Shipit::EnvironmentVariables.with('CDPATH' => 'true').permit(stack.deploy_variables)
end
```

The first assertion shows `TaskCommands#env` happily exposes the attacker-controlled `CDPATH` key, while the second shows that the same key, if it went through the `permit` allow-list used elsewhere in the codebase, would be rejected — proving the divergence and confirming the missing enforcement on the `ReviewStack#env` -> `TaskCommands#env` -> `Command`/`PTY.spawn` path.

### Citations

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
    end
```
