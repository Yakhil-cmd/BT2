### Title
`filter_deploy_envs` fails to reserve credential-carrying env names, letting a `deploy.variables` entry named `GITHUB_TOKEN`/`GIT_ASKPASS` be attacker-controlled at deploy time - (File: app/models/shipit/deploy_spec.rb)

### Summary
`DeploySpec#filter_deploy_envs` whitelists env var names purely by string match against `deploy_variables` parsed from the current `shipit.yml`, with no reserved-name exclusion list. Because `TaskCommands#env` merges the (permitted) task-supplied env **last**, over the real `GITHUB_TOKEN`/`GIT_ASKPASS` set by `Commands#base_env`, declaring one of those names as a `deploy.variables` entry lets any deploy trigger supply an arbitrary value that overrides Shipit's real git credential for that stack's git operations.

### Finding Description
Broken binding: "an env key permitted by `filter_deploy_envs` == a key that is safe for a caller to fully control the value of" is violated whenever `deploy.variables` contains `name: GITHUB_TOKEN` or `name: GIT_ASKPASS`.

Code path:
1. `DeploySpec#deploy_variables` (app/models/shipit/deploy_spec.rb:120-122) builds `VariableDefinition`s straight from `config('deploy', 'variables')`, i.e. the `shipit.yml` on the deployed branch/commit — no filtering of reserved names.
2. `DeploySpec#filter_deploy_envs` (app/models/shipit/deploy_spec.rb:174-176) calls `EnvironmentVariables.with(env).permit(deploy_variables)`.
3. `EnvironmentVariables#sanitize_env_vars` (lib/shipit/environment_variables.rb:35-44) only checks `allowed_variables.include?(k)` — it validates **names**, never values, and has no reserved/deny list for credential keys.
4. `Stack#filter_deploy_envs` is invoked when a `Deploy` is created from caller-supplied `env` params (deploys/API controllers), and the sanitized result is persisted as the task's `env`.
5. At execution time, `TaskCommands#env` (lib/shipit/task_commands.rb:33-48) computes: `super.merge(@stack.env).merge({...}).merge(deploy_spec.machine_env).merge(@task.env)`. `super` (from `Commands#base_env`, lib/shipit/commands.rb:37-50) sets the real `GITHUB_TOKEN` and, if enabled, `GIT_ASKPASS` (pointing at `lib/snippets/git-askpass`, which reads `GITHUB_TOKEN` as the git password). `@task.env` — the attacker-influenced, "permitted" hash — is merged **last**, so it wins.

If a `shipit.yml` change (merged onto the stack's deployed branch) adds:
```yaml
deploy:
  variables:
    - name: GIT_ASKPASS
```
then a subsequent deploy trigger with `env: {"GIT_ASKPASS" => "/tmp/attacker-script"}` passes `filter_deploy_envs` (the name is whitelisted) and ends up as `@task.env['GIT_ASKPASS']`, which overrides the legitimate `GIT_ASKPASS`/effectively substitutes the git credential helper used by `git` invocations for that stack's checkout/fetch/push, all executed via `Command`/`PTY.spawn`.

None of the existing guards catch this: `EnvironmentVariables#permit` only diffs names against the whitelist (test/unit/environment_variables_test.rb:20-23 confirms value-agnostic behavior); there is no `Shipit`-level reserved-word list (`GITHUB_TOKEN`, `GIT_ASKPASS`, `GITHUB_DOMAIN`, etc.) enforced anywhere in `DeploySpec`, `VariableDefinition`, or `EnvironmentVariables`.

### Impact Explanation
An attacker who can get such a `shipit.yml` change merged onto a stack's deployed branch, and who can trigger a deploy/rollback/task with a caller-controlled `env` param, can substitute the git credential (`GIT_ASKPASS` script or, if a plain env credential path is used, `GITHUB_TOKEN` itself) used for that stack's git operations. This can redirect authentication material or execute an attacker-supplied script during git operations that Shipit spawns via `Command`, i.e., command execution on the deploy host with attacker-controlled input in the credential-helper flow — matching the Critical categories "RCE on the deploy host via `Command`/`PTY.spawn`" and "exfiltration of `GITHUB_TOKEN`" / "unauthorized deploy". Blast radius is scoped to the single stack whose `shipit.yml` was modified; it is repeatable on every deploy of that stack once the config is merged.

### Likelihood Explanation
This requires two preconditions: (1) a `shipit.yml` change declaring `GITHUB_TOKEN` or `GIT_ASKPASS` as a `deploy.variables` name lands on the branch that gets deployed, and (2) the attacker (or anyone) can then trigger a deploy/rollback with a controlled `env` value for that key via the standard deploy/API endpoints. Precondition (1) normally requires the change to be merged — via a maintainer's review or Shipit's own PR auto-merge feature if branch protections are permissive — which is a meaningful barrier but is not enforced or defended against anywhere in this engine's code (no reserved-name check exists to stop it even if merged by a well-intentioned maintainer who didn't realize the implication). Precondition (2) is trivially satisfiable by any user who can trigger a deploy on that stack (a normal, low-privilege Shipit action). The root cause — absence of a reserved/deny list for credential env names in `DeploySpec`/`EnvironmentVariables` — is unconditional and configuration-independent.

### Recommendation
Add a hard-coded reserved-name deny list (e.g., `GITHUB_TOKEN`, `GIT_ASKPASS`, `GITHUB_DOMAIN`, and any other keys set in `Commands#base_env`/`TaskCommands#env`) that `DeploySpec#deploy_variables`/`rollback_variables`/`TaskDefinition#variables` reject at parse time, and/or have `EnvironmentVariables#permit` raise if `variable_definitions` include any reserved name. Additionally, change the merge order in `TaskCommands#env` and `DeployCommands#env` so that the real credential-setting `base_env` values cannot be overridden by `@task.env`/`@stack.env` (e.g., re-merge `base_env`'s reserved keys last, or `except` reserved keys from `@task.env` before merging).

### Proof of Concept
In `test/models/deploy_spec_test.rb` (or `test/unit/environment_variables_test.rb`):
```ruby
test "filter_deploy_envs must not permit reserved credential keys even if declared" do
  spec = DeploySpec.new(
    'deploy' => { 'variables' => [{ 'name' => 'GIT_ASKPASS' }] }
  )
  assert_raises(EnvironmentVariables::NotPermitted) do
    spec.filter_deploy_envs('GIT_ASKPASS' => '/tmp/attacker-script')
  end
end
```
Currently this assertion fails (no exception raised — `{"GIT_ASKPASS" => "/tmp/attacker-script"}` is returned), demonstrating the broken binding. A second test can show the override reaching `Command`:
```ruby
test "attacker-controlled GIT_ASKPASS overrides the real one in TaskCommands#env" do
  # given a Task whose env == {'GIT_ASKPASS' => '/tmp/attacker-script'} (as persisted after filter_deploy_envs)
  commands = Shipit::TaskCommands.new(task)
  refute_equal Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').to_s, commands.env['GIT_ASKPASS']
  assert_equal '/tmp/attacker-script', commands.env['GIT_ASKPASS']
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** app/models/shipit/deploy_spec.rb (L120-126)
```ruby
    def deploy_variables
      Array.wrap(config('deploy', 'variables')).map(&VariableDefinition.method(:new))
    end

    def default_deploy_env
      deploy_variables.map { |v| [v.name, v.default] }.to_h
    end
```

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```

**File:** lib/shipit/environment_variables.rb (L35-44)
```ruby
    def sanitize_env_vars(variable_definitions)
      allowed_variables = variable_definitions.map(&:name)

      allowed, disallowed = @env.partition { |k, _| allowed_variables.include?(k) }.map(&:to_h)

      error_message = "Variables #{disallowed.keys.to_sentence} have not been whitelisted"
      raise NotPermitted, error_message unless disallowed.empty?

      allowed
    end
```

**File:** lib/shipit/commands.rb (L37-50)
```ruby
    def base_env
      @base_env ||= begin
        env = Shipit.env.merge(
          'GITHUB_DOMAIN' => github.domain,
          'GITHUB_TOKEN' => github.token
        )

        if Shipit.use_git_askpass?
          env['GIT_ASKPASS'] = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
        end

        env
      end
    end
```

**File:** lib/shipit/task_commands.rb (L33-48)
```ruby
    def env
      super
        .merge(@stack.env)
        .merge(
          'SHIPIT_USER' => "#{@task.author.login} (#{normalized_author_name}) via Shipit",
          'EMAIL' => @task.author.email,
          'BUNDLE_PATH' => Rails.root.join('data', 'bundler').to_s,
          'SHIPIT_LINK' => @task.permalink,
          'TASK_ID' => @task.id.to_s,
          'IGNORED_SAFETIES' => @task.ignored_safeties? ? '1' : '0',
          'GIT_COMMITTER_NAME' => @task.user&.name || Shipit.committer_name,
          'GIT_COMMITTER_EMAIL' => @task.user&.email || Shipit.committer_email
        )
        .merge(deploy_spec.machine_env)
        .merge(@task.env)
    end
```

**File:** lib/snippets/git-askpass (L1-16)
```text
#!/bin/sh

GITHUB_USER="${GITHUB_USER:-git}"
GITHUB_DOMAIN="${GITHUB_DOMAIN:-github.com}"

if [ "${1}" = "Username for 'https://${GITHUB_DOMAIN}': " ]; then
  echo "${GITHUB_USER}"
  exit 0
fi

if [ "${1}" = "Password for 'https://${GITHUB_USER}@${GITHUB_DOMAIN}': " ]; then
  echo "${GITHUB_TOKEN}"
  exit 0
fi

exit 1
```

**File:** app/models/shipit/deploy.rb (L64-65)
```ruby
    delegate :broadcast_update, :filter_deploy_envs, to: :stack

```

**File:** app/models/shipit/variable_definition.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  class VariableDefinition
    attr_reader :name, :title, :default, :select

    def initialize(attributes)
      @name = attributes.fetch('name')
      @title = attributes['title']
      @default = attributes['default'].to_s
      @default_provided = attributes.key?('default')
      @select = attributes['select'].presence
    end

    def default_provided?
      @default_provided
    end
```
