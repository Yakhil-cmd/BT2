### Title
`Shipit::EnvironmentVariables#permit` allows operator-supplied deploy `env` values to override `GIT_ASKPASS`/`GITHUB_TOKEN` because `TaskCommands#env` merges `@task.env` last - ([File: lib/shipit/task_commands.rb], [File: lib/shipit/commands.rb], [File: lib/shipit/environment_variables.rb])

### Summary
`EnvironmentVariables#permit` (`sanitize_env_vars`) only checks that a supplied env key's **name** appears in `variable_definitions.map(&:name)`; it never excludes security-relevant reserved names such as `GIT_ASKPASS` or `GITHUB_TOKEN`. Since `TaskCommands#env` merges `@task.env` (the whitelisted, operator/attacker-influenced hash) **last**, any declared `deploy.variables` entry named `GIT_ASKPASS` overrides the Shipit-controlled askpash script path set in `Commands#base_env`.

### Finding Description
The broken binding: a key `k` accepted by `EnvironmentVariables#permit` because `k ∈ variable_definitions.map(&:name)` is assumed to be independent of/never able to override `base_env['GIT_ASKPASS']` and `base_env['GITHUB_TOKEN']` — but no such independence is enforced.

Code path:
- `Commands#base_env` sets `env['GITHUB_TOKEN'] = github.token` and, when `Shipit.use_git_askpash?`, `env['GIT_ASKPASS'] = <path to lib/snippets/git-askpass>` [1](#0-0) .
- `TaskCommands#env` starts from `super` (i.e., `base_env`, containing `GIT_ASKPASS`/`GITHUB_TOKEN`), then merges `@stack.env`, then a hardcoded hash (`SHIPIT_USER`, `TASK_ID`, etc.), then `deploy_spec.machine_env`, and finally merges `@task.env` **last** [2](#0-1) .
- `DeployCommands#env` calls `super` (the above) and only adds `SHA`/`REVISION`/`DIFF_LINK` afterward — it does not re-protect `GIT_ASKPASS`/`GITHUB_TOKEN` [3](#0-2) .
- `@task.env` is populated from the deploy's whitelisted `env`, filtered via `EnvironmentVariables#permit`, which only checks `variable_definitions.map(&:name).include?(k)` — no denylist of reserved/internal keys (`GIT_ASKPASS`, `GITHUB_TOKEN`, `TASK_ID`, `SHIPIT_USER`, etc.) exists [4](#0-3) .

Because the merge order places `@task.env` last, and `permit` has no reserved-name exclusion, an attacker who can get a `shipit.yml` change merged (`deploy.variables: [{name: 'GIT_ASKPASS'}]`) and who can trigger/influence the operator-submitted deploy `env` (e.g. `GIT_ASKPASS=/tmp/evil`) can have that value survive the entire merge chain and reach `Command`/`PTY.spawn`, replacing the git credential-helper script used for git operations.

### Impact Explanation
If `Shipit.use_git_askpath?` is enabled, the deploy host will invoke the attacker-controlled path as the askpash program during git network operations, i.e., arbitrary code execution on the deploy host under the Shipit worker's privileges (Critical: RCE on the deploy host via `Command`/`PTY.spawn`). This also generalizes to `GITHUB_TOKEN`, allowing exfiltration/substitution of the app's GitHub token used for git/API operations for that stack. The blast radius is scoped to the stack whose `shipit.yml` was modified and where an operator triggers a deploy supplying the matching `env` key — it is repeatable for every deploy on that stack.

### Likelihood Explanation
This requires: (1) an attacker gets a PR merged (or, if `shipit.yml` is read from the branch being deployed without merge-gating, simply opens a PR/pushes a branch) declaring `deploy.variables` with a reserved name; and (2) an operator (or automation) supplies a matching `env` value when triggering the deploy via the UI/API. The second precondition — an operator knowingly/unknowingly supplying `env['GIT_ASKPASS']=...` — is a meaningful barrier since it requires an operator action; this is not a fully attacker-only path but a two-party trigger. I was not able to fully confirm within this session whether `shipit.yml`'s `deploy.variables` is read from an unreviewed branch (e.g., in review-stack/PR-based deploys) or only from a trusted/protected branch — this materially affects whether the attacker alone can satisfy precondition (1). Given the code confirms the core merge-order/whitelist flaw regardless of that nuance, and no denylist exists in `EnvironmentVariables#permit`, this is a real bug in this engine's code.

### Recommendation
In `Shipit::EnvironmentVariables#permit`/`sanitize_env_vars`, reject variable definitions or supplied env keys that collide with reserved/internal names (`GIT_ASKPASS`, `GITHUB_TOKEN`, `GITHUB_DOMAIN`, `TASK_ID`, `SHIPIT_USER`, `SHIPIT_LINK`, `EMAIL`, `IGNORED_SAFETIES`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, `SHA`, `REVISION`, `DIFF_LINK`, `BUNDLE_PATH`). Alternatively/additionally, in `TaskCommands#env`/`DeployCommands#env`, merge `@task.env` before the hardcoded/security-critical keys (or re-apply `base_env`'s `GIT_ASKPASS`/`GITHUB_TOKEN` after merging `@task.env`) so operator/PR-declared variables can never shadow Shipit-controlled credentials.

### Proof of Concept
```ruby
# test/unit/deploy_commands_test.rb (conceptual addition)
test "task-declared env cannot override GIT_ASKPASS" do
  Shipit.stubs(:use_git_askpass?).returns(true)
  stack = shipit_stacks(:shipit)
  deploy_spec = stack.deploy_spec
  deploy_spec.stubs(:deploy_variables).returns(
    [Shipit::DeploySpec::VariableDefinition.new('name' => 'GIT_ASKPASS')]
  )
  deploy = stack.trigger_deploy(shipit_commits(:second), shipit_users(:walrus),
                                env: { 'GIT_ASKPASS' => '/tmp/evil' })
  commands = Shipit::DeployCommands.new(deploy)

  expected_askpass = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
  assert_equal expected_askpass, commands.env['GIT_ASKPASS']
  refute_equal '/tmp/evil', commands.env['GIT_ASKPASS']
end
```
This test currently fails (asserts the vulnerable behavior), demonstrating that `commands.env['GIT_ASKPASS']` equals the attacker-supplied `/tmp/evil` rather than the Shipit-controlled snippet path, confirming the binding is broken.

### Citations

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

**File:** lib/shipit/deploy_commands.rb (L9-16)
```ruby
    def env
      commit = @task.until_commit
      super.merge(
        'SHA' => commit.sha,
        'REVISION' => commit.sha,
        'DIFF_LINK' => diff_url
      )
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
