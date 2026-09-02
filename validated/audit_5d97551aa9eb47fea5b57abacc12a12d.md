### Title
`machine_env` from an attacker-controlled `shipit.yml` overrides trusted `GIT_ASKPASS`/`GITHUB_TOKEN` in the spawned process environment - ([File: lib/shipit/task_commands.rb])

### Summary
`TaskCommands#env` builds the process environment by starting from `Commands#base_env` (which sets the trusted `GITHUB_TOKEN` and, if enabled, `GIT_ASKPASS`) and then merging `deploy_spec.machine_env`, which is populated directly from the repository's `shipit.yml` `machine.environment` key. Because `Hash#merge` lets the later hash win, a `shipit.yml` committed to a branch/PR that Shipit deploys can set `GIT_ASKPASS` (or `GITHUB_TOKEN`) and have that attacker value flow, unmodified, all the way to `Command#unbundled_env` and `PTY.spawn`.

### Finding Description
The broken binding: the equality Shipit relies on is `env['GIT_ASKPASS'] (in PTY.spawn env) == Commands#base_env['GIT_ASKPASS']` (the trusted askpass script Shipit installs at `lib/snippets/git-askpass`), and likewise for `GITHUB_TOKEN == github.token`. This equality does not hold.

Trace:
- `Commands#base_env` sets the trusted values: `env['GITHUB_TOKEN'] = github.token` and, when `Shipit.use_git_askpass?`, `env['GIT_ASKPASS'] = .../lib/snippets/git-askpass` [1](#0-0) .
- `TaskCommands#env` starts from `super` (i.e. `base_env`) and then chains `.merge(deploy_spec.machine_env).merge(@task.env)` [2](#0-1) .
- `DeploySpec#machine_env` returns `config('machine', 'environment')`, which is read straight from the parsed `shipit.yml` [3](#0-2) .
- `DeploySpec::FileSystem` loads `shipit.yml`/`.shipit/shipit.yml` from the checked-out working directory via `SafeYAML.load` with no schema restriction on which keys `machine.environment` may contain [4](#0-3) .
- `Command#unbundled_env` merges `BASE_ENV` (Bundler-clean env) with `Shipit.shell_paths`/`PATH`, and finally `@env.stringify_keys`, where `@env` is exactly the `TaskCommands#env` hash built above [5](#0-4) . This merged hash is passed directly to `PTY.spawn` in `Command#start` [6](#0-5) .

Because merge order places `deploy_spec.machine_env` after the trusted `base_env` values, any key an attacker names in `machine.environment` (e.g. `GIT_ASKPASS: /path/to/attacker/script` or `GITHUB_TOKEN: <value>`) silently overrides Shipit's own value with no validation, filtering, or key-blocklist anywhere in this chain. `EnvironmentVariables#permit` is used only for `deploy`/`rollback` step variables (`filter_deploy_envs`/`filter_rollback_envs`), not for `machine_env`, so it provides no protection here.

Exploit flow: an attacker who can get a `shipit.yml` deployed (by pushing to a branch that gets deployed, or via a PR that a maintainer merges/deploys, or on any repo they fully control that is registered as a Shipit stack) sets:
```yaml
machine:
  environment:
    GIT_ASKPASS: "/bin/sh -c 'echo $GITHUB_TOKEN > /tmp/exfil; cat /some/real/askpass'"
```
When Shipit runs `git` commands for that task/deploy, `PTY.spawn` executes git with `GIT_ASKPASS` pointing at the attacker's script, which git will invoke and pass the credential prompt to — allowing token exfiltration or arbitrary command execution under the deploy host's git invocation, or substitution of `GITHUB_TOKEN` itself if git/other tooling reads it from env for authentication.

### Impact Explanation
This lets a party who controls (or can get a commit merged/deployed into) a stack's `shipit.yml` cause the deploy host to invoke an attacker-chosen executable as `GIT_ASKPASS` during any git operation for that stack, or to substitute the value of `GITHUB_TOKEN` used by tooling relying on that env var. This can lead to exfiltration of the real `GITHUB_TOKEN`/credentials the Shipit-managed `GitHubApp` injects, or arbitrary script execution during git checkout/fetch under the Shipit process's privileges. Impact is scoped to the repository/stack whose `shipit.yml` is under attacker control — it does not cross-contaminate other stacks' env since `env` is built per-task from that stack's own deploy spec, but within that stack it is a full compromise of the git-credential trust boundary and a Critical-severity command-injection/credential-exfiltration path matching "exfiltration of GITHUB_TOKEN or credential substitution."

### Likelihood Explanation
Precondition: the attacker's `shipit.yml` (with a `machine.environment.GIT_ASKPASS` or `GITHUB_TOKEN` key) must actually be present in the working directory checked out for a task/deploy on a stack Shipit manages. For a repo the attacker fully controls and has registered as a stack (a normal, low-privilege Shipit usage pattern), this is trivial and repeatable on every deploy. For a repo they don't control, they'd need their `shipit.yml` change merged/deployed by a maintainer — feasible via a malicious PR review-checklist bypass or supply-chain style contribution, but requires some cooperation from repository maintainers/CI merge flow. No Shipit secrets, sessions, or privileged roles are needed; only the ability to have `shipit.yml` content land in the deployed working directory.

### Recommendation
In `Commands#base_env` / `TaskCommands#env`, apply the trusted `GITHUB_TOKEN` and `GIT_ASKPASS` (and any other Shipit-managed credential keys) as the last merge (highest precedence) rather than the first, or explicitly re-assert them after merging `deploy_spec.machine_env` and `@task.env`. Additionally, filter `deploy_spec.machine_env`/`@task.env` through an explicit denylist (or the same `EnvironmentVariables#permit` allowlist mechanism used for deploy/rollback variables) to reject reserved credential-related keys (`GIT_ASKPASS`, `GITHUB_TOKEN`, `GITHUB_DOMAIN`, etc.) before merging into the process environment.

### Proof of Concept
In `test/unit/deploy_commands_test.rb` (or a new minitest under `test/`), stub `deploy_spec.machine_env` to return `{'GIT_ASKPASS' => '/tmp/attacker-askpass', 'GITHUB_TOKEN' => 'attacker-token'}`, then:
1. Build `TaskCommands.new(task).env` and assert `env['GIT_ASKPASS'] == '/tmp/attacker-askpass'` and `env['GITHUB_TOKEN'] == 'attacker-token'` (demonstrating the override happens before `Command#unbundled_env`).
2. Construct `Command.new('git', 'status', chdir: ..., env: env)` and assert `command.unbundled_env['GIT_ASKPASS'] == '/tmp/attacker-askpass'`, proving the attacker value — not `Shipit::Engine.root.join('lib','snippets','git-askpass')` — reaches the hash passed to `PTY.spawn`.
3. Compare against the trusted expectation: assert this differs from `Commands.new(stack).send(:base_env)['GIT_ASKPASS']`, establishing the binding violation explicitly.

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

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
    end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L98-107)
```ruby
      def load_config
        return if config_file_path.nil?

        if !Shipit.respect_bare_shipit_file? && config_file_path.to_s.end_with?(*bare_shipit_filenames)
          return { 'deploy' => { 'pre' => [shipit_not_obeying_bare_file_echo_command, 'exit 1'] } }
        end

        config_obj = read_config(config_file_path)
        build_config(config_file_path, config_obj)
      end
```

**File:** lib/shipit/command.rb (L85-101)
```ruby
    def start(&block)
      return if @started

      @control_block = block
      @out = @pid = nil
      FileUtils.mkdir_p(@chdir)
      begin
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
        child_in.close
      rescue Errno::ENOENT
        raise NotFound, "#{Shellwords.split(interpolated_arguments.first).first}: command not found"
      rescue Errno::EACCES
        raise Denied, "#{Shellwords.split(interpolated_arguments.first).first}: Permission denied"
      end
      @started = true
      self
    end
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```
