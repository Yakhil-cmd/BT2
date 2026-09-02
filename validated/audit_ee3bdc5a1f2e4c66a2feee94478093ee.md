### Title
`OpenedHandler#provision?` operator-precedence bug allows Review Stack provisioning on `review_stacks_enabled=false` repositories, leading to RCE via attacker-controlled `shipit.yml` - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`OpenedHandler#provision?` only gates the `allow_all` provisioning behavior on `repository.review_stacks_enabled`; the `allow_with_label` and `prevent_with_label` branches are evaluated independently due to Ruby operator precedence, so an attacker who opens a labeled pull request against a repository with `review_stacks_enabled=false` (but `provisioning_behavior` set to `allow_with_label`/`prevent_with_label`) can still trigger creation of a `ReviewStack`. Once a `ReviewStack` exists for the attacker's fork branch, deploy/task execution reads `shipit.yml` from that branch's checkout and can define arbitrary shell steps executed via `Command`/`PTY.spawn`.

### Finding Description
Broken binding: the intended invariant is `stack_creation_allowed == repository.review_stacks_enabled AND (behavior-specific rule)`. The actual code in `provision?` is: [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && label_present?) || (prevent_with_label? && !label_present?)`

Only the first disjunct checks `review_stacks_enabled`. If an operator sets `provisioning_behavior` to `allow_with_label` or `prevent_with_label` while leaving (or later setting) `review_stacks_enabled` to `false` — e.g., via the settings form at [2](#0-1)  where the checkbox and select are independent fields — `provision?` still returns `true` for a labeled/unlabeled PR, regardless of the disabled flag.

Call sequence:
1. Attacker opens a PR from their fork (`pull_request.opened` webhook, `POST /webhooks`), optionally adding a label they control on their own PR.
2. `OpenedHandler#process` → `respond_to_pull_request_opened?` → `provision?` returns `true` due to the precedence bug [3](#0-2) .
3. `ReviewStackAdapter#find_or_create!` creates a `ReviewStack` bound to the attacker's fork ref/branch.
4. On task execution, `TaskCommands#deploy_spec` builds `DeploySpec::FileSystem.new(@task.working_directory, @stack)` [4](#0-3) .
5. `DeploySpec::FileSystem#load_config` resolves `config_file_path` by walking `shipit_file_names_in_priority_order` and returning the first existing file inside the checked-out working directory [5](#0-4) . Since the working directory is a checkout of the attacker's branch, the attacker's own `shipit.yml`/`.shipit/shipit.yml` is read.
6. `TaskCommands#steps` returns `@task.definition.steps`, derived from that config's `deploy.override`/`tasks` entries [6](#0-5) .
7. `TaskCommands#perform` wraps each step in `Command.new(command_line, env:, chdir: steps_directory)` [7](#0-6) , which is ultimately executed via `PTY.spawn` (in `TaskExecutionStrategy::Default#capture!`/`Command#start`, not shown here but corroborated by the call chain in the task description).

Existing guards do not prevent this: `respond_to_label_change?` in `LabeledHandler`/`UnlabeledHandler` correctly `&&`s `review_stacks_enabled` against the entire archive/unarchive check [8](#0-7) , showing the correct pattern that `OpenedHandler#provision?` (and identically `ReopenedHandler#unarchive?` at [9](#0-8) ) fails to follow. No webhook signature check, `ExplicitParameters` schema, or model validation constrains `provisioning_behavior` to only take effect when `review_stacks_enabled` is true — `Repository` validations only cover `name`/`owner` format [10](#0-9) .

### Impact Explanation
On an affected repository, an unauthenticated/unprivileged GitHub user (fork owner) can force creation of a `ReviewStack` that Shipit will check out and execute deploy/task steps for. Since the shell steps come entirely from the attacker's own `shipit.yml` in their fork branch, this yields arbitrary command execution on the Shipit deploy host (`Command`/`PTY.spawn`), matching the Critical/RCE category. Blast radius is scoped to repositories whose operator has set `provisioning_behavior` to `allow_with_label`/`prevent_with_label` while `review_stacks_enabled` is `false` — this is a plausible misconfiguration since the two fields are set independently in the settings UI, with no validation tying them together.

### Likelihood Explanation
Preconditions: a repository must have `review_stacks_enabled=false` and `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (a non-default but reachable configuration state, as both fields are independently settable via `RepositoriesController#update` / the settings form). The attacker needs only the ability to open a PR (and, for `allow_with_label`, apply their own label to their own PR) — no Shipit credentials or GitHub team membership required. This is fully repeatable against any repository in this specific misconfigured state.

### Recommendation
Fix the operator precedence in `provision?` (and the identical bug in `ReopenedHandler#unarchive?`) so `review_stacks_enabled` gates all three provisioning-behavior branches, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
Minitest in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not create stacks for repos with review_stacks_enabled=false even with allow_with_label + matching label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # review_stacks_enabled = false
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
With the current code, this test fails (a stack is created) because `provision?` returns `true` despite `review_stacks_enabled == false`, demonstrating the equality `stack_created == review_stacks_enabled` is violated. After the fix, the assertion passes.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/views/shipit/repositories/settings.html.erb (L10-41)
```erb
      <%= form_for @repository do |f| %>
        <div class="field-wrapper">
          <%= f.check_box :review_stacks_enabled %>
          <%= f.label :review_stacks_enabled, "Dynamically provision stacks for Pull Requests?" %>
        </div>

        <div class="field-wrapper">
          <p>
            <%= f.label :provisioning_behavior, "Provisioning behavior", aria: { describedby: 'provisioningBehaviorHelp' } %>
            <%= f.select :provisioning_behavior, Shipit::Repository.provisioning_behaviors.map { |key, value| [ key.titleize, key] } %>
          </p>
          <p>
            <small class="form-text text-muted" id="provisioningBehaviorHelp">
              When "Allow All", the provisioning label has no effect on dynamic stack provisioning - ALL Pull Requests dynamically provision stacks.
            </small>
          </p>
          <p>
            <small class="form-text text-muted">
              When "Allow With Label", dynamic provisioning occurs ONLY for Pull Requests whose labels include the 'Provisioning Label'.
            </small>
          </p>
          <p>
            <small class="form-text text-muted">
              When "Prevent With Label", dynamic provisioning will occur for every Pull Request EXCEPT those whose labels include the 'Provisioning Label'.
            </small>
          </p>
        </div>

        <div class="field-wrapper">
          <%= f.label :provisioning_label_name, "Provisioning label" %>
          <%= f.text_field :provisioning_label_name %>
        </div>
```

**File:** lib/shipit/task_commands.rb (L13-15)
```ruby
    def deploy_spec
      @deploy_spec ||= DeploySpec::FileSystem.new(@task.working_directory, @stack)
    end
```

**File:** lib/shipit/task_commands.rb (L23-27)
```ruby
    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end
```

**File:** lib/shipit/task_commands.rb (L29-31)
```ruby
    def steps
      @task.definition.steps
    end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L98-142)
```ruby
      def load_config
        return if config_file_path.nil?

        if !Shipit.respect_bare_shipit_file? && config_file_path.to_s.end_with?(*bare_shipit_filenames)
          return { 'deploy' => { 'pre' => [shipit_not_obeying_bare_file_echo_command, 'exit 1'] } }
        end

        config_obj = read_config(config_file_path)
        build_config(config_file_path, config_obj)
      end

      YAML_EXTENSIONS = ["yml", "yaml"].freeze

      def shipit_file_names_in_priority_order
        YAML_EXTENSIONS.flat_map do |ext|
          [
            "#{app_name}.#{@env}.#{ext}",
            ".shipit/#{app_name}.#{@env}.#{ext}",

            "#{app_name}.#{ext}",
            ".shipit/#{app_name}.#{ext}",

            "shipit.#{@env}.#{ext}",
            ".shipit/#{@env}.#{ext}",

            "shipit.#{ext}",
            ".shipit/shipit.#{ext}"
          ]
        end.uniq
      end

      def bare_shipit_filenames
        YAML_EXTENSIONS.flat_map do |ext|
          ["#{app_name}.#{ext}", "shipit.#{ext}", ".shipit/#{app_name}.#{ext}", ".shipit/shipit.#{ext}"]
        end.uniq
      end

      def config_file_path
        shipit_file_names_in_priority_order.each do |filename|
          path = file(filename, root: true)
          return path if path.exist?
        end

        nil
      end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/repository.rb (L41-45)
```ruby
    validates :name, uniqueness: { scope: %i[owner], case_sensitive: false,
                                   message: 'cannot be used more than once' }
    validates :owner, :name, presence: true, ascii_only: true
    validates :owner, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: OWNER_MAX_SIZE }
    validates :name, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: NAME_MAX_SIZE }
```
