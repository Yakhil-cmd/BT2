### Title
`provision?` operator-precedence bug lets label-based branches bypass `review_stacks_enabled` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` intends "no stack shall ever be created unless `review_stacks_enabled` is true," but Ruby's `&&`/`||` precedence only applies `review_stacks_enabled` to the `allow_all` branch. When a repository is configured with `provisioning_behavior_allow_with_label` or `provisioning_behavior_prevent_with_label`, an opened pull request satisfying the label condition triggers stack creation even while `review_stacks_enabled` is `false`.

### Finding Description
Intended binding: `provision? == true` should require `repository.review_stacks_enabled == true` for every behavior, i.e. `review_stacks_enabled && (allow_all? || (allow_with_label? && label) || (prevent_with_label? && !label))`.

Actual code: [1](#0-0) 

Because `&&` binds tighter than `||`, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && label_present?) || (prevent_with_label? && !label_present?)`

`review_stacks_enabled` only gates the first disjunct. If the repository owner has `review_stacks_enabled = false` but `provisioning_behavior` set to `allow_with_label` (with the label present) or `prevent_with_label` (with the label absent), `provision?` still returns `true`.

`respond_to_pull_request_opened?` then permits `process` to call: [2](#0-1) 

`ReviewStackAdapter#create!` builds the stack via the passed-in `scope`, i.e. `repository.review_stacks` (repository A's own association), using the PR's head ref and PR number as attributes: [3](#0-2) 

The stack is enqueued via `ReviewStackProvisioningQueue.add`, and eventually `stack.provisioner.provision?` / `stack.provision` runs a task whose `TaskCommands#env` merges `@stack.env` and other secrets tied to `@stack.repository` (repository A) and whose GitHub App credentials are resolved via `Shipit.github(organization: @stack.repository.owner)`: [4](#0-3) [5](#0-4) 

Because `Repository.from_github_repo_name` correctly resolves to repository A from `params.repository.full_name`, `repository.review_stacks_enabled` is correctly read as `false`, yet the buggy `||` chain still lets provisioning proceed. This confirms the equality the question describes: the resolved repository is correct, but the enable/disable flag is not honored for the label-conditioned behaviors — a genuine logic defect in this engine's own code, not a webhook-forgery or authentication issue.

I was not able to fully trace `Commands`' base `env`/`unbundled_env` implementation in this session to confirm the exact key name `GITHUB_TOKEN` is present in the merged environment (that class lives outside the files inspected here), so that specific detail should be verified separately, but the broader claim — that a task belonging to repository A's stack executes with repository A's GitHub App credentials while running attacker-supplied `shipit.yml` steps from a PR the owner intended to block via `review_stacks_enabled = false` — is supported directly by the code above.

### Impact Explanation
Once a repository is in this state (`review_stacks_enabled: false`, `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`), any external contributor who opens a matching pull request causes Shipit to create a `ReviewStack` scoped to that repository and run its deploy pipeline (`install_dependencies`/`perform`) with that repository's environment and GitHub App credentials, executing commands defined by the attacker's own `shipit.yml`/branch content. This is repeatable per PR/label combination and is confined to the misconfigured repository, but for that repository it results in credential exposure/misuse matching the "exfiltration of deploy-time secrets" Critical category.

### Likelihood Explanation
This requires a specific repository configuration precondition: `review_stacks_enabled = false` combined with `provisioning_behavior` set to a label-based mode (not the default `allow_all`+enabled combo most repos would use). This is a plausible operational state (e.g., an owner toggling off review stacks without resetting the behavior dropdown) but is not attacker-controlled directly — the attacker only supplies the PR/label. Given that precondition, exploitation is trivial and repeatable (no secrets, sessions, or signatures needed by the attacker).

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates all three behaviors:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
Minitest plan (extends `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` patterns already present):
```ruby
test "does not create stacks when review_stacks_enabled is false, even with allow_with_label + matching label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end

test "does not create stacks when review_stacks_enabled is false, even with prevent_with_label + no label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Both assertions currently fail against the unpatched code (a `Shipit::Stack`/`ReviewStack` is created despite `review_stacks_enabled == false`), demonstrating the binding `repository.review_stacks_enabled == false ⇒ provision? == false` is violated.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
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

**File:** lib/shipit/task_commands.rb (L100-104)
```ruby
    private

    def github
      Shipit.github(organization: @stack.repository.owner)
    end
```
