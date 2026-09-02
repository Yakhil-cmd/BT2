This confirms the vulnerability. `StatusHandler#process` queries `Commit.where(sha: params.sha)` globally across the entire database, unlike every other handler (`PushHandler`, `CheckSuiteHandler`) which scope through `stacks` (derived from `Repository.from_github_repo_name(repository_name)`) before touching any commit record.

## Title
Cross-tenant status webhook forgery via unscoped SHA lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by SHA alone (`Commit.where(sha: params.sha)`), with no check that the webhook's `repository.full_name` matches the `Repository` that owns the target `Commit`'s `Stack`. In a Shipit instance configured for multiple GitHub organizations, a webhook correctly signed for attacker-owned org can create a `success` `Status` on a commit belonging to a completely different, victim-owned stack, as long as the SHA is shared or known/guessed (trivial when repos share history via forks, or the SHA is public GitHub information). This flips `Commit#deployable?` to true and lets `Stack#trigger_continuous_delivery` deploy a commit that never had CI run against the victim's own repository/stack.

### Finding Description
The broken binding: `Status#stack_id` (and by extension the org that authenticated the webhook) must equal `commit.stack.repository`'s owning org — i.e. `webhook_repository_owner == commit.stack.repository.owner`. This equality is never checked.

Path:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only checks that the signature is valid *for the organization named in the payload's own `repository.owner.login`* via `Shipit.github(organization: repository_owner)`. It says nothing about which `Commit`/`Stack` the payload's `sha` maps to.
2. `Shipit::Webhooks.for_event('status')` dispatches to `Handlers::StatusHandler` (`app/models/shipit/webhooks.rb:19`).
3. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This is a **global**, cross-tenant lookup — it never uses the base `Handler#stacks` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) that scopes by `repository_name` (`Repository.from_github_repo_name(repository_name)&.stacks`), unlike `PushHandler#process` (`stacks.not_archived.where(branch:)...`) and `CheckSuiteHandler#process` (`stacks.where(branch: ...)`), both of which correctly scope through `stacks` before touching commit records.
4. `Commit#create_status_from_github!` → `Status.replicate_from_github!` (`app/models/shipit/status.rb:24-33`) creates a `Status` row using `stack_id: commit.stack_id` — the **victim's** stack id — regardless of which org's webhook secret signed the request.
5. `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) becomes `true` once `success?` flips and `blocked?` is false, and `Status#schedule_continuous_delivery` (`app/models/shipit/status.rb:19,42-44`) fires continuous delivery for the victim's stack.

Attacker's exact request: attacker is a legitimate tenant of the same multi-tenant Shipit instance (has their own org/app configured under `Shipit.github` per `docs/setup.md:182-209`, so they can produce a validly-signed `X-Hub-Signature` for their own org). They send `POST /webhooks` with header `X-Github-Event: status`, `repository.owner.login` = their own org (passes `verify_signature`), and body `{"sha": "<victim commit sha>", "state": "success", ...}`. Because `StatusHandler` never checks that the `sha` belongs to a commit in a stack whose repository matches the webhook's own `repository.full_name`, any commit anywhere in the Shipit installation sharing that SHA gets a forged `success` status attributed to the attacker's CI.

Existing guards do not catch this: `verify_signature` validates the org that signed the webhook, not the org that owns the target commit; `ExplicitParameters` only validates types/shape of `sha`/`state`, not ownership; there is no `Repository`/`Stack` scoping anywhere in `StatusHandler`.

### Impact Explanation
An attacker who is any tenant on a shared/multi-org Shipit instance can forge a `success` CI status on **any other tenant's** commit merely by knowing/guessing its SHA (often public via GitHub), causing `Commit#deployable?` to become true and an unauthorized deploy (`Stack#trigger_continuous_delivery`) to be scheduled for a commit that never passed the victim's actual CI pipeline. This is a cross-repo/cross-tenant mutation of another party's stack/commit state leading to an unauthorized deploy — Critical severity per the given rubric. It's repeatable against any commit/stack in the installation and requires no privilege beyond being one authenticated (but unrelated) tenant.

### Likelihood Explanation
Requires: (a) the Shipit instance configured with multiple GitHub orgs (`Shipit.github` multi-org schema, `docs/setup.md:182-209`), i.e. attacker's own org is a legitimate, separately-configured tenant with its own webhook secret; (b) `continuous_delivery` enabled and `ignore_ci?` false on the victim stack (per question's preconditions); (c) attacker knows or can predict the target commit's SHA (trivially available for public repos, or via fork relationships that share commit history). Attacker cost is one signed HTTP POST from their own legitimately configured GitHub org/app — no secrets belonging to the victim are needed. Fully repeatable against arbitrary victim stacks/commits sharing SHAs.

### Recommendation
In `StatusHandler#process`, scope the commit lookup through the webhook's own repository, mirroring `PushHandler`/`CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This enforces `commit.stack.repository == Repository.from_github_repo_name(payload.repository.full_name)` before any `Status` is created, closing the cross-tenant forgery path.

### Proof of Concept
minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or extending `test/controllers/webhooks_controller_test.rb`):
```ruby
test "status webhook from one org cannot create a status for another org's commit with the same sha" do
  victim_stack = shipit_stacks(:shipit)          # owned by org "shopify"
  attacker_repo_full_name = "attacker-org/attacker-repo"
  shared_sha = victim_stack.commits.last.sha

  # Attacker's own repo/org is legitimately configured in Shipit as a separate tenant,
  # so their webhook signature verifies successfully against their own org's secret.
  request.headers['X-Github-Event'] = 'status'
  body = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => attacker_repo_full_name, 'owner' => { 'login' => 'attacker-org' } }
  }.to_json

  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  commit = victim_stack.commits.find_by(sha: shared_sha)
  refute commit.deployable?, "precondition: commit should not be deployable before forged status"

  assert_no_difference -> { commit.statuses.count } do
    post :create, body:, as: :json
  end

  refute commit.reload.deployable?, "commit must not become deployable via a status forged from an unrelated repository"
end
```
Assert on both sides of the equality: before the fix, `commit.statuses.count` increases and `commit.reload.deployable?` becomes `true` despite `attacker_repo_full_name != victim_stack.repository.full_name`; after applying the recommended fix, the webhook is dropped for that commit because `stacks` (scoped to `attacker-org/attacker-repo`) does not include `victim_stack`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
