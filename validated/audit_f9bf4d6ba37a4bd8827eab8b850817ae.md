### Title
Webhook signature verification is bound to the attacker-supplied `repository.owner.login`, not the target `Commit`'s owning org, allowing cross-tenant forged commit statuses - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/secret to validate the HMAC against using `repository_owner`, a value taken verbatim from the JSON body the attacker controls. `StatusHandler#process` then looks up the target `Commit` purely `by sha`, with no relationship at all to the organization that was actually used to verify the signature, so a signature that is valid (or trivially bypassed) for one org can write a `Status` onto a commit belonging to a completely different, unrelated org/stack.

### Finding Description
The broken binding is: **verifying org (`params.dig('repository','owner','login')`) must equal owning org of the mutated `Commit` row**. These are never checked against each other.

- `WebhooksController#verify_signature` computes `repository_owner` from the attacker-controlled payload and calls `Shipit.github(organization: repository_owner)` to obtain the `GitHubApp` used to verify the HMAC: [1](#0-0) , with `repository_owner` defined as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the resolved app has no `webhook_secret` configured: `return true unless webhook_secret` [3](#0-2) . Multiple documented/sample configs show orgs configured with `webhook_secret: # nil` [4](#0-3) .
- Once past `verify_signature`, `WebhooksController#create` dispatches the raw parsed body to handlers with no re-check of ownership: [5](#0-4) .
- `StatusHandler#process` resolves the target purely by `sha`, globally across the entire `commits` table, independent of any organization/repository scoping: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [6](#0-5) . Note the handler's declared params schema never even requires/uses `repository.full_name` [7](#0-6) .
- `Commit#create_status_from_github!` unconditionally records the attacker-supplied state/description/target_url/context via `Status.replicate_from_github!` [8](#0-7) [9](#0-8) .

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: status`, body `{"repository":{"owner":{"login":"org-with-no-secret"}}, "sha":"<real sha belonging to org-with-secret/private-repo>", "state":"success", ...}`. `repository_owner` resolves to `org-with-no-secret`; `Shipit.github(organization: 'org-with-no-secret')` returns a `GitHubApp` with `webhook_secret` unset, so `verify_webhook_signature` short-circuits `true` for any signature header value (even garbage). `StatusHandler` then finds the real `Commit` row for the given `sha` — which belongs to a totally different, secured org — and writes a forged `Status` on it.

Existing guards fail because: `drop_unhandled_event` only checks the event type is handled, not provenance; the `head(422)` path only triggers for an unconfigured/unknown org, not for a mismatch between verifying org and the commit's actual org; `ExplicitParameters` schema in `StatusHandler` validates types/presence of `sha`/`state`/etc. but has no cross-check against `repository.full_name` or the commit's stack/repository owner.

### Impact Explanation
An attacker who knows (or guesses) a valid commit SHA for any tracked repository can forge arbitrary CI status states (`success`, `failure`, etc.) with attacker-chosen `description`/`target_url`/`context` on that commit, as long as any org exists in `Shipit.github_apps` configuration without a `webhook_secret` (or whose secret the attacker can otherwise satisfy) — regardless of whether that org has anything to do with the target repository. This is a cross-tenant write: a payload naming one repository/org mutates state belonging to a different repository/org's commit and stack, directly matching the "Critical - payload for one repository mutating another's commit" category. A forged `success` status can unblock merge/deploy gates (`Commit#deployable?` / `blocked?` depend on status state) [10](#0-9) , and status transitions can also trigger `ProcessMergeRequestsJob` [11](#0-10) . The attack is repeatable against any known SHA and any misconfigured/unconfigured org name in the deployment's config.

### Likelihood Explanation
Preconditions: the Shipit deployment must have at least one org configured in `Shipit.github_apps`/`secrets.github` with no `webhook_secret` (shown as a valid/expected configuration shape in the shipped sample configs), and the attacker must know a valid commit SHA belonging to any tracked stack (commit SHAs are frequently public/derivable from public repos, PRs, or leaked via UI). No secrets, sessions, or tokens are required from the attacker; a single unauthenticated HTTP POST suffices. This is fully feasible and repeatable with zero privileges.

### Recommendation
Bind the verified organization to the record being mutated: after determining `repository_owner` and its `GitHubApp`, ensure the target `Commit`(s) resolved in `StatusHandler` (and other handlers matching by `sha` alone) belong to a `Stack`/`Repository` whose `owner` matches the verified `repository_owner` (or `repository.full_name`) before calling `create_status_from_github!`. Reject/skip commits whose repository does not match the payload's `repository.full_name`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status forges a status on a commit belonging to a different, unrelated org" do
  # commit belongs to stack owned by 'org-with-secret' in fixtures
  commit = shipit_commits(:first)
  refute_equal 'org-with-no-secret', commit.stack.repository.owner

  Shipit.stubs(:github_app_config).with('org-with-no-secret').returns({}) # no webhook_secret key
  request.headers['X-Github-Event'] = 'status'

  body = {
    'sha' => commit.sha,
    'state' => 'success',
    'description' => 'forged',
    'target_url' => 'https://evil.example.com',
    'context' => 'attacker/ci',
    'repository' => { 'owner' => { 'login' => 'org-with-no-secret' }, 'full_name' => 'org-with-no-secret/unrelated-repo' }
  }.to_json

  assert_difference 'commit.statuses.count', 1 do
    post :create, body:, as: :json
  end
  assert_response :ok
  assert_equal 'success', commit.statuses.last.state
  assert_equal 'forged', commit.statuses.last.description
end
```
This demonstrates: verifying org = `org-with-no-secret` ≠ owning org of mutated commit (`commit.stack.repository.owner`), yet `Commit#create_status_from_github!` is invoked and the write succeeds.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L219-229)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L23-34)
```ruby
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
```

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
