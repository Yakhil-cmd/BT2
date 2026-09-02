This confirms the vulnerability: `StatusHandler#process` at [1](#0-0)  directly creates a `Status` (state, description, context) on an existing `Commit` matched purely by `sha` from the attacker-supplied payload, with no cross-check against the organization used for signature verification, and CI status directly drives merge-queue eligibility via `ProcessMergeRequestsJob`.

### Title
Webhook signature verification uses an attacker-chosen organization while the payload's `repository.full_name`/`sha` determine what is actually written, allowing forged CI status/push events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to validate the HMAC signature against by reading `repository.owner.login` (falling back to `organization.login`) straight out of the **unverified** JSON body [2](#0-1) [3](#0-2) . The organization used to authenticate the request is never checked against the organization/repository that the payload actually causes Shipit to act on.

### Finding Description
In a multi-organization Shipit deployment (`config/secrets.yml` keyed by organization, as documented and exercised in `test/dummy/config/secrets_double_github_app.yml`), `Shipit.github(organization:)` resolves a distinct `GitHubApp` per organization, each with its own optional `webhook_secret` [4](#0-3) . Critically, `GitHubApp#verify_webhook_signature` treats an unset secret as automatically valid: `return true unless webhook_secret` [5](#0-4) .

Because `repository_owner` (used solely to pick the verification key) is read from the same untrusted JSON body that is later handed unmodified to the event handlers, an attacker can:
1. Set `repository.owner.login` (or `organization.login`) to the name of *any* configured organization that has no `webhook_secret` set (a common/documented configuration option), so `verify_signature` accepts the request without a valid signature.
2. Simultaneously craft the rest of the payload — e.g. `repository.full_name` and `sha` — to reference a *different*, victim organization's repository/commit.

`WebhooksController#create` then dispatches the full, unmodified payload to handlers [6](#0-5) , which resolve the target purely from `payload.dig('repository', 'full_name')` [7](#0-6)  — with no re-validation that this repository belongs to the organization that was actually used to authenticate. This breaks the intended binding: `organization authenticated == organization/repository written`.

The most damaging handler is `StatusHandler`, which takes `sha`, `state`, `description`, `context` directly from the attacker payload and writes a `Status` on any existing commit matching that `sha`, regardless of stack/org: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [1](#0-0) . A forged "success" status can satisfy `ci.require` gating and enqueue `ProcessMergeRequestsJob`, feeding the merge queue as shown by `#add_status schedule a MergeMergeRequests job` test behavior [8](#0-7) . `PushHandler` similarly resolves the target stack purely by `repository.full_name`/`branch` from the payload and triggers `stack.sync_github` [9](#0-8) .

### Impact Explanation
An unauthenticated, unprivileged network attacker who has learned (from public documentation/config templates, e.g. `docs/setup.md`, or observed 422 error/log leakage of `repository_owner`) the name of *any* organization configured in the Shipit instance with no `webhook_secret` set can forge webhook events attributed to a *different* organization's repositories/stacks that they do not control. This can:
- Force-inject a fabricated "success" CI status onto an arbitrary commit SHA, enabling it to bypass `ci.require` checks and be picked up by the merge queue (`ProcessMergeRequestsJob`) — an unauthorized merge path.
- Trigger spurious `GithubSyncJob`s on unrelated stacks via forged `push` events.

This satisfies the "unauthorized merge" / cross-repository-write category of Critical/High impact defined in scope.

### Likelihood Explanation
The `/webhooks` endpoint is unauthenticated by design (it's meant to be called by GitHub) and reachable without any Shipit session, `ApiClient` token, or GitHub write access — the only prerequisite is that the operator has configured at least one organization without a `webhook_secret`, which is an explicitly supported and documented configuration (`webhook_secret: # nil` appears in `docs/setup.md`, `config/secrets.development.example.yml`, and `test/dummy/config/secrets_double_github_app.yml`). This is not a hypothetical multi-tenant edge case — it is the codebase's own documented and tested multi-org configuration shape.

### Recommendation
After selecting the `GitHubApp`/`webhook_secret` to verify against using `repository_owner`, re-validate that the organization actually owning the payload's `repository.full_name` (the value handlers will act on) matches the organization used for verification, and reject the request if they differ. Alternatively, require every configured organization in a multi-org setup to have a non-blank `webhook_secret`, and/or resolve the verification key from the target `Stack`/`Repository`'s already-known, trusted organization rather than from attacker-supplied payload fields.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `TrustedVictimOrg` (has `webhook_secret` set, owns `victim/app`) and `OpenOrg` (no `webhook_secret` configured), per the multi-org schema in `docs/setup.md`.
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OpenOrg" }, "full_name": "TrustedVictimOrg/victim-app" }
}
```
No `X-Hub-Signature` header (or any bogus value) is required.
3. `verify_signature` resolves `Shipit.github(organization: "OpenOrg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally [10](#0-9) .
4. `create` dispatches the payload to `StatusHandler`, which finds the commit by `sha` in `TrustedVictimOrg/victim-app` (regardless of which org "authenticated") and records a forged `success` status [1](#0-0) , potentially unblocking the merge queue for that commit.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
