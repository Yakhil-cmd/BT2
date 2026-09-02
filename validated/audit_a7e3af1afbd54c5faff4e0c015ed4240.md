### Title
Cross-tenant status forgery via unscoped `Commit.where(sha:)` in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using `repository_owner`, which falls back to `params.dig('organization','login')` when `repository` is omitted [1](#0-0) [2](#0-1) . Once the signature is verified against *any* organization's `webhook_secret`, `StatusHandler#process` applies the status to `Commit.where(sha: params.sha)` with no repository or stack scoping whatsoever [3](#0-2) , and `Commit#blocked?` uses that state to gate deploys via `stack.commits.reachable...any?(&:blocking?)` [4](#0-3) .

### Finding Description
The broken binding: the code implicitly assumes `repository_owner` (used to select the verifying `GitHubApp`/secret) `== repository.full_name` (used to scope what gets mutated). In reality `repository_owner` is read from `organization.login` while `StatusHandler` never reads `repository` at all — it only filters by `sha`, a value fully controlled by the attacker.

Path: `WebhooksController#create` parses the JSON body, and `verify_signature` calls `Shipit.github(organization: repository_owner)` to fetch a `GitHubApp` instance and verify the HMAC signature [5](#0-4) . In a multi-tenant/multi-organization config, `Shipit.github` looks up a *per-organization* `webhook_secret` via `github_app_config(organization)` [6](#0-5) [7](#0-6) . Any organization onboarded to the multi-tenant Shipit instance legitimately possesses/knows its own `webhook_secret`. Because `repository_owner` falls back to `organization.login` when `repository` is omitted, an attacker who is a legitimate low-privilege member of Organization A (owning a valid webhook secret for A, but with no access to Stack/repo of victim Organization B) can:
1. Omit `repository` from the payload, or set `organization.login` to their own org "A" while separately setting the handler-irrelevant fields (`sha`, `state`) to reference a commit that also exists (by content-addressed SHA1) in victim B's tracked stack.
2. Sign the request with Org A's own `webhook_secret`, which passes `verify_webhook_signature`.
3. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` — with zero repository/stack filtering [8](#0-7) .
4. If any `Commit` row with that `sha` exists under victim B's stack (trivial when the target repo is public — SHA1 hashes are known from GitHub's public commit history, or from a shared upstream/fork), a forged status is written against B's commit.
5. If B's stack has `blocking_statuses` configured, the forged `failure`/`error` state flips `Commit#blocked?` to true via `blocking?` [9](#0-8) , which is read by `deployable?` to gate deploys [10](#0-9) .

None of the existing guards catch this: `verify_signature` only proves the request was signed by *some* configured organization's secret, not that the payload's actual target repository belongs to that organization; `drop_unhandled_event` and the `ExplicitParameters` schema for `StatusHandler` only validate presence/type of `sha`/`state`, not repository identity; there is no `require_permission!`/`stacks` scoping check in the webhooks pipeline at all.

### Impact Explanation
An attacker who controls (or is a legitimate low-privilege member of) any one organization/tenant configured in a multi-org Shipit deployment can write forged CI status records against commits belonging to a completely different tenant's stack, as long as they can guess/know the target SHA (trivial for public repos). Combined with `blocking_statuses`, this lets the attacker gate/unblock deploys for a stack they have no authorization over — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." This is repeatable per-request against any stack whose commit SHAs are discoverable, and the blast radius spans every stack sharing the multi-org Shipit instance.

### Likelihood Explanation
This requires a **multi-organization** `github` secrets configuration (`Shipit.github_organizations` returning more than one org) — in the common single-org config, `Shipit.github(organization:)` ignores the passed organization and always uses the one global secret [11](#0-10) , so `repository_owner`'s value is irrelevant and this specific divergence has no effect. In the multi-org case, the attacker must possess a genuinely valid `webhook_secret` for at least one configured organization (i.e., be a legitimate but unprivileged tenant), and must know a target `sha` that exists in the victim's `Commit` table (easy for public repos, harder for private ones). Given these preconditions, exploitation cost is a single unauthenticated HTTP POST with a correct HMAC signature computed from the attacker's own known secret.

### Recommendation
Scope `StatusHandler#process` (and other unscoped handlers) to commits belonging to the repository actually indicated by the authenticated organization/secret — e.g., resolve `repository_owner`/`repository.full_name` server-side from the verified GitHub App/organization context and filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository: ... })` instead of a bare `Commit.where(sha:)`. Additionally, `verify_signature` should derive `repository_owner` consistently from the same field the handlers use (`repository.full_name`), and reject events where `repository` is absent for handlers that require repository scoping.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (illustrative, minitest)
test "status event signed with org A's secret must not mutate org B's stack" do
  victim_stack = shipit_stacks(:shipit) # configured with blocking_statuses
  victim_commit = shipit_commits(:first)
  victim_commit.stack.update!(blocking_statuses: ['ci/test'])

  attacker_org = 'attacker-org'
  Shipit.stubs(:github).with(organization: attacker_org).returns(
    Shipit::GitHubApp.new(attacker_org, webhook_secret: 'attacker-known-secret')
  )

  body = {
    'sha' => victim_commit.sha,
    'state' => 'failure',
    'context' => 'ci/test',
    'organization' => { 'login' => attacker_org }
    # no 'repository' key -> repository_owner falls back to organization.login
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', 'attacker-known-secret', body)}"
  request.headers['X-Github-Event'] = 'status'
  request.headers['X-Hub-Signature'] = signature

  assert_equal false, victim_commit.reload.blocked?
  post :create, body:, as: :json
  assert_response :ok

  # BINDING VIOLATED: attacker authenticated as attacker_org, yet mutated victim_stack's commit
  assert_equal true, victim_commit.reload.blocked?
end
```
Both sides of the equality — "organization that authenticated the request" (`attacker-org`) vs. "stack/repository actually mutated" (`victim_stack`, owned by a different org) — diverge, confirming the cross-tenant write.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L219-237)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
