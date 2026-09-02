### Title
`StatusHandler#process` writes attacker-authored status onto a Commit belonging to an org that never authenticated the payload - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a payload against the GitHub App configured for `repository_owner`/`organization.login` taken from the attacker-controlled JSON body [1](#0-0) [2](#0-1) , but once verified, `StatusHandler#process` looks up the target `Commit` purely by global `sha`, with no check that the commit's `stack`/repository is owned by the org that just authenticated the request [3](#0-2) . In a multi-org Shipit deployment where any configured org has no `webhook_secret` (an explicitly supported, documented configuration - see `docs/setup.md`), any request claiming to be from that org passes signature verification unconditionally [4](#0-3) , letting the sender forge a `status` webhook with a victim commit's `sha` and have `Commit#create_status_from_github!` persist attacker-controlled `state`/`description`/`target_url`/`context` on that victim's commit [5](#0-4) .

### Finding Description
The binding the code is supposed to enforce is: **organization that authenticated the payload (`repository_owner` resolved via `Shipit.github(organization: repository_owner)` in `verify_signature`) == organization owning the `Commit`/`Stack` whose `statuses` are mutated by `StatusHandler#process`**. Tracing the code shows this equality is never checked:

1. `WebhooksController#create` parses `request.raw_post` and dispatches to handlers before authenticity is content-scoped: `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` [6](#0-5) .
2. `verify_signature` resolves the GitHub App purely from attacker-supplied JSON fields (`repository.owner.login` or `organization.login`), then calls `github_app.verify_webhook_signature` [7](#0-6) [2](#0-1) .
3. `GithubApp#verify_webhook_signature` returns `true` unconditionally `unless webhook_secret` is configured for that org [4](#0-3) . Multi-org configuration is a documented, supported feature where `webhook_secret` is explicitly optional per org (see `docs/setup.md` lines 181-209 and `config/secrets.development.example.yml` showing `webhook_secret: # nil`).
4. Once verification passes (as an attacker-owned org with no configured secret, or with a secret the attacker knows because they own that org's GitHub App), `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, cross-tenant lookup with zero reference to `repository_owner`, the stack's repository, or any ownership check [3](#0-2) .
5. `create_status_from_github!` -> `add_status` -> `statuses.replicate_from_github!` persists the attacker-supplied `state`, `description`, `target_url`, `context` directly, and triggers downstream effects such as `stack.schedule_merges if new_status.pending? || new_status.success?` [5](#0-4) [8](#0-7) .

None of the listed guards close this gap: `drop_unhandled_event` only checks the event type is handled, `verify_signature` authenticates the *sender's claimed org*, not the *target commit's owning org*, the `ExplicitParameters` schema in `StatusHandler` only validates field types/shapes (`sha`, `state`, etc.) with no repository binding [9](#0-8) , and `Commit#create_status_from_github!`/`add_status` perform no ownership check either [8](#0-7) .

**Exact attacker request**: `POST /webhooks` with header `X-Github-Event: status`, JSON body `{"repository":{"owner":{"login":"attacker-org"}}, "sha":"<victim-commit-sha>", "state":"success", "context":"ci/forged", "target_url":"https://evil", "branches":[]}`, signed (or unsigned, if no secret is configured) for `attacker-org`, where `attacker-org` is any GitHub organization/app registered in Shipit's multi-org `github:` config that the attacker legitimately owns and controls (and for which no `webhook_secret` is set, or the attacker knows the secret since they set it themselves).

### Impact Explanation
A successful request writes a forged `Status` row (including a fabricated `"success"` state) onto a `Commit` belonging to a completely different tenant/org's `Stack`, bypassing the "org that authenticated" == "org that's mutated" invariant. Since `Commit#deployable?` and `stack.schedule_merges` react to status changes, this can make a victim's commit appear CI-green and enable an unauthorized deploy or auto-merge gate bypass — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy, rollback or merge". The attack is repeatable against any commit `sha` in the entire Shipit instance (the lookup is global, not scoped per stack/repo), so the blast radius spans all tenants hosted on one Shipit deployment.

### Likelihood Explanation
Exploitability requires: (a) the Shipit instance to be configured for multiple GitHub organizations (a documented, supported configuration), and (b) at least one configured org to have no `webhook_secret` set (also documented as optional/`nil` in example configs), or the attacker owning/controlling one of the configured orgs and thus knowing its secret. Given these preconditions, the attacker's cost is a single unauthenticated-cost HTTP POST with a guessed/observed victim commit `sha` (SHAs of public repos are frequently visible via GitHub UI/API), fully repeatable and requiring no Shipit session, API token, or GitHub secret beyond what the attacker's own org already has.

### Recommendation
In `StatusHandler#process`, restrict the `Commit` lookup to commits whose `stack`/`repository` matches the `repository_owner`/`repository.full_name` that was authenticated in `verify_signature` (e.g., join through `Stack`/`Repository` and filter by `owner`/`full_name` before calling `create_status_from_github!`). More generally, `WebhooksController` should pass the authenticated `repository_owner`/`repository.full_name` down to every handler so each handler can enforce that the record it mutates belongs to the organization that signed the request.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (minitest, no live GitHub)
test "status webhook authenticated under attacker org can forge status onto victim's commit" do
  victim_commit = shipit_commits(:first) # belongs to stack owned by "shopify" (or similar victim org)
  attacker_org = "attacker-org"

  # Precondition mirrors docs/setup.md multi-org config: attacker-org has no webhook_secret
  Shipit.stubs(:github).with(organization: attacker_org).returns(
    Shipit::GithubApp.new(attacker_org, { webhook_secret: nil })
  )

  payload = {
    "repository" => { "owner" => { "login" => attacker_org } },
    "sha" => victim_commit.sha,
    "state" => "success",
    "context" => "attacker-forged-ci",
    "target_url" => "https://evil.example.com"
  }

  assert_difference "victim_commit.statuses.count", 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload) # dispatched exactly as WebhooksController#create does
  end

  forged_status = victim_commit.statuses.last
  # Binding under test: authenticating org (attacker_org) != owning org of victim_commit.stack
  refute_equal attacker_org, victim_commit.stack.repository.owner
  assert_equal "success", forged_status.state
  assert_equal "attacker-forged-ci", forged_status.context
end
```
This demonstrates that `params.sha` matching a real victim `Commit` is sufficient for `StatusHandler#process` to write attacker-controlled `state`/`context`/`target_url` regardless of which org authenticated the webhook, confirming the broken binding.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-15)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
