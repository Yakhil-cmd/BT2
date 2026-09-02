This confirms the exploit chain: `StatusHandler#process` at [1](#0-0)  looks up commits purely by `sha` (globally, across all stacks) via `Commit.where(sha: params.sha)` and directly calls `create_status_from_github!`, which is not scoped to `repository.full_name` at all — it's scoped only by `sha`, so a colliding/matching commit sha in *any* stack tracked by Shipit will get a forged status attached. `Status` then triggers `schedule_continuous_delivery` on `after_commit` at [2](#0-1)  and `Stack#trigger_continuous_delivery` will build and run an actual deploy if the stack has `continuous_deployment: true` and the forged status makes the commit `deployable?`, as shown by the test `"updating state to success triggers new deploy when stack has continuous deployment"` at [3](#0-2) .

The authentication binding is: `WebhooksController#verify_signature` selects the GitHub App/secret keyed by `repository_owner` derived from `params.dig('repository','owner','login')` at [4](#0-3)  and [5](#0-4) , but `GithubApp#verify_webhook_signature` explicitly skips verification when no `webhook_secret` is configured for that organization: `return true unless webhook_secret` at [6](#0-5) . Since `webhook_secret` is an explicitly optional, per-organization key documented as such (`docs/setup.md` shows it and `config/secrets.development.shopify.yml` ships with it `nil`), any organization onboarded without a webhook secret makes the `/webhooks` endpoint effectively unauthenticated for arbitrary payload content — including the `sha`/`state` used by `StatusHandler`, which is not otherwise repository/organization scoped.

### Title
Unauthenticated `status` webhook forgery triggers unauthorized deploys via commit-sha-only lookup and optional webhook secret bypass - (File: app/models/shipit/webhooks/handlers/status_handler.rb, app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb)

### Summary
The engine's `status` webhook handler trusts and applies the `sha`/`state` fields globally across all commits in the datastore without any binding to the organization that was used to select the signature-verification secret, and signature verification itself is a no-op whenever an organization's `webhook_secret` config value is blank. This breaks the equality that should hold: `organization authenticated by verify_signature == organization owning the stack/commit acted upon by the handler`.

### Finding Description
`WebhooksController#verify_signature` picks the verifying `github_app` using `repository_owner`, taken from the untrusted payload (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), shown at [7](#0-6) . `GithubApp#verify_webhook_signature` returns `true` unconditionally when that organization's `webhook_secret` is not configured, at [8](#0-7) . This is a documented, legitimate configuration state (webhook_secret is optional per `docs/setup.md:119` and shown as `nil` in `config/secrets.development.shopify.yml`).

Once past this gate, `StatusHandler#process` performs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` at [1](#0-0) , which is scoped only by `sha` — a value that is global across all stacks/repositories in the Shipit instance, with no check that the commit's stack belongs to the organization that authenticated the request. Creating a `Status` fires `schedule_continuous_delivery` on `after_commit`, at [2](#0-1) , which for any stack with `continuous_deployment: true` builds and runs a real `Deploy` once the commit becomes `deployable?`, as verified by [3](#0-2) .

### Impact Explanation
An unprivileged network attacker who knows (or brute-forces/observes) a real commit SHA that exists in a victim stack tracked by the same Shipit instance can forge a `status` event whose `repository.owner.login` names any organization configured without a `webhook_secret`, bypassing signature verification entirely, then set `state: success` for that SHA. This is High/Critical impact: it lets an attacker trigger an unauthorized deploy (`Stack#trigger_continuous_delivery`) on a repository/organization the attacker was never authenticated against, directly matching the "unauthorized deploy" impact criterion.

### Likelihood Explanation
Requires: (1) at least one organization onboarded to the Shipit instance without `webhook_secret` set — an explicitly supported, documented configuration — and (2) knowledge of a commit SHA tracked on a target stack with continuous deployment enabled (SHAs are not secret; they're visible in the Shipit UI/API and GitHub). No GitHub write access, API token, or session is required, satisfying the "unprivileged attacker" bar.

### Recommendation
- Require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`).
- Scope `StatusHandler#process` (and any similar handler) to commits belonging to the stack(s) of the authenticated `repository_owner`/`repository.full_name`, not a bare `sha` lookup across the whole instance.
- Cross-check `params.dig('repository','full_name')`'s owner against `repository_owner` used for signature selection before dispatching to handlers.

### Proof of Concept
1. Configure (or find) an organization `org-no-secret` in `Shipit.github` config with `webhook_secret` unset.
2. Identify a commit SHA `S` that is tracked by a victim stack `victim/repo` with `continuous_deployment: true` (SHAs are publicly visible via GitHub/Shipit UI).
3. `POST /webhooks` with header `X-Github-Event: status`, no valid `X-Hub-Signature` needed, and body:
```json
{"repository": {"owner": {"login": "org-no-secret"}}, "sha": "S", "state": "success", "context": "any"}
```
4. `verify_signature` resolves `github_app` for `org-no-secret`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the (missing/garbage) signature header.
5. `StatusHandler#process` finds commit `S` (belonging to `victim/repo`, an unrelated org) via the global `Commit.where(sha: ...)` and creates a `success` status on it.
6. `Status#schedule_continuous_delivery` fires; if commit `S` is now deployable and no other deploy is in flight, `ContinuousDeliveryJob` runs and `Stack#trigger_continuous_delivery` performs an unauthorized deploy on `victim/repo`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
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
