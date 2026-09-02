### Title
Cross-tenant status forgery via signature verification keyed on an unrelated org's `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/org config used to verify the HMAC signature solely from `repository.owner.login` in the attacker-controlled JSON body, via `repository_owner`. `Shipit::GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever that org has no `webhook_secret` configured. `StatusHandler#process` then applies the (unverified) payload globally with `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }`, with no repository/stack scoping whatsoever.

### Finding Description
The broken binding: the code implicitly assumes `repository_owner (used to select the signing secret) == the org that owns the data the handler mutates`. In reality the only value consulted for verification is `params.dig('repository','owner','login')` [1](#0-0) , and the org config it resolves to is looked up via `Shipit.github(organization: repository_owner)` before running `verify_webhook_signature` [2](#0-1) .

Root cause in `GitHubApp#verify_webhook_signature`: `return true unless webhook_secret` [3](#0-2) . If the org named in `repository.owner.login` has no `webhook_secret` configured, **any** payload is accepted, regardless of signature, body content, or which repository/stack the event actually claims to affect.

`StatusHandler` never re-validates the repository at all: it only declares `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches` in its params schema [4](#0-3) , and its `process` method queries `Commit.where(sha: params.sha)` — a global, unscoped lookup across every stack/repository in the installation — and calls `commit.create_status_from_github!(params)` on each match [5](#0-4) . `create_status_from_github!` writes a `Status` record tied to that commit's actual `stack`, which can influence deployability (`add_status` triggers `schedule_merges`, `Hook.emit(:deployable_status, ...)`, etc.) [6](#0-5) [7](#0-6) .

Exploit flow:
1. Attacker identifies (or creates) a Shipit-configured GitHub organization/app entry that has no `webhook_secret` set (a legitimate, if lax, configuration state that the "org configured without webhook_secret" precondition grants).
2. Attacker sends `POST /webhooks` with header `X-Github-Event: status` and body `{"repository": {"owner": {"login": "<no-secret-org>"}}, "sha": "<victim sha>", "state": "success", ...}`. Note the `full_name` split described in the question is not even necessary here, because `StatusHandler` never reads `repository.full_name` to scope the query — it only needs `repository.owner.login` to pick a no-secret org for signature bypass.
3. `verify_signature` resolves `Shipit.github(organization: "no-secret-org")`, calls `verify_webhook_signature`, which short-circuits to `true` because that org's `webhook_secret` is blank.
4. `StatusHandler.call(params)` runs, matching `sha` against every `Commit` row in the database irrespective of which org/repository it belongs to, and writes a forged status onto it.

Existing guards do not stop this: `drop_unhandled_event` only checks the event type is registered, not the payload's authenticity [8](#0-7) ; the `ExplicitParameters` schema for `StatusHandler` has no repository/stack field to validate [4](#0-3) ; and no controller-level check ties the verified org to the affected commit's stack.

### Impact Explanation
An attacker who controls (or can name) one poorly configured, secret-less GitHub organization in the Shipit deployment can forge a `status` webhook that writes a `Status` record onto **any commit in any stack/repository in the entire installation**, purely by guessing/knowing a target SHA (SHAs are not secret — they're visible via GitHub, PRs, commit links, CI logs, etc.). This can flip a commit from `pending`/`failure` to `success`, which feeds directly into `deployable?`, `schedule_merges`, and continuous-deployment eligibility (`schedule_continuous_delivery`), potentially triggering an unauthorized deploy/merge for a completely unrelated tenant's stack. This matches "Critical — a payload for one repository mutating another's stack/commit" and "unauthorized deploy/merge."

### Likelihood Explanation
Preconditions: the Shipit installation must have at least one org configured without a `webhook_secret` (this is an explicit stated precondition of the question, and is a real, supported configuration path since `webhook_secret` is optional/`presence`-checked in `GitHubApp#initialize` [9](#0-8) ). Given that, the attack requires zero authentication, zero secrets, and a single HTTP POST — attacker cost is minimal and fully repeatable against arbitrary target SHAs across the whole installation, not just repos the attacker controls.

### Recommendation
Verify the webhook signature using the secret belonging to the organization/repository that the handler will actually mutate, and enforce that binding structurally: (1) do not allow `verify_webhook_signature` to silently return `true` for org configs missing a `webhook_secret` — require an explicit "unauthenticated" opt-in or reject in that case; (2) scope every handler's mutation to the specific `Repository`/`Stack` resolved from the verified organization (e.g., `StatusHandler` should restrict `Commit.where(sha: ...)` to commits whose `stack.repository` matches the verified `repository.full_name`), never a global, cross-tenant lookup by `sha` alone.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub, using existing `t0kEn`/test stubbing conventions in the repo):
1. Configure two orgs in `Shipit.github_config`/`Rails.application.config.x.shipit.github`-equivalent test fixture: `"secretless-org"` with no `webhook_secret`, and `"victim-org"` with a configured `webhook_secret`.
2. Create a `Stack` belonging to `victim-org/victim-repo` and a `Commit` with a known `sha` and no existing successful status; assert `commit.status.state != "success"` (LHS of the binding: no legitimate status exists).
3. `POST /webhooks` with header `X-Github-Event: "status"`, no/garbage `X-Hub-Signature`, and JSON body: `{"repository": {"owner": {"login": "secretless-org"}}, "sha": commit.sha, "state": "success", "context": "forged"}`.
4. Assert response is `200 OK` (accepted despite invalid/absent signature, because `secretless-org` has no `webhook_secret`).
5. Reload `commit` and assert `commit.status.state == "success"` and `commit.statuses.last.context == "forged"` — proving a payload "verified" against `secretless-org` mutated a commit belonging to `victim-org`'s stack, i.e., RHS now equals the forged value, violating the invariant that "`A status event only affects the repository/stack whose secret authenticated it`."

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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
