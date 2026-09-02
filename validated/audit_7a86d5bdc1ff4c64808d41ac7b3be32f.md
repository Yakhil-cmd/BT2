### Title
Webhook signature verification is bound to an attacker-chosen `repository.owner.login`/`organization.login` while the handlers act on an unrelated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a value read straight out of the untrusted, unsigned JSON body. The downstream event handlers (`PushHandler`, `StatusHandler`, etc.) resolve the target `Stack`/`Commit` using a *different* field of that same untrusted body (`repository.full_name`, or bare `sha`). Nothing enforces that the organization whose secret validated the signature is the same organization that owns the repository the handler is about to mutate.

### Finding Description
`repository_owner` is computed purely from payload content: [1](#0-0) 

That value selects the `GitHubApp` instance/config used to verify the signature: [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly **bypasses verification entirely** when the selected organization's `webhook_secret` is blank: [3](#0-2) 

This "no secret configured = always verified" behavior is a supported, documented configuration (multiple orgs configured under `secrets.github`, each with its own optional `webhook_secret`), as shown in the dummy secrets fixture where `OrgTwo` has `webhook_secret: # nil`: [4](#0-3) 

Once `verify_signature` passes (trivially, for the secret-less org), `WebhooksController#create` dispatches the raw, attacker-supplied JSON to handlers, unmodified: [5](#0-4) 

The handlers never re-check `repository_owner`; they instead resolve the actual `Repository`/`Stack` from `repository.full_name` (a separate, independently-controlled field of the same payload): [6](#0-5) [7](#0-6) 

`StatusHandler` is even less scoped — it doesn't consult `repository` at all, only a bare commit `sha`, and applies whatever `state`/`context` the attacker supplies to any commit row matching that sha across the whole install: [8](#0-7) 

**Broken binding (equality that should hold but doesn't):**
`organization authenticated (repository_owner used to pick webhook_secret)` ≠ `organization/repository actually written to (repository.full_name / commit.sha used by handlers)`.

Concretely: an unprivileged, unauthenticated internet requester can send a POST to the public `/webhooks` endpoint with:
- `repository.owner.login` (or `organization.login`) = an org configured in `secrets.github` with a blank `webhook_secret` (this is a supported per-org opt-out, not a bug on its own),
- `repository.full_name` = the full name of any *other* org's/repo's tracked `Stack` in the same Shipit instance,
- an `X-Github-Event: status` header and a `sha` matching a real commit, with `state: "success"`.

`verify_signature` authenticates against the empty-secret org and passes unconditionally, then `StatusHandler` (or `PushHandler`) acts on the targeted stack/commit belonging to a completely different, properly-secured organization.

### Impact Explanation
This crosses the "High" bar explicitly listed in scope: it is an unauthenticated forgery of `status`/`push` webhook data affecting a tracked stack that the attacker was never authenticated for. Concretely:
- `StatusHandler` lets the attacker create arbitrary CI `Status` rows (state `success`/`failure`/etc., arbitrary `context`/`description`) for any commit in the instance, without ever proving control of, or a valid signature from, that commit's actual owning organization. Because `Status` creation feeds `Commit#add_status`, which can schedule continuous delivery / merges (`stack.schedule_merges if new_status.pending? || new_status.success?`), a forged "success" status can influence auto-merge/continuous-deployment scheduling for a stack the attacker has no legitimate relationship to — an unauthorized-deploy-adjacent primitive achieved purely by an unauthenticated cross-organization binding break.
- `PushHandler` lets the attacker trigger `GithubSyncJob`/`sync_github` for any tracked stack by supplying its `repository.full_name`, again authenticated only against an unrelated, secret-less org.

This is possible with zero credentials, zero repository access, and zero session — exactly the unprivileged-attacker class the scope calls out.

### Likelihood Explanation
Requires only that the Shipit deployment: (a) uses the multi-organization GitHub App config format (`secrets.github` keyed by org — supported and documented), and (b) has at least one configured organization with `webhook_secret` unset/blank while at least one other organization's repos are tracked. This is a realistic operational configuration (e.g., an org onboarded before webhook secrets were mandated, or an org intentionally left without a secret because "it's optional"), and the resulting cross-organization confusion is silent — no error, no log flag distinguishing "verified because valid HMAC" from "verified because no secret was configured for the org name found in the payload."

### Recommendation
- After selecting the `GitHubApp` via `repository_owner`, re-verify that `repository_owner` matches the owner of the `Stack`/`Repository`/`Commit` actually being mutated by the handler (i.e., only allow a handler to touch resources belonging to the organization that was cryptographically authenticated, or whose config explicitly opted out of both verification and cross-org isolation).
- Do not treat "webhook_secret blank" as "signature verified"; instead require an explicit `insecure_skip_verification: true`-style flag, and scope any secret-less org's webhooks so they can only affect repositories under that same org.
- In `StatusHandler`, resolve `Commit`s by `(sha, repository_owner)`/stack ownership rather than a bare, install-wide `sha` lookup.

### Proof of Concept
1. Configure `secrets.github` with two orgs: `victim-org` (`webhook_secret: "s3cr3t"`) owning a tracked `Stack` for `victim-org/app`, and `empty-org` (`webhook_secret:` blank/nil), also configured but not related to `victim-org`.
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<real sha of a commit in victim-org/app>",
  "state": "success",
  "context": "ci/travis",
  "repository": { "owner": { "login": "empty-org" }, "full_name": "empty-org/whatever" }
}
```
No `X-Hub-Signature` header is required to be valid because `Shipit.github(organization: "empty-org")` has a blank `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`).
3. `WebhooksController#create` dispatches this payload to `StatusHandler`, which looks up `Commit.where(sha: params.sha)` — irrespective of `empty-org` — and calls `create_status_from_github!`, forging a `success` status on `victim-org`'s commit, potentially triggering continuous-delivery scheduling for a stack the attacker never authenticated against.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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
