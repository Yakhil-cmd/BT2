### Title
Webhook signature verification keys off an attacker-controlled `repository.owner.login` field instead of the repository actually acted upon, allowing cross-organization/cross-repository forgery when any configured GitHub org has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to verify a webhook against using a field it reads straight out of the untrusted, unauthenticated JSON body (`repository.owner.login`, falling back to `organization.login`), before any signature check has occurred. [1](#0-0) [2](#0-1)  `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that selected org has no `webhook_secret` configured, without checking the signature or the payload at all. [3](#0-2)  Because the org used to pick the (possibly absent) secret and the repository actually processed by the event handlers can be two independent fields of the same attacker-supplied body, this breaks the binding "the organization that authenticated the request == the repository that is written/acted on."

### Finding Description
The verification flow is:
1. `repository_owner` is computed purely from the JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [2](#0-1) 
2. That value is used to look up a `GitHubApp` config: `Shipit.github(organization: repository_owner)`. [4](#0-3) 
3. `verify_webhook_signature` is called on that app; if the app has no `webhook_secret` configured (a documented, supported configuration - `webhook_secret: # nil` in the sample secrets files), it returns `true` immediately, without ever hashing or comparing the payload against anything. [3](#0-2) [5](#0-4) 
4. After "verification" succeeds (or is skipped), `create` dispatches the *entire raw body* to event handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [6](#0-5) 
5. Handlers resolve the target `Repository`/`Stack` using a *different* field of the same body — `repository.full_name` — not the `repository.owner.login` used for the security decision: `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')`. [7](#0-6)  The same disjoint-field pattern recurs in `PushHandler`, `StatusHandler` (matches by bare `sha`, no repo scoping at all), `CheckSuiteHandler`, and every `PullRequest::*Handler` (`Repository.from_github_repo_name(params.repository.full_name)`). [8](#0-7) [9](#0-8) [10](#0-9) 

The equality the design relies on is:
`org authenticated via webhook secret lookup == org/repository whose Stack state handlers mutate`

In GitHub's real world this equality always holds because both fields come from the same authentic, GitHub-signed payload. But once *any single organization in the Shipit deployment is configured without a `webhook_secret`* (an explicitly supported and documented configuration - see the sample secrets templates), an unauthenticated attacker can send a POST to `/webhooks` with:
- `repository.owner.login` (or `organization.login`) = the weak org's login → causes `verify_webhook_signature` to short-circuit to `true` with no cryptographic check whatsoever,
- `repository.full_name` = `"<victim-org>/<victim-repo>"` (any org/repo tracked by the Shipit instance, including ones that *do* have a strict secret configured) → causes the handler to operate on the victim's `Stack`.

This decouples "who is proven to be sending this webhook" from "whose repository state gets mutated," directly matching the analog-bug class in the report (state mutated by a code path that assumed a binding which was never actually enforced).

### Impact Explanation
With this bypass an unauthenticated attacker can, for any Shipit-tracked repository:
- Forge `push` events to trigger `PushHandler#process` → `stack.sync_github(expected_head_sha:)`, forcing GitHub sync of arbitrary branches/stacks on demand. [11](#0-10) 
- Forge `status` events to inject fabricated commit statuses via `Commit#create_status_from_github!`, since `StatusHandler` matches purely by `sha` with no repository scoping at all — these statuses feed into deployability/safety checks that can gate automatic deploys. [9](#0-8) 
- Forge `check_suite` events to force `schedule_refresh_check_runs!` on arbitrary commits/stacks. [12](#0-11) 
- Forge `pull_request` events to archive/unarchive review stacks, capture arbitrary labels, or trigger provisioning of review stacks for any repository, via `ReviewStackAdapter`/`*Handler#process`. [13](#0-12) 

If commit statuses or check-suite results are wired into continuous-deployment gating (`Stack.schedule_continuous_delivery`, deployability checks), forged statuses can influence whether an automatic deploy proceeds — pushing this toward "unauthorized deploy/rollback" territory, though I could not fully trace whether forged `status`/`check_suite` events alone are sufficient to flip a stack's deployability without also controlling the underlying commit — this is uncertain from the code reviewed. At minimum this is unauthenticated read/write of stack, commit, and review-stack state (creation of fake commit statuses, forced syncs, forced review-stack lifecycle transitions) for any repository/organization tracked by the Shipit instance, as soon as one organization in the multi-tenant config has no `webhook_secret`.

### Likelihood Explanation
Likelihood depends entirely on deployment configuration: exploitation requires that at least one organization registered with the Shipit instance has no `webhook_secret` set. This is not a hypothetical edge case — it is explicitly presented as a valid configuration in the shipped sample secrets files (`webhook_secret: # nil`) and in the double-app test fixtures, and nothing in `GitHubApp#verify_webhook_signature` or `WebhooksController#verify_signature` prevents or warns against mixing a no-secret org with a secret-protected org on the same instance. [5](#0-4) [14](#0-13)  In any multi-org Shipit deployment where operators forget or choose not to set a webhook secret for a low-traffic/internal org, every other org's repositories become forgeable from the internet with zero credentials — no OAuth token, no `ApiClient`, no repository access needed.

### Recommendation
Do not select the verifying `GitHubApp`/secret using a field taken from the unauthenticated body when that field is disjoint from the field actually used to locate/mutate state. Concretely:
1. Have `verify_signature` fail closed (return `422`) rather than `true` when `webhook_secret` is blank, or require every configured organization to have a secret in production.
2. After signature verification, re-derive the acting organization from the *same* field used to select the verifying secret (`repository.owner.login`) and assert it matches the organization implied by `repository.full_name` before dispatching to handlers, rejecting any mismatch.
3. Consider deriving the app/secret to verify from the installation ID (`installation.id`) present in GitHub App webhook payloads rather than from a client-suppliable `login` string, since installation IDs are harder to spoof usefully across orgs.

### Proof of Concept
Preconditions: Shipit instance configured with two GitHub orgs, `weakorg` (no `webhook_secret`) and `victimorg` (has a `webhook_secret`), both with tracked stacks.

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json
(no X-Hub-Signature header needed, or any bogus value)

{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "weakorg" },
    "full_name": "victimorg/victim-repo"
  }
}
```

Trace:
- `repository_owner` resolves to `"weakorg"`. [2](#0-1) 
- `Shipit.github(organization: "weakorg")` returns the app config with `webhook_secret` blank, so `verify_webhook_signature` returns `true` unconditionally. [15](#0-14) 
- `create` dispatches to `PushHandler.call(params)`, whose `repository_name` is `payload.dig('repository','full_name')` = `"victimorg/victim-repo"`, so it resolves `victimorg`'s real `Stack` and calls `sync_github` on it. [7](#0-6) [11](#0-10) 

The attacker never needed `victimorg`'s webhook secret, an `ApiClient` token, or any GitHub credential.

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

**File:** config/secrets.development.shopify.yml (L5-10)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
