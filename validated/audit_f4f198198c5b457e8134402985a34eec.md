### Title
Webhook signature is verified against the payload's `repository.owner.login`, but every event handler resolves and mutates state using the unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to HMAC-verify a delivery against using `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`), but the handlers that actually act on the payload (`Shipit::Webhooks::Handlers::Handler#repository_name`, used by `PushHandler`, all `PullRequest::*Handler`s, etc.) resolve the target `Repository`/`Stack` from `payload.dig('repository','full_name')` — a completely different, independently attacker-controlled field in the same forged JSON body. [1](#0-0) [2](#0-1) 

### Finding Description
The equality that must hold for signature verification to be meaningful is:

`organization whose webhook_secret authenticated the request == organization/repository that the handler subsequently writes to`

In this codebase that equality is never enforced:

- `verify_signature` picks `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` comes from `repository.owner.login` (or `organization.login`), and calls `github_app.verify_webhook_signature(signature, raw_post)` [3](#0-2) , [4](#0-3) .
- `GitHubApp#verify_webhook_signature` HMAC-verifies the *raw body bytes* against that org's configured `webhook_secret` [5](#0-4) .
- Every handler, however, ignores `repository.owner.login` entirely and instead looks up the target repository from `payload.dig('repository', 'full_name')` [6](#0-5) , which is used consistently by `PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `UnlabeledHandler`, `LabelCapturingHandler`, etc. to find the `Repository`/`Stack`/`PullRequest` to mutate [7](#0-6) [8](#0-7) .
- `StatusHandler` is even less scoped: it looks up commits purely `Commit.where(sha: params.sha)` with **no repository check at all**, and directly writes a status onto every matching commit across the whole install [9](#0-8) .

Since the raw JSON body is entirely attacker-controlled (a Shipit multi-tenant installation configures `webhook_secret` per organization, see `config/secrets.development.shopify.yml`, each onboarded organization's admin knows the secret they entered into their own GitHub webhook), an admin of Organization A can craft a payload where:
- `repository.owner.login = "orgA"` — makes `verify_signature` select `orgA`'s `webhook_secret` and the HMAC checks out.
- `repository.full_name = "orgB/victim-repo"` (or, for `status` events, simply any known commit `sha`) — is the value every handler actually acts on.

Before the attacker's request: Org A can only affect stacks/repositories under Org A because it can only forge a valid signature for Org A.
After the attacker's request: Org A, using its own legitimately-known `webhook_secret`, can trigger `PushHandler#process` → `stack.sync_github`, `PullRequest::*Handler`s → archive/unarchive review stacks, capture labels, or `StatusHandler#process` → inject arbitrary commit statuses, all scoped to Org B's (or any other tenant's) repositories/commits — despite never having proven control of Org B's GitHub organization or its webhook secret.

### Impact Explanation
This breaks the authentication boundary the signature check is supposed to enforce (`Shipit.github_teams`/multi-tenant isolation): the check only proves "this request was signed with *some* configured organization's secret," not "this request concerns that organization's repository." Concretely, `StatusHandler` lets a party who only controls one tenant's webhook secret write arbitrary commit statuses (`create_status_from_github!`) onto commits belonging to any other tenant's stack, since it does no repository scoping whatsoever. Commit/CI status state feeds into deploy-readiness signals surfaced elsewhere in the app (`Stack`/`CommitChecks`), so a cross-tenant forged "success" status can influence whether a commit in another organization's stack is presented/treated as deployable, i.e. can materially contribute to an **unauthorized deploy** decision for a repository the attacker never authenticated against.

### Likelihood Explanation
Likelihood is limited to Shipit deployments configured with more than one GitHub organization/app (explicitly supported per `config/secrets.development.shopify.yml`, which documents a `github:` map keyed by multiple org names each with its own `webhook_secret`). Any org onboarded to such a shared instance already legitimately possesses its own `webhook_secret` (it's the value the org's own admin configures in GitHub's webhook settings) — no privileged Shipit credentials, `ApiClient` token, or GitHub App private key are needed. The only requirement is crafting a raw JSON body with mismatched `repository.owner.login` vs `repository.full_name` and posting it to the shared `/webhooks` endpoint.

### Recommendation
In `Shipit::Webhooks::Handlers::Handler#repository_name` (and `StatusHandler#process`), require that the resolved repository's owner matches the organization that the controller used to verify the signature — either by passing the verified `repository_owner` through to the handler and asserting `Repository.owner == verified_organization`, or by deriving the lookup key exclusively from the field that was authenticated (`repository.owner.login`) rather than the independent `repository.full_name`/global commit-sha lookup.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with distinct `webhook_secret`s (as supported by `config/secrets.development.shopify.yml`).
2. As an admin of `orgA` (who knows `orgA`'s `webhook_secret` because they configured GitHub's webhook with it), craft a `status` event body:
```json
{
  "sha": "<sha of a commit belonging to orgB's stack>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(orgA_webhook_secret, raw_body)`.
4. POST to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA").verify_webhook_signature(...)`, which succeeds because the signature really was made with `orgA`'s secret [10](#0-9) .
6. `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [9](#0-8) , writing a forged "success" status onto `orgB`'s commit despite the request never being authenticated against `orgB`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
