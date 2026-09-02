### Title
Webhook signature verification is keyed to `repository.owner.login` while every event handler acts on the unrelated `repository.full_name` field, letting an attacker impersonate any repository by targeting an unprotected/misconfigured organization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using `repository_owner`, derived from `payload.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) . Every downstream handler, however, resolves the target `Repository`/`Stack` from a completely different field of the same attacker-controlled JSON body: `payload.dig('repository', 'full_name')` [3](#0-2) . Nothing ties these two fields together at parse time, so the "organization whose secret authenticated the request" and the "repository the handler actually mutates" are two independent, attacker-supplied values.

### Finding Description
The equality that is silently assumed but never enforced is:
`repository.owner.login` (used to select the signing secret) == owner-portion of `repository.full_name` (used to select the target repository/stack).

`Shipit.github(organization: repository_owner)` looks up the per-organization config via `github_app_config`, and `verify_webhook_signature` explicitly **skips verification entirely if that organization has no `webhook_secret` configured**: `return true unless webhook_secret` [4](#0-3) . Multi-org deployments are an explicitly supported configuration shape [5](#0-4) , and it is entirely plausible for one organization to be configured without a `webhook_secret` (e.g. during onboarding, or because `webhook_secret` is documented as optional in `docs/setup.md`) while other organizations in the same install are fully secured.

An attacker who knows (or guesses) the name of any organization configured in this Shipit install *without* a `webhook_secret` can send an unsigned POST to `/webhooks` with:
- `repository.owner.login` = the unprotected organization (so `verify_signature` trivially passes, no `X-Hub-Signature` needed), and
- `repository.full_name` = `"<protected-org>/<protected-repo>"` (any other, fully-secured repository already onboarded to Shipit).

Because handlers never re-check that the verified organization matches the repository they operate on, the forged payload is processed as if it came from GitHub for the protected repository. For example `PushHandler` calls `Repository.from_github_repo_name(repository_name)` (using only `full_name`) and then `stack.sync_github(expected_head_sha: params.after)` [6](#0-5) , and `StatusHandler` writes arbitrary commit statuses for any `sha` matching a `Commit` in the DB, entirely independent of repository ownership [7](#0-6) . `Repository.from_github_repo_name` itself does a bare owner/name lookup with no cross-check against a "verified organization" [8](#0-7) .

### Impact Explanation
This breaks a deployment-trust binding at Critical severity: an attacker with **no credentials at all** (no webhook secret, no `ApiClient` token, no GitHub session) can inject forged GitHub events — fake commit `status` updates, fake `push`/sync triggers — into a fully protected repository/stack by merely routing the forged payload through an organization entry that happens to have no `webhook_secret`. Fake `status` events can flip a commit to "success" for CI contexts that `ci.require` checks against, which the deploy flow trusts when deciding `deployable?`; combined with a forged `push` to trigger `GithubSyncJob`, this can lead to unauthorized/expedited deploys of code that never actually passed CI, i.e. "an unauthorized deploy" per the accepted-impact bar. It also allows an attacker to spoof pull-request lifecycle events (`opened`/`labeled`/`closed`/`reopened`) against arbitrary review stacks, since those handlers resolve the acting repository the same way [9](#0-8) .

### Likelihood Explanation
Requires only that the Shipit install has at least two configured GitHub organizations where at least one lacks a `webhook_secret` — a configuration the codebase explicitly supports and documents as optional (`docs/setup.md` line 30: "Webhook secret (optional)"). No secret, session, or token is needed by the attacker; only knowledge of an unprotected org's login name and the target repository's `owner/name`, both of which are typically public information.

### Recommendation
Enforce that the organization used to verify the signature matches the owner encoded in `repository.full_name` before dispatching to handlers (i.e., derive a single canonical "verified organization" and reject/ignore any handler lookup whose repository owner differs from it). Additionally, consider requiring a non-blank `webhook_secret` for every configured organization (fail closed instead of `return true unless webhook_secret`), so that a single misconfigured/unsecured organization cannot be leveraged to bypass verification for other repositories.

### Proof of Concept
1. Shipit is configured with two organizations, e.g. `unsecured-org` (no `webhook_secret` set) and `secured-org` (properly configured with `webhook_secret` and an onboarded stack `secured-org/app`).
2. Attacker sends, with no `X-Hub-Signature` header at all:
```
POST /webhooks
X-Github-Event: push

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "secured-org/app"
  }
}
```
3. `WebhooksController#verify_signature` computes `repository_owner = "unsecured-org"`, fetches its `GitHubApp` config (no secret), and `verify_webhook_signature` returns `true` unconditionally [4](#0-3) .
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("secured-org/app")` [3](#0-2)  and triggers `stack.sync_github(expected_head_sha: ...)` for the fully-secured `secured-org/app` stack, without ever presenting a valid signature for that organization.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
