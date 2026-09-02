### Title
Webhook signature is verified against the organization named in `repository.owner.login`/`organization.login`, but event handlers act on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to validate the `X-Hub-Signature` against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). Once the signature check passes, the raw parsed `params` (the entire attacker-controlled JSON body) is dispatched unmodified to every registered `Shipit::Webhooks::Handlers::Handler`. Those handlers locate the target `Repository`/`Stack` using a *different* field of the same payload: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), which is then split into owner/name and looked up via `Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`).

### Finding Description
The binding that should hold is: **the GitHub organization whose secret authenticated the signature == the GitHub organization that owns the repository being written to by the handler**. Nothing in the code enforces that these two payload fields agree.

- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from `repository.owner.login` (or `organization.login`) and calls `Shipit.github(organization: repository_owner)` to fetch the corresponding `GitHubApp` instance's `webhook_secret`, then verifies the raw body HMAC against it.
- `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and consumers like `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) use `repository.full_name` (a completely separate JSON field) to find the `Stack`s that get synced/deployed.

In Shipit's documented multi-organization mode (`docs/setup.md:181-209`), each organization has its own `app_id`, `installation_id`, and independently configured `webhook_secret` (which can legitimately be blank/unset, and `GitHubApp#verify_webhook_signature` explicitly returns `true` when `webhook_secret` is blank — `lib/shipit/github_app.rb:76-83`). An attacker who has (or can obtain) a valid HMAC for one configured organization — including trivially, an org whose `webhook_secret` was left unset — can craft a JSON body where `repository.owner.login`/`organization.login` names that (weakly-configured/known) organization, while `repository.full_name` names a repository belonging to a *different* organization that Shipit also tracks. The signature check passes because it only ever inspects the "owner" field, yet every handler that follows blindly trusts `repository.full_name` to decide which `Repository`/`Stack` to mutate.

### Impact Explanation
This crosses the "organization authenticated vs. repository written" trust boundary explicitly called out in scope. Concretely:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` on any not-archived stack whose branch matches, for a repository chosen purely from `full_name` — enabling spoofed pushes against a stack belonging to a repository/org that was never actually authenticated by the signature.
- `StatusHandler` writes commit statuses (`Commit#create_status_from_github!`) based purely on `sha`, with no organization binding check at all beyond the initial mis-scoped signature check.
- Because `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the same `params` to all handlers, this is a general cross-repository write primitive, not confined to one handler.

This matches "cross-repository writes" in the Critical impact bucket, since it lets an attacker who can produce a valid signature for one (possibly weakly-secured) organization inject webhook events that mutate state (triggering sync/deploys, forged commit statuses) for a repository/stack under a different, better-protected organization.

### Likelihood Explanation
Exploitability depends on the attacker being able to produce a signature that `verify_webhook_signature` accepts for at least one org configured in Shipit's `github` secrets — e.g., an org whose `webhook_secret` is left blank (which `verify_webhook_signature` explicitly treats as "always verified", per `lib/shipit/github_app.rb:76-77`), or one whose secret is otherwise known/leaked. In the common single-org deployment this collapses (there's only one `webhook_secret`, so `repository_owner` mismatch is moot), but the vulnerability is real and reachable specifically in the documented multi-GitHub-app configuration (`docs/setup.md` "Using Multiple Github Applications"), where distinct orgs can have independently weak or unset secrets while `repository.full_name` is never cross-checked against the authenticated org. I could not fully verify from the available index whether `Shipit.github(organization:)`'s lookup enforces case/format constraints that would block a mismatched-but-plausible owner string, so likelihood in a hardened, single-org, fully-secreted deployment is low, but non-trivial in the supported multi-org configuration.

### Recommendation
After signature verification succeeds for `repository_owner`, enforce that every field of the payload used by handlers to identify the target repository (in particular `repository.full_name`'s owner segment) matches the same `repository_owner`/organization that authenticated the request. Reject the webhook (422) if `repository.full_name.split('/').first` does not case-insensitively equal `repository_owner`, before dispatching to `Shipit::Webhooks.for_event(event)`.

### Proof of Concept
1. Configure Shipit with two GitHub Apps per `docs/setup.md` multi-org example: `OrgWeak` (no `webhook_secret` set) and `OrgTarget` (properly secured, hosts a tracked repository `OrgTarget/prod-app`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha already known to Shipit>",
  "repository": {
     "owner": { "login": "OrgWeak" },
     "full_name": "OrgTarget/prod-app"
  }
}
```
No `X-Hub-Signature` header is required to pass verification because `verify_webhook_signature` short-circuits to `true` when `OrgWeak`'s `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`), and `repository_owner` resolves to `OrgWeak` (`app/controllers/shipit/webhooks_controller.rb:59-61`).
3. `PushHandler#process` resolves the target stack using `repository.full_name` = `OrgTarget/prod-app` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`, `push_handler.rb:12-17`), triggering `sync_github` against `OrgTarget`'s tracked stack despite the request never being authenticated by `OrgTarget`'s secret. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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
      end
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
