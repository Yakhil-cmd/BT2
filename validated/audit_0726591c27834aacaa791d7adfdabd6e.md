### Title
Cross-organization webhook forgery via mismatched signature-selection org and processed-repository org - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/HMAC secret to use for signature verification based on an attacker-controlled JSON field (`repository.owner.login` / `organization.login`), but the event handlers that subsequently act on the payload key off a different (also attacker-controlled) field (`repository.full_name`). In a multi-organization Shipit deployment where at least one configured organization has no `webhook_secret` set, this breaks the binding "organization whose secret authenticated the request == repository/organization that Shipit actually writes to."

### Finding Description
`Shipit::WebhooksController#verify_signature` computes the verifying GitHub App from the payload itself, before the signature has actually been validated: [1](#0-0) [2](#0-1) 

`repository_owner` is read directly from the untrusted, unauthenticated JSON body (`params.dig('repository','owner','login')`). `Shipit.github(organization: repository_owner)` then looks up per-org config and constructs/reuses a `GitHubApp` for that org (`lib/shipit.rb:170-181`, `196-200`). `GitHubApp#verify_webhook_signature` is only meaningful if a `webhook_secret` is configured for that specific org: [3](#0-2) 

Note line 77: `return true unless webhook_secret` — if the organization resolved from the attacker-supplied `repository.owner.login` has no `webhook_secret` configured, verification unconditionally passes regardless of the actual `X-Hub-Signature` header.

Once `verify_signature` passes, `create` parses the same raw body and dispatches to handlers using a *different* attacker-controlled field, `repository.full_name`, to look up the actual `Shipit::Repository`/`Stack` to mutate: [4](#0-3) [5](#0-4) 

For example, `PushHandler` triggers a GitHub sync for any stack matching the branch, regardless of which org's secret validated the request: [6](#0-5) 

and `PullRequest::OpenedHandler`/`ClosedHandler`/`LabeledHandler` resolve the repository via `Repository.from_github_repo_name(params.repository.full_name)` — completely independent from the org used for authentication: [7](#0-6) 

**Broken binding:** `organization authenticated (via repository.owner.login / GitHubApp#webhook_secret)` == `repository/stack actually written (via repository.full_name)`. Nothing enforces that these two attacker-supplied fields refer to the same organization, and the whole request body — including both fields — is fully attacker-controlled prior to signature verification succeeding.

### Impact Explanation
In any Shipit instance configured for multiple GitHub organizations (the documented multi-org `secrets.yml` schema, see `docs/setup.md`/`config/secrets.development.example.yml`) where at least one configured org has an empty/unset `webhook_secret`, an unauthenticated attacker can:
- Set `repository.owner.login` (or `organization.login`) to the org lacking a webhook secret, causing `verify_webhook_signature` to return `true` unconditionally.
- Set `repository.full_name` to `victim-org/victim-repo` (any repo actually tracked by Shipit, belonging to a *different*, properly-secured org).
- Forge `push`, `status`, `check_suite`, `pull_request`, or `membership` events for the victim repository/org.

Depending on handler, this enables forcing `stack.sync_github` (triggering GithubSyncJob for arbitrary shas), forging commit statuses (`StatusHandler` → `Commit#create_status_from_github!`, which can flip CI/deploy-gating checks), fabricating/archiving review stacks via forged `pull_request` events, and injecting fabricated team/user memberships via the `membership` handler. Forged commit statuses that mark commits as passing CI, combined with the deploy pipeline's reliance on such statuses for deployability checks, can lead to an unauthorized deploy of attacker-influenced state — meeting the "unauthorized deploy" bar. This crosses the required repository/authentication boundary without requiring any Shipit session, API token, or GitHub credentials, satisfying the "organization authenticated versus repository written" analog explicitly called out in scope.

### Likelihood Explanation
Requires a specific but realistic and documented deployment pattern: multi-organization `secrets.yml` github configuration where not every organization entry sets `webhook_secret` (the sample config marks `webhook_secret` as optional/`nil`-able in `config/secrets.development.example.yml`). Given this is a supported, documented configuration shape, and the exploit needs no credentials, only a crafted HTTP POST to `/webhooks`, likelihood is moderate-to-high in installations using multiple orgs without uniformly enforcing webhook secrets.

### Recommendation
Verify the webhook signature using a fixed, deployment-wide/global secret determination that cannot be influenced independently by the payload — or, at minimum, after determining `repository_owner`, cross-check that the resolved `Repository`/`Stack` model's actual `owner` matches `repository_owner`/the org whose secret validated the signature before dispatching to handlers. Additionally, treat organizations without a configured `webhook_secret` as unable to authenticate requests referencing repositories belonging to other organizations (fail closed rather than `return true unless webhook_secret`), or require `webhook_secret` to be mandatory for all configured organizations.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `victim-org` (has `webhook_secret: <strong-secret>`, has a tracked repository/stack `victim-org/prod-app`), and `attacker-org` (installed app, but `webhook_secret` left blank/nil — a documented supported configuration).
2. Attacker sends, without any valid signature:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already known to exist on victim repo>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/prod-app"
  }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`; since `attacker-org` has no `webhook_secret`, `verify_webhook_signature` returns `true` immediately, bypassing verification.
4. `Shipit::Webhooks.for_event('push')` dispatches `PushHandler`, which calls `stack.sync_github(expected_head_sha: params.after)` for any `victim-org/prod-app` stack matching branch `main` — an unauthenticated write triggered against `victim-org`'s repository, despite the request never being signed with `victim-org`'s secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
