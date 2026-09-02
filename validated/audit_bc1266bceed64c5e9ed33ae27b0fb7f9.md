### Title
Webhook signature check verifies the payload's `repository.owner.login` while every event handler acts on `repository.full_name`, letting a webhook signed for one configured GitHub organization drive writes on a stack belonging to a different organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/secret used to authenticate the inbound webhook based on `repository_owner`, which is read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or the `organization.login` fallback). Every downstream event handler, however, resolves the `Stack`/`Repository` it actually mutates from a different, independently-controlled field of the same body: `payload.dig('repository','full_name')`. Because these two fields are never checked for consistency, a webhook that is validly signed (or unsigned, if that org has no `webhook_secret` configured) for organization A can carry a `repository.full_name` pointing at a stack owned by organization B, causing Shipit to act on B's repository under the identity check of A.

### Finding Description
`verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that organization:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

Shipit explicitly supports multiple GitHub organizations sharing one Shipit instance, each with its own `webhook_secret` in `secrets.yml` (`webhook_secret` documented as optional): [3](#0-2) 

Once `verify_signature` passes, the raw payload is dispatched to handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, and every base `Handler` resolves the target repository from a *different* JSON field:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`Repository.from_github_repo_name` looks up by `owner`/`name` parsed from `full_name` with no cross-check against `repository.owner.login`:
```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [5](#0-4) 

The `PushHandler` uses that mismatched lookup directly to trigger a GitHub sync of the resolved stack:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [6](#0-5) 

This is exactly the "organization that authenticated versus the repository that is written" binding: the equality `verified_org(repository.owner.login) == acted_on_repo(repository.full_name)` is assumed by the controller but never enforced.

### Impact Explanation
If a Shipit deployment is configured for multiple GitHub organizations (a documented, supported configuration), and any one configured organization has no `webhook_secret` set (also a documented, valid configuration — `webhook_secret (optional)`), an unauthenticated attacker who merely knows/controls that low-security organization's name can forge a `push`/`status`/`check_suite`/`membership` webhook body whose `repository.owner.login` is set to the low-security org (bypassing/trivially satisfying signature verification) while `repository.full_name` names a stack that actually belongs to a different, sensitive organization. The forged event is then processed against the real stack: `PushHandler` will call `stack.sync_github`, `StatusHandler`/`CheckSuiteHandler` can inject forged CI/check state for a commit, and `MembershipHandler` can create/alter `Team`/`Membership` records — all under an identity check that never verified authorization for that target repository. Because Shipit stacks can be configured for continuous deployment gated on commit statuses/checks, forging a passing CI status for a commit via this path is a route to an unauthorized deploy, meeting the "unauthorized deploy" / "cross-repository writes" bar in scope.

### Likelihood Explanation
Requires the operator to run a legitimate multi-org Shipit configuration (explicitly documented and supported) where at least one configured org omits `webhook_secret`, and requires the attacker to know or guess the `owner/name` of a target stack (stack names/URLs are often not secret — e.g., they are visible in Shipit's own UI paths and API). No GitHub credentials, Shipit session, or `ApiClient` token are required — this is a plain unauthenticated POST to the public `/webhooks` endpoint. This is a plausible, not merely theoretical, misconfiguration given the docs present `webhook_secret` as optional per-org.

### Recommendation
Do not derive the signing-organization identity and the acted-upon-repository identity from independently attacker-controlled fields. `verify_signature` and every `Handler#stacks`/`repository_name` lookup should agree on a single source of truth for the repository (e.g., verify the signature using the app matching the *resolved* stack's actual owner, or reject the payload if `repository.owner.login` does not match the owner segment of `repository.full_name`). Additionally, treat a missing `webhook_secret` for any organization as reducing trust only for that organization's own repositories, never allowing it to authenticate events for other organizations' repositories.

### Proof of Concept
Preconditions: Shipit configured with two orgs, e.g. `LowSecOrg` (no `webhook_secret`) and `TargetOrg` (has a stack `TargetOrg/prod-app`).

```http
POST /webhooks HTTP/1.1
X-Github-Event: push

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-already-known-to-target-repo>",
  "repository": {
    "owner": { "login": "LowSecOrg" },
    "full_name": "TargetOrg/prod-app"
  }
}
```
1. `WebhooksController#verify_signature` computes `repository_owner = "LowSecOrg"`, fetches `Shipit.github(organization: "LowSecOrg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — no `X-Hub-Signature` header is even required.
2. `Shipit::Webhooks.for_event('push').each { |h| h.call(params) }` invokes `PushHandler`, whose `repository_name` reads `payload.dig('repository','full_name') == "TargetOrg/prod-app"`.
3. `Repository.from_github_repo_name("targetorg/prod-app")` resolves the real `TargetOrg` stack, and `stack.sync_github(expected_head_sha: ...)` is invoked — a write triggered under an org-authentication check that never covered `TargetOrg`. [7](#0-6) [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-62)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** docs/setup.md (L182-209)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
end
```
