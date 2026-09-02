### Title
Webhook signature is verified against `repository.owner.login` while the acted-upon repository is resolved from the independent `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's HMAC secret to validate a GitHub webhook against by reading `repository.owner.login` (or `organization.login`) out of the *unauthenticated* request body, then verifies the signature using that org's secret. Every event handler, however, resolves the Stack/Repository that will actually be mutated by reading a *different* JSON path in the same unauthenticated body: `repository.full_name`. Nothing binds these two fields together, so a payload can be crafted where the field used to select/verify the signature names one organization while the field used to find the target repository names a completely different one — mirroring the reported bug class of two logically-coupled values (anchor price used for the "is the reporter trusted" check vs. the price actually written) being allowed to diverge.

### Finding Description
`verify_signature` picks the signing organization purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`repository_owner` is derived from `params.dig('repository', 'owner', 'login')`, and `Shipit.github(organization: repository_owner)` looks up the per-organization GitHub App config (and its `webhook_secret`) for that name. The HMAC is verified with `github_app.verify_webhook_signature(...)` from `lib/shipit/github_app.rb`, comparing the request signature against the secret for whatever organization name happens to sit at that JSON path — a path fully controlled by whoever is sending the HTTP request.

Once the signature check passes, every dispatched handler resolves the target repository from a *different, independently-controlled* field in the same body: [3](#0-2) 

`repository_name` reads `payload.dig('repository', 'full_name')`, and `stacks` looks it up via `Repository.from_github_repo_name`: [4](#0-3) 

`PushHandler` then dispatches `GithubSyncJob`-driving `sync_github` calls on every non-archived stack of whatever repository `full_name` resolves to: [5](#0-4) 

The equality the code implicitly (and incorrectly) assumes is:

`organization whose secret authenticated the request (repository.owner.login) == organization/repository that gets acted upon (repository.full_name)`

Because `repository.owner.login` and `repository.full_name` are two independent leaves of the same attacker-supplied JSON tree, an operator who legitimately controls their own tenant in a multi-organization Shipit deployment (each organization configured with its own `webhook_secret` via `Shipit.github(organization: ...)`) can sign a payload with their own valid secret while setting `repository.owner.login` to their own org (so `verify_signature` picks — and passes against — their own secret) and `repository.full_name` to `"victim-org/victim-repo"` (so the handler resolves and acts on a Stack belonging to a different organization entirely). All PR/push/status handlers in `app/models/shipit/webhooks/handlers/**` share this same `full_name`-based resolution, so this is not limited to pushes.

### Impact Explanation
This breaks a repository-authorization boundary that Shipit's per-organization webhook secrets are meant to enforce: possessing a valid secret for organization A should never let you act as organization B's webhook. Depending on which event is replayed this way, an attacker tenant can trigger `GithubSyncJob`/`sync_github` on another organization's stack, forge commit statuses that CI/merge-queue logic relies on, or manipulate pull-request/review-stack state for repositories they do not own — i.e. cross-tenant writes reachable without any GitHub write access, `ApiClient` token, or session, satisfying the "cross-repository writes / unauthorized deploy" impact tier.

### Likelihood Explanation
Exploitation requires only that the deployment hosts more than one GitHub organization (a documented, supported configuration via `Shipit.github(organization:)`/`GithubOrganizationUnknown`), and that the attacker is an administrator of any one of those organizations able to configure/trigger a webhook delivery with an arbitrary body (which GitHub App webhook delivery UIs, or a custom `curl`, both allow since only the HMAC needs to match). No interaction with the victim organization is required.

### Recommendation
Verify the signature using the same value that is later trusted to resolve the target repository. Concretely, derive `repository_owner` (used for secret selection) and repository resolution from the *same* `repository.full_name` field, or explicitly assert `full_name.split('/').first == repository.owner.login` before processing, rejecting the webhook otherwise.

### Proof of Concept
1. Operate organization `attacker-org` inside a multi-tenant Shipit instance, with its own configured `webhook_secret`.
2. Craft a `push` event body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha existing in victim repo>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Sign the body with `attacker-org`'s webhook secret and send it to `POST /github/webhooks` with `X-Github-Event: push` and the matching `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s secret, and the signature matches → request is accepted.
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `sync_github(expected_head_sha: ...)` on `victim-org`'s stacks, even though the attacker never proved control of `victim-org`. [6](#0-5) [3](#0-2) [7](#0-6) [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
