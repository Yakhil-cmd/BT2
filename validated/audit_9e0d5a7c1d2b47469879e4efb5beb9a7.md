### Title
Webhook signature is verified against `repository.owner.login` while event handlers act on the independent `repository.full_name` field, allowing cross-organization/cross-repository writes with a validly-signed payload - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC signature against using `repository.owner.login` (or `organization.login`) pulled from the JSON body. However, every event `Handler` (e.g. `PushHandler`, `pull_request/*Handler`) resolves the `Repository`/`Stack` to act on using a *different* field of the same body, `repository.full_name`. These two fields are never checked for consistency with each other.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

The organization used to pick the verifying secret is `repository.owner.login`. But `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name` — the base class every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `PullRequest::*Handler`) relies on to look up the target `Repository`/`Stack` — uses `repository.full_name` instead:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`repository.owner.login` and `repository.full_name` are two independently attacker-controlled JSON fields inside the same signed request body — the HMAC covers the whole raw body's bytes, but nothing in the application enforces that `full_name` is prefixed by `owner.login`. An attacker who controls (or is a legitimate member of) an organization "attacker-org" that has its own Shipit GitHub App installation/webhook secret can compute a valid signature for a payload where `repository.owner.login = "attacker-org"` (so `Shipit.github(organization: "attacker-org")` resolves to the app whose secret they know and signature verification passes) while setting `repository.full_name = "victim-org/victim-repo"`. The handler layer then looks up and acts on `victim-org/victim-repo`'s `Stack`, breaking the equality that should hold: *organization whose credential authenticated the request == repository that is written*.

### Impact Explanation
Depending on which event is spoofed against a stack belonging to another repository/organization configured on the same Shipit instance, this can:
- Trigger `PushHandler` → `stack.sync_github(expected_head_sha:)` on an arbitrary victim stack, forcing an out-of-band GitHub resync.
- Trigger `StatusHandler` to write forged commit statuses (`commit.statuses`) on a victim stack's commits, which can make CI-gated deploy checks (`ci.require`) appear green, enabling an unauthorized deploy path for a stack that continuous deployment or the merge queue is watching.
- Trigger `pull_request/*Handler`s (`opened_handler`, `labeled_handler`, `closed_handler`, `reopened_handler`) to archive/unarchive or (de)provision review stacks belonging to a different repository than the authenticating organization, i.e., cross-repository writes performed by an org that was never granted permission over that repository.

This matches the "High" bar of "escalation ... unauthenticated write / cross-repository writes / unauthorized deploy" via a broken deployment-trust binding (organization authenticated ≠ repository written), reachable by any party that operates their own legitimately configured GitHub App organization on the same Shipit deployment — no session, `ApiClient` token, or leaked secret required, only their own valid webhook secret for their own org.

### Likelihood Explanation
Exploitability requires:
1. A multi-tenant/multi-organization Shipit deployment (supported natively via the `github: { org1: {...}, org2: {...} }` config shown in `config/secrets.development.shopify.yml`) where the attacker's own organization is one of the configured orgs.
2. The attacker is able to compute a valid HMAC for their own org's webhook secret (trivial — they control that org's GitHub App and can trigger/observe real deliveries, or simply have configured it themselves).
3. The victim stack/repository exists in the same Shipit installation.

Given multi-org support is a documented, intended configuration and no cross-field validation exists anywhere in `WebhooksController` or `Handler`, likelihood is Medium-to-High in any shared/multi-tenant Shipit deployment.

### Recommendation
Enforce that the organization used to select the verifying GitHub App/secret matches the organization prefix of `repository.full_name` (and `organization.login`) before dispatching to handlers — i.e., derive a single canonical "owning organization" for the payload and use it consistently for both signature verification and repository/stack resolution. Reject the webhook if the two disagree.

### Proof of Concept
1. Configure Shipit for two organizations, `attacker-org` and `victim-org`, each with the GitHub App installed and its own `webhook_secret` (a supported, documented multi-org configuration).
2. As a member/owner of `attacker-org`, craft a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over the raw JSON body (this is fully within the attacker's capability since it's their own org's secret).
4. POST the body with headers `X-Github-Event: push` and the computed `X-Hub-Signature` to `/webhooks`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature.
6. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` (via `Handler#repository_name`) and triggers `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack, even though the request was authenticated only for `attacker-org`. [3](#0-2)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L26-38)
```ruby
        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
