### Title
Webhook signature is verified against `repository.owner.login`, but the repository/stack acted upon is selected from the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/webhook secret to validate the HMAC using `repository_owner`, which is read from the same untrusted JSON body (`params.dig('repository','owner','login')`), while every event handler (`PushHandler`, `PullRequest::OpenedHandler`, etc.) resolves the `Repository`/`Stack` to act on using a *different* field of that same body, `repository.full_name`. Nothing binds these two fields together.

### Finding Description
`verify_signature` computes the signing organization solely from the payload itself: [1](#0-0) [2](#0-1) 

Meanwhile, every handler determines which `Repository`/`Stack` a webhook event applies to via `repository_name = payload.dig('repository', 'full_name')`: [3](#0-2) 
and e.g. the push handler that triggers `stack.sync_github`: [4](#0-3) 

In Shipit's documented multi-organization mode, each GitHub organization that installs the app gets its own `webhook_secret`, keyed by organization name in `secrets.github`: [5](#0-4) 

The equality that should hold is: `organization that authenticated the payload == owner of the repository being written to`. In this code, the "authenticated" side is `repository.owner.login`, while the "written to" side is derived from `repository.full_name` — two independent, attacker-influenced fields inside the same raw body that are never cross-checked against each other. An unprivileged attacker who legitimately controls their own low-privilege GitHub organization (and therefore genuinely knows that organization's real `webhook_secret`, because they configured it themselves in their own GitHub App settings) can craft a POST to `/webhooks` where `repository.owner.login` = their own org (so the HMAC validates using their own legitimate secret) but `repository.full_name` = `"victim-org/victim-repo"`. The signature check passes because it only validates against the attacker's own secret; the handler then resolves and acts on `victim-org/victim-repo`'s `Stack` regardless.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope. Concretely, an attacker owning their own trivial organization can forge push/pull_request/status/check_suite/membership events that Shipit will process as if genuinely originating from a victim organization's repository, causing `PushHandler` to invoke `stack.sync_github(expected_head_sha: ...)` on the victim stack, `PullRequest::OpenedHandler`/`ReopenedHandler` to provision or unarchive victim review stacks, and label handlers to archive/unarchive victim environments — all without ever possessing the victim's real webhook secret or repository access. Depending on `continuous_deployment` settings on the victim stack, syncing arbitrary attacker-chosen `expected_head_sha`/commits into the victim's commit history can influence which commit is considered deployable, moving toward an unauthorized deploy trigger.

### Likelihood Explanation
Requires only that the attacker legitimately controls at least one organization with the Shipit GitHub App installed (a normal, unprivileged, self-service action on any multi-tenant Shipit deployment) and can craft an arbitrary raw HTTP POST — no compromise of the victim's secret, no repository write access to the victim's repo, and no privileged Shipit account are needed. The mismatch is purely a missing internal consistency check between two fields of an already-authenticated-but-mis-scoped payload.

### Recommendation
In `WebhooksController#verify_signature`, after establishing the authenticating organization, assert that `repository.full_name`'s owner segment (and/or `organization.login` for org-level events) matches `repository_owner`/the resolved `GitHubApp#organization`, rejecting the webhook (422) on mismatch before dispatching to any handler. Alternatively, have each handler validate that the `Repository` it resolves via `full_name` belongs to the same organization that was used to authenticate the request.

### Proof of Concept
Assume Shipit is configured in multi-org mode with orgs `attacker-org` (secret `S_A`, attacker's own legitimate GitHub App installation) and `victim-org` (secret `S_V`, hosts the target stack).

1. Attacker builds a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, raw_body)>` using their own known `S_A`.
3. POST to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, calls `Shipit.github(organization: "attacker-org")`, verifies HMAC with `S_A` → succeeds (this is genuinely valid for the attacker's own org).
5. `PushHandler#process` resolves `repository_name` from `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`, looks up the real victim `Repository`/`Stack`, and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on it — an event the attacker was never authorized to send for that repository. [6](#0-5) [3](#0-2) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
