### Title
Signature verification binds trust to `repository.owner.login`/`organization.login`, but event processing acts on the unverified `repository.full_name` field, allowing cross-repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to use for HMAC verification based on `repository_owner`, a value derived from the payload's `repository.owner.login` (or `organization.login`) field. However, every webhook handler resolves the actual `Repository`/`Stack` to mutate using a *different* payload field, `repository.full_name`, via `Handler#repository_name`. Nothing ties these two fields together, so a correctly-signed payload for organization A can carry a `repository.full_name` pointing at organization B's stack.

### Finding Description
The controller computes the signing organization purely from attacker-supplied JSON: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: repository_owner)` looks up the configured `GithubApp`/webhook secret keyed by that owner login, and the HMAC is verified against `request.raw_post` (the whole body) using that org's secret. This only proves the request was signed with *some* organization's secret that happens to match the `repository.owner.login` value embedded in the same body — it says nothing about which repository the event is actually about, because `full_name` is never cross-checked against `owner.login`.

Every handler, however, resolves the stack to act on from `full_name`: [2](#0-1) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

Since `owner.login` (used for signing) and `full_name` (used for the actual DB lookup/action) are independent, unvalidated fields in the same JSON body, an attacker who legitimately controls a GitHub App/org configured in this Shipit instance (and therefore knows that org's `webhook_secret`) can craft a payload where `repository.owner.login = "org-they-control"` (to pass signature verification) but `repository.full_name = "victim-org/victim-repo"` (to target a stack they don't own). `PushHandler`, `PullRequest::*Handler`, `StatusHandler`, and `CheckSuiteHandler` all inherit this same `stacks`/`repository_name` resolution and will act on the victim's stack: [3](#0-2) 

This is the equality that should hold but does not:
`organization authenticated by verify_signature (repository.owner.login/organization.login)` == `organization implied by repository.full_name acted on by the handler`.

### Impact Explanation
Forging events against an arbitrary victim stack lets the attacker:
- Trigger `GithubSyncJob` on a victim stack (`PushHandler#process` → `stack.sync_github`), forcing re-sync from GitHub and writing commit history state for a repo the attacker doesn't control [3](#0-2) .
- Inject/forge `CommitStatus` records for the victim's commits via `StatusHandler`, which can gate or unblock CI-required deploy checks (`ci.require`) on the victim stack.
- Archive/unarchive review stacks and capture arbitrary PR labels for the victim's repository via `PullRequest::*Handler`s (e.g. `ClosedHandler#process` → `review_stack.archive!`, `ReopenedHandler#process` → `stack.unarchive!`) [4](#0-3) .

These are cross-repository writes into stack/commit/review-stack state that the attacker has no legitimate authorization over, satisfying the "cross-repository writes" Critical-impact bucket, since CI-status manipulation can directly gate/unblock an otherwise-unauthorized deploy.

### Likelihood Explanation
Exploitation requires the attacker to control at least one organization/GitHub App that is legitimately configured in this Shipit instance's `github:` secrets (so they know that org's `webhook_secret`) — this is a realistic scenario for any multi-tenant Shipit deployment serving several orgs/teams, since each org owner who set up their own GitHub App knows its `webhook_secret`. No repository write access, `ApiClient` token, or session is needed; only the ability to POST to the public `/webhooks` endpoint with a validly-signed-for-their-own-org body whose `repository.full_name` is swapped to the victim.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), validate that the `organization`/`repository.owner.login` used to select the verification secret matches the owner segment of `repository.full_name` before processing; reject the webhook (422) on mismatch. Alternatively, resolve the target `Repository`/`Stack` using the same verified `repository_owner` value rather than trusting `full_name` independently.

### Proof of Concept
1. Configure Shipit with two orgs, `attacker-org` and `victim-org`, each with its own GitHub App/`webhook_secret` (multi-tenant setup as supported by `config/secrets.development.shopify.yml`).
2. As the owner of `attacker-org`, compute a valid `sha1=` HMAC over a JSON body using `attacker-org`'s known `webhook_secret`, where the body is:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. POST this to `/webhooks` with header `X-Github-Event: push` and the computed `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies successfully against the attacker's own secret.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")`, matching the not-attacker-owned victim stack, and enqueues `GithubSyncJob` for it — demonstrating a cross-organization write despite the signature only proving control of `attacker-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```
