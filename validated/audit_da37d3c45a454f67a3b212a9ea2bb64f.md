### Title
Cross-organization webhook forgery: verified signature binds to the wrong organization, allowing status/CI spoofing across repositories — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit verifies inbound GitHub webhooks using an HMAC secret selected from a field inside the *unverified* JSON body, but the handlers that actually act on the payload (creating commit statuses, syncing stacks) trust a *different* field of that same unverified body to decide which repository/stack to mutate. An attacker who legitimately owns any GitHub organization/App installation that talks to the same Shipit instance can therefore sign a forged webhook with their own (valid) secret while making the payload claim to be about a completely different, victim organization's repository and commit.

### Finding Description
`WebhooksController#verify_signature` picks which `GithubApp`/secret to verify against solely from the payload itself: [1](#0-0) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This means the "authenticated organization" is whatever `repository.owner.login`/`organization.login` says in the JSON body — a field that is itself covered by the HMAC only in the trivial sense that the attacker controls both the field and the secret used to sign it, since they own that organization's GitHub App installation (a normal, unprivileged configuration per `docs/setup.md`, "Installing the GitHub App on your organization").

Once `verify_signature` passes, `create` hands the *entire* raw payload to the event handlers: [2](#0-1) 

Handlers such as `StatusHandler` and `PushHandler` never re-check that the repository they act on matches the organization that was actually authenticated: [3](#0-2) 

```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

`Commit.where(sha:)` is a global lookup across *all* repositories tracked by the Shipit instance — there is no scoping to the organization whose secret was verified. Likewise `PushHandler` resolves target stacks via the payload's `repository`/`branch` fields: [4](#0-3) 

The binding that should hold is: `organization authenticated by verify_signature == organization that owns the repository/commit the handler mutates`. That equality is never enforced. Before the attacker's request: victim commit's CI/status state reflects real GitHub CI. After: attacker (who only controls their own unrelated org/app installation) submits a `status` event with `sha` = a real, publicly-known commit SHA belonging to the victim's repository and `state` = `success`, signed with their own org's webhook secret. The signature check passes (`repository_owner` = attacker's org), and `StatusHandler` writes a synthetic "success" `CommitStatus` onto the victim's commit regardless of which org's repo it belongs to.

### Impact Explanation
Because `Commit#deployable?` (used to gate `require_ci` deploys, see `app/controllers/shipit/api/deploys_controller.rb`) and CI status displayed in the UI both rely on these `CommitStatus` records, an attacker with no privileges on the victim repository/stack can forge a green CI status for an arbitrary commit and cause it to be treated as deployable, or spoof `push`/`check_suite` events to trigger syncs and status changes on stacks they have no access to. This breaks the "organization authenticated vs. repository written" trust boundary and can enable an unauthorized deploy of a commit that never actually passed CI on the real repository — matching the Critical-impact category "unauthorized deploy" in the given rules.

### Likelihood Explanation
Any user capable of creating/installing a GitHub App or organization webhook pointed at the shared Shipit `/webhooks` endpoint (a normal, documented, unprivileged setup step) can exploit this with a single crafted HTTP POST; no access to the victim's repository, GitHub token, or Shipit session/API token is required. Commit SHAs for public repositories are trivially discoverable.

### Recommendation
After `verify_signature` succeeds, re-derive the organization/repository the payload claims to reference (e.g., `repository.full_name`, `organization.login`) and reject or ignore the event unless it matches the organization whose secret was actually used to verify the signature. Scope `StatusHandler`'s `Commit.where(sha:)` (and `PushHandler`'s stack lookup) to commits/stacks whose `Repository` belongs to the verified organization, not merely to a SHA/branch match across the whole instance.

### Proof of Concept
1. Attacker installs the shared Shipit GitHub App on their own org `attacker-org`, obtaining a valid webhook secret for it (documented setup step, no victim access needed).
2. Attacker finds a public commit SHA `deadbeef...` belonging to victim stack `victim-org/victim-repo`.
3. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/forged",
  "repository": {"owner": {"login": "attacker-org"}},
  "organization": {"login": "attacker-org"}
}
```
   signed with `attacker-org`'s webhook secret via `X-Hub-Signature`.
4. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and the signature checks out.
5. `StatusHandler#process` runs `Commit.where(sha: 'deadbeef...')` — matching the victim's commit globally — and calls `create_status_from_github!`, writing a forged "success" status onto a commit the attacker never had access to.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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
