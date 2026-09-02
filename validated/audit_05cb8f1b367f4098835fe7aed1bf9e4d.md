### Title
Cross-organization status forgery bypasses organization/repository binding, enabling unauthorized continuous deployment - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook by looking up the GitHub App secret keyed on the **organization** embedded in the payload (`repository.owner.login`, falling back to `organization.login`), via `repository_owner`. Once the HMAC check passes, `Shipit::Webhooks::Handlers::StatusHandler#process` acts on the payload using only the commit `sha` — with **no repository/organization scoping at all** — matching `Commit.where(sha: params.sha)` across the entire database. This breaks the binding "organization that authenticated == repository that is written": any org onboarded to a shared/multi-tenant Shipit instance can forge a `status` event, sign it with its own legitimate webhook secret, and have it applied to a commit belonging to a completely different organization's stack.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

This selects which org's `webhook_secret` is used to verify the *whole raw body*, based on a field the requester fully controls at the moment they craft the payload for their own org's App. The signature only proves "this body was HMAC-signed with OrgX's secret" — it says nothing about which repository/commit the body's other fields describe.

The `status` handler that then runs is:
```ruby
class StatusHandler < Handler
  params do
    requires :sha, String
    requires :state, String
    ...
  end
  def process
    Commit.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
``` [2](#0-1) 

Unlike the other handlers (`PushHandler`, `PullRequest::*Handler`), `StatusHandler` never scopes the lookup by `Handler#repository_name`/`payload.dig('repository','full_name')` — it queries `Commit` globally by `sha` alone, and applies the attacker-supplied `state`/`description`/`context` to whatever stack owns that commit, regardless of which organization the request was authenticated as.

`Commit#create_status_from_github!` → `add_status` creates a `Status`, which triggers:
```ruby
after_create :enable_ci_on_stack
after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
``` [3](#0-2) 
and in `Commit#add_status`:
```ruby
stack.schedule_merges if new_status.pending? || new_status.success?
``` [4](#0-3) 

For any stack with `continuous_deployment: true`, a forged `success` status on the victim's latest commit schedules continuous delivery, which (per `Stack#continuous_delivery_delayed?`/`trigger_continuous_delivery`) can result in `trigger_deploy` being invoked and a deploy being enqueued/run for a repository the attacker does not own and never authenticated against.

### Impact Explanation
This is an **unauthorized deploy**: an attacker who legitimately administers *any* GitHub App/organization configured on a shared Shipit installation (knows only their own `webhook_secret`, not the victim's) can forge a `status` webhook that is verified against their own org's secret but is applied to a victim organization's commit purely by guessing/observing its `sha` (commit SHAs are not secret — they are visible via GitHub UI, CI badges, PR pages, `git log`, etc.). This can flip CI/deployability state and trigger continuous deployment for a stack belonging to a different, unrelated organization — a cross-repository/cross-organization write and an unauthorized deploy, matching the Critical impact bucket.

### Likelihood Explanation
Requires the attacker to control (own) at least one GitHub App/org already configured in `Shipit.github(organization: ...)` for the target Shipit instance (a realistic scenario for any Shipit deployment serving multiple orgs/teams), plus knowledge of a victim commit `sha` for a stack with `continuous_deployment: true` — both readily obtainable without any privileged Shipit credential, `ApiClient` token, or the victim's secrets. No social engineering, TLS interception, or host misconfiguration is needed; it exploits the engine's own authorization binding (org-scoped signature vs. global, unscoped handler action).

### Recommendation
Scope `StatusHandler` (and any other handler that doesn't already do so) to the repository identified in the payload, consistent with `Handler#stacks`/`repository_name`, e.g. restrict the `Commit` lookup to commits whose `stack.repository == Repository.from_github_repo_name(payload.dig('repository','full_name'))`, and verify that this repository belongs to the same organization (`repository_owner`) used to select the signing secret in `WebhooksController#verify_signature`. More generally, enforce that the organization used to verify the signature matches the owner of the repository being mutated for every handler.

### Proof of Concept
1. Attacker operates `OrgA`, a legitimate GitHub App/org configured in this shared Shipit instance with its own known `webhook_secret`.
2. Attacker discovers the commit `sha` of the latest commit on `OrgB/victim-repo`'s continuously-deployed stack (public info via GitHub).
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/attacker-repo" }
}
```
4. Attacker computes `X-Hub-Signature` using `OrgA`'s own `webhook_secret` over this raw body and POSTs it to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` to `"OrgA"`, verifies successfully against `OrgA`'s secret.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matching the commit that actually belongs to `OrgB/victim-repo`, and creates a `success` `Status` on it — unrelated to `OrgA` at all.
7. If `OrgB`'s stack has `continuous_deployment: true`, `Status`'s `after_commit :schedule_continuous_delivery` callback fires, potentially triggering an unauthorized deploy of `OrgB`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
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
end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
