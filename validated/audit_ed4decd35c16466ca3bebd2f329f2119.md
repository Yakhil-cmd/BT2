### Title
Cross-Repository Status Forgery Bypasses CI Gating for Unauthorized Deploys - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The reported bug class is that an untrusted, but nominally "authenticated," party can supply a value that is used to control a security-critical decision without that value being bound to the identity that was actually verified. In `shipit-engine`, GitHub webhook signatures are verified per-organization, and the organization used for verification is picked from an attacker-controlled payload field. The `status` webhook handler then acts on a completely different field (`sha`) with no scoping check to the verified organization/repository, letting one legitimately-configured (but unprivileged relative to the target) GitHub organization forge a CI status for a commit belonging to any other stack in the same Shipit instance, bypassing CI gating and triggering an unauthorized deploy.

### Finding Description
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification from a field inside the very payload being verified: [1](#0-0) 

`repository_owner` is `params.dig('repository', 'owner', 'login')` (or `organization.login`) — both attacker-controlled fields inside the JSON body. This is fine as a way to pick *which* secret to check, as long as the org whose secret validated the request is later cross-checked against whatever resource the payload claims to affect.

That cross-check is missing for the `status` event. `Shipit::Webhooks::Handlers::StatusHandler#process` ignores the `repository` field entirely and updates commits by a **global** SHA lookup: [2](#0-1) 

Unlike other handlers (`PushHandler`, `MembershipHandler`, etc.) which resolve `stacks` via `Handler#repository_name`/`Handler#stacks` (`Repository.from_github_repo_name(repository_name)`), `StatusHandler` never calls `stacks` and never checks that the commit it mutates belongs to a stack owned by the verified organization: [3](#0-2) .

The status is then persisted and immediately feeds CI gating logic: [4](#0-3) [5](#0-4) [6](#0-5) 

And a new "success" status on a previously-blocked commit schedules continuous delivery for that commit's *actual* stack: [7](#0-6) [8](#0-7) 

**The broken binding, as an equality:**

- Before the attack: `verified_organization (from repository.owner.login, secret known to attacker) == repository.owner.login (payload claim)`, and this is assumed by the code to imply `verified_organization == owner_of(stack_that_gets_written)`.
- After the attack: `verified_organization` is the attacker's own onboarded org (whose `webhook_secret` they legitimately know), but `stack_that_gets_written` is determined solely by `Commit.where(sha: params.sha)`, which can match a commit belonging to a **completely different** stack/repository/organization.

Multi-organization configuration (each org with its own independent `webhook_secret`) is a documented, first-class deployment model: [9](#0-8) . Any team that has its own GitHub org/repo onboarded into a shared Shipit instance therefore possesses a valid webhook secret it can use to sign arbitrary payloads, while `StatusHandler` provides no repository ownership check to keep that trust scoped to its own repositories.

### Impact Explanation
This is a cross-repository write with an unauthorized-deploy outcome, both explicitly listed as Critical/High impacts. An attacker who legitimately controls one onboarded (low-privilege) GitHub organization/repository in a shared Shipit deployment can:
1. Discover the SHA of a commit sitting in another, unrelated stack that is currently blocked on CI (SHAs are not secret — visible on GitHub, on the Shipit UI, or via the API).
2. Send a `status` webhook, signed with their own org's `webhook_secret` (which passes `verify_signature` because that org is legitimately configured), with `sha` set to the victim commit's SHA, `context` matching the victim stack's `ci.require` context, and `state: success`.
3. `StatusHandler` writes this forged status onto the victim's commit with no ownership check, `Commit#deployable?` now evaluates true, and `schedule_continuous_delivery` enqueues `ContinuousDeliveryJob`, resulting in an unauthorized deploy of the victim stack.

### Likelihood Explanation
The prerequisite is only that the attacker controls any organization/repository that is legitimately configured in the same Shipit instance — not a privileged Shipit account, `ApiClient` token, or GitHub App private key for the *victim* repository. Multi-tenant Shipit deployments (shared instance serving many teams/orgs, each with independent GitHub Apps/webhook secrets, as shown in the documented config format) are common, making this reachable without any social engineering or host misconfiguration.

### Recommendation
In `StatusHandler#process` (and any other handler that mutates state keyed only by an attacker-suppliable identifier such as `sha`), scope the lookup to the repository/stacks owned by the organization whose secret validated the signature, e.g. `stacks.commits.where(sha: params.sha)` using the same `Handler#repository_name`/`Handler#stacks` resolution the other handlers already use, and additionally verify that `repository_owner` from `WebhooksController#verify_signature` matches the repository actually referenced by the payload before dispatching to handlers.

### Proof of Concept
1. Attacker legitimately owns `github.com/attacker-org/attacker-repo`, which is configured in Shipit's `secrets.yml` with its own `webhook_secret` (`S_attacker`), as supported by the documented multi-org config format.
2. Attacker learns the SHA of a currently CI-blocked commit `deadbeef...` on `victim-org/victim-repo`'s tracked stack (public info via GitHub/Shipit UI).
3. Attacker POSTs to `/webhooks` (`X-Github-Event: status`) with body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/required-check",
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/attacker-repo"}
}
```
signed with `X-Hub-Signature: sha1=HMAC(S_attacker, raw_body)`.
4. `verify_signature` resolves `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and verification succeeds because the attacker legitimately knows `S_attacker`.
5. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")` — matching the victim's commit regardless of the `repository` field — and calls `create_status_from_github!`, marking the victim's commit `success`.
6. If this clears the victim stack's remaining blocking statuses, `schedule_continuous_delivery` enqueues `ContinuousDeliveryJob`, deploying the victim stack based on a forged status the attacker never had legitimate rights to set.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
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
