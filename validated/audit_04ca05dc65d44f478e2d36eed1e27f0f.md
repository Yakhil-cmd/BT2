### Title
Cross-organization/cross-repository commit status forgery via `sha`-only lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The `status` webhook handler resolves the target `Commit` purely by SHA, with no scoping to the repository/organization whose signature was verified for that request. This breaks the intended binding "organization that authenticated == repository that is written," letting an attacker who legitimately controls one GitHub organization/app installed on a multi-tenant Shipit instance forge commit statuses for commits belonging to a completely different organization/repository tracked by the same Shipit instance, as long as they know (or can predict/observe) a target commit SHA — which is public information on GitHub.

### Finding Description
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on a field taken directly from the untrusted payload itself (`repository.owner.login` or `organization.login`), not from any binding established at App configuration time for the specific target repo being modified: [1](#0-0) [2](#0-1) 

Once the signature check passes (using whatever org's secret matches `repository_owner` in the same attacker-controlled payload), the raw payload is dispatched to handlers without any further check that the "authenticated organization" and the entity actually mutated are the same: [3](#0-2) 

For most handlers (`PushHandler`, etc.) the base `Handler#stacks` correctly scopes lookups by `repository.full_name` from the same payload, so the authenticated org and the repository acted upon are the same object in the request: [4](#0-3) 

However `StatusHandler#process` does not use `repository_name`/`stacks` at all. It looks up commits **globally by SHA only**, with no repository or stack constraint: [5](#0-4) 

`Commit.where(sha: params.sha)` searches the entire `commits` table across every `Stack`/`Repository`/organization known to this Shipit instance. Because Shipit explicitly supports multiple GitHub organizations each with its own `webhook_secret` (documented in `docs/setup.md`), the "authenticating organization" (org A, whose secret validated this specific HTTP request) and the "repository being written to" (org B's commit, matched purely by SHA) are two independent values that the code never checks for equality — exactly the trust binding this task's rules call out ("an organization that authenticated versus the repository that is written").

`create_status_from_github!` then mutates commit state and fires downstream side effects that affect gating and continuous delivery: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

`deployable?` and `blocked?` (used to gate deploys/merges) and `schedule_continuous_delivery` (which triggers `ContinuousDeliveryJob` when a commit becomes `success?` and the stack is `continuous_deployment?`) are directly driven by injected status state: [10](#0-9) 

### Impact Explanation
An attacker who is a legitimate GitHub organization owner/installer of a Shipit-integrated GitHub App (i.e., controls org A and its `webhook_secret`, without any credential belonging to org B) can send a validly-signed `status` webhook for org A but with a `sha` value copied from a commit visible in org B's repository (SHAs are public via the GitHub UI/API for any repo the attacker can view, and for a public repo tracked by this Shipit instance no special access is required to learn a SHA). This forges a fake `success` status on org B's commit, which can flip `Commit#deployable?` to true and, when `stack.continuous_deployment?` is enabled, trigger an unauthorized automatic deploy of org B's stack via `schedule_continuous_delivery` → `ContinuousDeliveryJob`. This satisfies the "unauthorized deploy" impact bar defined for Critical findings.

### Likelihood Explanation
Requires the attacker to control at least one GitHub organization/app installation registered with the target multi-tenant Shipit instance (a realistic scenario for shared/hosted Shipit deployments serving multiple orgs), plus knowledge of a target commit SHA in another tracked repository (trivially obtainable for public repos, or via any other webhook/API leakage for private ones). No repository write access, API token, or session is needed — only the ability to send an HTTP POST with a validly-signed webhook body for an organization the attacker legitimately administers.

### Recommendation
Scope `StatusHandler#process` (and any other handler relying on cross-cutting global lookups) to the repository identified in the same payload, mirroring `Handler#stacks`/`repository_name`, e.g. restrict the `Commit` lookup to `stacks.map(&:commits)` or join through `Repository.from_github_repo_name(repository_name)` before matching by SHA, so a commit can only be updated by a webhook whose verified signature corresponds to the same repository/organization that owns that commit.

### Proof of Concept
1. Shipit is configured with two GitHub organizations, `org-a` and `org-b`, each with its own `github.webhook_secret` (per the multi-org config documented in `docs/setup.md`), each with stacks/repositories tracked.
2. Attacker legitimately controls `org-a`'s GitHub App installation and therefore knows `org-a`'s `webhook_secret`.
3. Attacker observes (publicly, or via any other means) a commit SHA `deadbeef...` belonging to a commit tracked under an `org-b` stack.
4. Attacker crafts a `status` event payload:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-a/some-repo" },
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/tests"
}
```
5. Attacker computes `X-Hub-Signature` using `org-a`'s known `webhook_secret` and POSTs to `/webhooks` with `X-Github-Event: status`.
6. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` and verifies successfully because the signature matches `org-a`'s secret — see `app/controllers/shipit/webhooks_controller.rb:24-30`.
7. `StatusHandler#process` executes `Commit.where(sha: params.sha)` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), which matches the `org-b` commit regardless of the fact the request was authenticated only for `org-a`, and calls `commit.create_status_from_github!(params)`, forging a `success` status on `org-b`'s commit.
8. If `org-b`'s stack has continuous deployment enabled, `Commit#schedule_continuous_delivery` (`app/models/shipit/commit.rb:281-287`) enqueues `ContinuousDeliveryJob`, resulting in an unauthorized deploy triggered entirely by an actor with no relationship to `org-b`.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
