### Title
Cross-repository Status forgery via organization/repository binding mismatch in webhook signature verification - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate an inbound webhook using the organization named in the payload's `repository.owner.login` (or `organization.login`), but the handler that actually acts on the payload (`StatusHandler`) trusts a completely different field — the commit `sha` — without ever checking that the `sha` belongs to the same repository/organization that was used to select the verification secret. The binding "organization whose secret authenticated the request" ≠ "repository/commit that is written to" is never enforced, closely mirroring the reported bug class where the index used to authorize a write differs from the index actually written.

### Finding Description
`verify_signature` computes the expected signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight out of the untrusted, attacker-supplied JSON body: [1](#0-0) [2](#0-1) 

Once the signature is verified for *that organization's* secret, `create` dispatches the entire raw payload to every registered handler for the event, with no re-binding of "verified organization" to what the handler actually touches: [3](#0-2) 

Most handlers scope themselves back to a repository via `Repository.from_github_repo_name(repository_name)`, using `payload.dig('repository', 'full_name')` — a field independent from the `owner.login` used to pick the verification secret: [4](#0-3) 

`StatusHandler`, however, does not scope by repository at all — it looks up **any** `Commit` row anywhere in the installation purely by `sha` and writes a GitHub-sourced status onto it: [5](#0-4) 

Because a Shipit installation can be configured with multiple GitHub Apps/organizations (`Shipit.github(organization: ...)`, `GithubOrganizationUnknown`), an attacker who legitimately possesses the webhook secret for *their own* onboarded organization (Org A) can:
1. Craft a `status` event body with `repository.owner.login = "OrgA"` (so `verify_signature` validates it against Org A's real, known secret) and `sha` equal to a commit SHA belonging to a stack tracked under an unrelated Org B.
2. Sign the raw body with Org A's secret and POST it directly to the shared `/webhooks` endpoint.
3. `verify_signature` succeeds (Org A's secret matches), and `StatusHandler#process` finds the `Commit` by `sha` regardless of which organization/repository it actually belongs to, and calls `commit.create_status_from_github!(params)`.

The write path that finally persists the status is `Commit#create_status_from_github!` → `add_status`, which feeds directly into deploy/merge decision logic: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

`deployable?` and `schedule_continuous_delivery` react directly to the forged status: a successful forged status can flip a commit to `deployable?`, and if the target stack has `continuous_deployment?` enabled it schedules `ContinuousDeliveryJob`, resulting in an **unauthorized deploy** of Org B's stack triggered entirely by Org A's webhook credentials.

### Impact Explanation
This breaks the binding "organization authenticated by webhook signature" == "repository/commit the payload's effects apply to." An attacker who legitimately controls one onboarded organization/repository in a multi-tenant Shipit deployment can forge CI status for any commit SHA in any other tracked repository, without ever compromising that other organization's GitHub App, webhook secret, or repository. Because status directly feeds `deployable?`/`blocked?`/`schedule_continuous_delivery`, this can trigger an unauthorized deploy for continuous-deployment-enabled stacks belonging to a repository the attacker does not own — matching the "unauthorized deploy" Critical-impact criterion.

### Likelihood Explanation
Requires the attacker to already be a legitimate, onboarded user of at least one organization configured on the Shipit instance (i.e., possess that organization's real webhook secret) — a real but bounded prerequisite in any multi-organization Shipit deployment (`config/shipit.yml` supporting multiple `github` app configs per organization, and `Shipit::GithubOrganizationUnknown` handling implies multiple orgs are expected). Given that prerequisite, forging the SHA and constructing a raw JSON body is trivial; no other secret (GitHub App private key, `webhook_secret` of the *target* org, `api_clients_secret`) is needed.

### Recommendation
- In `WebhooksController`, verify that the field used to select the verification secret (`repository_owner`/`organization.login`) matches the repository the handler will actually mutate (`repository.full_name`'s owner segment) before dispatching.
- In `StatusHandler` (and any other handler that resolves records purely by cross-repository-ambiguous fields such as `sha`), scope lookups through `stacks`/`Repository.from_github_repo_name(repository_name)` the same way `PushHandler`, `CheckSuiteHandler`, and the `PullRequest` handlers already do, instead of a global `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Onboard/attacker controls Org A on the Shipit instance and knows Org A's real webhook secret (`Shipit.github(organization: "OrgA")`).
2. Identify a commit `sha` on a stack belonging to Org B (public commit SHAs are easily discoverable).
3. Build payload:
```json
{
  "sha": "<Org-B-tracked-commit-sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/some-repo" }
}
```
4. Compute `X-Hub-Signature` using Org A's webhook secret over the raw JSON body, set `X-Github-Event: status`, and POST to `/webhooks`.
5. `verify_signature` passes because it is validated with Org A's secret. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) finds the `Commit` row for Org B's SHA irrespective of Org A/B mismatch and creates a successful status on it, which can flip `deployable?` true and trigger continuous delivery for Org B's stack.

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
