## Title
Cross-organization webhook signature confusion allows spoofed commit statuses and unauthorized deploys via unscoped `StatusHandler` — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: lib/shipit/github_app.rb])

### Summary
`WebhooksController` selects which GitHub App/organization's HMAC secret to verify a webhook against using an attacker-supplied field of the *same unverified request body* that is later used to decide what gets written. `StatusHandler`, which processes GitHub `status` webhooks, then updates commit state by a bare `sha` lookup across the *entire* `Commit` table, with no scoping to the repository/organization that was actually verified. This is the same class of bug as the reported `_removeOrder()` issue: an operation (write) is performed on a target that the verification step never actually pinned down — the "authenticated organization" and "the repository/commit that gets written" are two different bindings that are never checked for equality.

### Finding Description
`WebhooksController#verify_signature` picks the HMAC secret to check based on `repository_owner`, extracted straight from the unverified JSON payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization config (see the documented multi-org schema, where `webhook_secret` is explicitly optional/`nil` per organization) via `GithubApp#verify_webhook_signature`: [3](#0-2) 

Critically, `return true unless webhook_secret` means **any organization configured without a `webhook_secret` makes signature verification a no-op for requests claiming that organization**, regardless of the actual HMAC header sent. This is a documented, expected configuration state, not a misconfiguration: [4](#0-3) 

Once `verify_signature` passes (using the attacker-chosen, secret-less `repository_owner`), `WebhooksController#create` dispatches the raw JSON body to handlers: [5](#0-4) 

For `status` events, `StatusHandler#process` looks up commits **only by `sha`**, with no repository/organization scoping at all — it doesn't even use the `stacks` helper that other handlers (e.g. `PushHandler`) use to scope to the resolved repository: [6](#0-5) 

Compare with `PushHandler`, which at least scopes to `Repository.from_github_repo_name(payload.dig('repository','full_name'))`-derived stacks: [7](#0-6) [8](#0-7) 

`StatusHandler` has no such scoping. The binding that is broken as an equality is:

`organization verified by signature check (repository_owner from unverified payload)` ≠ `repository/commit actually written (any Commit row matching an attacker-known sha, across all stacks/orgs in the Shipit instance)`.

Before the attacker's request: a commit `sha` belonging to Stack B (a different, properly-secured org) has no `success` status for the CI context that gates deploy. After the attacker's request: a forged `status` webhook — signed (trivially, since no secret is required) as organization A, which has no `webhook_secret` configured — sets `state: 'success'` on that same `sha` belonging to Stack B via the global `Commit.where(sha:)` lookup.

### Impact Explanation
Setting a commit's CI status to `success` can directly trigger an unauthorized deploy on any stack in the instance that has `continuous_deployment: true`, since successful/deployable commit statuses drive the continuous-delivery trigger path: [9](#0-8) [10](#0-9) 

This satisfies the "Critical" impact bucket explicitly listed in scope: an unauthorized deploy triggered by a webhook request that never had to pass a real signature check for the organization whose commit/stack is actually affected.

### Likelihood Explanation
The webhook endpoint is public/unauthenticated by design (it only relies on HMAC signature verification), so any external, unprivileged attacker can POST to it. The only precondition is that at least one organization/app configured in `Shipit.github` (multi-org setups are a first-class, documented feature) lacks a `webhook_secret` — a state the setup docs treat as normal/optional, not exceptional. Given that precondition, forging a `status` event that references a known commit `sha` from a target stack requires no secret knowledge at all, because the `sha` itself is public (visible on GitHub, in PRs, and in the Shipit UI). The `StatusHandler` lookup is unconditionally global, so no additional bypass or timing is needed.

### Recommendation
- In `StatusHandler#process`, scope the `Commit` lookup to the repository resolved from the payload (as `PushHandler` does via `stacks`), and additionally verify that the resolved repository's owning organization matches the organization whose secret was used to verify the request signature.
- In `WebhooksController#verify_signature`, after establishing which `github_app`/organization verified the signature, cross-check that `repository_owner` (used to select the secret) is the actual, expected owner for the repository being mutated by the handler — i.e., don't let two different fields of the same unverified/partially-verified payload silently diverge in what they authorize vs. what they let handlers act on.
- Consider rejecting requests entirely (rather than treating them as "verified") when an organization has no `webhook_secret` configured, or require an explicit secret for any organization enabled for continuous deployment.

### Proof of Concept
1. Configure Shipit with two organizations: `orgA` (no `webhook_secret` set) and `orgB` (has stacks with `continuous_deployment: true`, secured with a real `webhook_secret`).
2. As an unauthenticated external attacker, obtain a known commit `sha` for a stack in `orgB` (e.g., from the public Shipit commit page or GitHub).
3. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<orgB-target-sha>",
  "state": "success",
  "context": "ci/travis",
  "repository": { "owner": { "login": "orgA" } }
}
```
No valid `X-Hub-Signature` is required, because `verify_webhook_signature` short-circuits to `true` for `orgA` per `lib/shipit/github_app.rb:76-77` (no `webhook_secret` configured for `orgA`).
4. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) matches the commit purely by `sha`, ignoring `orgA` vs `orgB`, and creates a `success` status on the `orgB` commit.
5. If `orgB`'s stack has `continuous_deployment: true` and this satisfies its deploy gating, `ContinuousDeliveryJob`/`Stack#trigger_continuous_delivery` triggers an unauthorized deploy (`app/models/shipit/stack.rb:210-228`).

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/stack.rb (L210-228)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
```

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```
