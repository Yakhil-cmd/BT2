### Title
Cross-repository CI status forgery via unscoped `sha` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The GitHub `status` webhook is authenticated per-organization (the HMAC secret used to verify the payload is selected via `params.dig('repository','owner','login')`), but the handler that processes the event resolves the target `Commit` purely by `sha`, with no check that the commit belongs to the same repository/organization that authenticated the request.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to verify the payload with based on the organization named inside the payload itself (`repository_owner`), then dispatches the (now "authenticated for that org") payload to the matching handler: [1](#0-0) 

`StatusHandler#process`, however, looks up commits to update using only the `sha` field from the payload, globally across the entire `Commit` table, with no scoping to `repository_name`/`stacks` (unlike `PushHandler`, which does scope through `stacks.where(branch:)`): [2](#0-1) [3](#0-2) 

This breaks the binding: `organization that authenticated == repository that is written`. Any organization/repository already onboarded onto the Shipit instance (i.e., any tenant with a configured GitHub App/webhook for their own, possibly low-trust or open-source, repository) can deliver a validly-signed `status` event carrying an arbitrary `sha`. `Commit.where(sha: params.sha)` will match that sha in **any** repository/stack tracked by the instance, and `commit.create_status_from_github!(params)` will write attacker-controlled status state/description/target_url onto that unrelated commit: [4](#0-3) 

If the sha coincides with a commit tracked under a different, unrelated stack (e.g., a fork/cherry-pick sharing history, a well-known empty-tree/no-op commit hash, or any commit whose sha the attacker can predict/observe), the forged "success" status can flip that commit's `deployable?` and trigger continuous delivery on someone else's stack: [5](#0-4) [6](#0-5) 

### Impact Explanation
This is a cross-repository write: a tenant that only authenticates as the owner of Repository A can write CI status data attached to a commit under Repository B's stack, and in the continuous-deployment case can trigger an unauthorized deploy of Repository B by manufacturing a passing status for a shared/guessed sha. This matches the Critical impact bucket "cross-repository writes ... or an unauthorized deploy."

### Likelihood Explanation
Exploitation requires the attacker to control (or be a collaborator on) at least one repository already onboarded to the same multi-tenant Shipit instance, which is a realistic "unprivileged relative to the rest of the fleet" position, and to find/produce a `sha` collision with a commit in the target stack (e.g. two repos sharing history, submodule/fork relationships, or a commonly reused base commit such as an initial empty commit). This narrows real-world likelihood, but the underlying missing scope check is a genuine root-cause defect independent of how easy sha collision is to engineer.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository identified in the authenticated payload, mirroring `PushHandler`'s use of `stacks`/`repository_name`, e.g. restrict to `stacks.map(&:commits)` or filter by `stack.repository == Repository.from_github_repo_name(repository_name)` before calling `create_status_from_github!`.

### Proof of Concept
1. Onboard Repository A (attacker-controlled or low-trust open-source repo) into the shared Shipit instance with a valid GitHub App/webhook secret.
2. Identify or arrange a commit sha that also exists as a tracked `Commit` under victim Stack B (e.g., both repos share a common ancestor commit, or B's earliest commit sha is well known/predictable).
3. From Repository A's GitHub, POST (or have GitHub deliver) a `status` event with `sha` = the shared/target sha and `state: "success"`, correctly signed with A's webhook secret.
4. `WebhooksController#verify_signature` validates the signature using Org A's secret and passes.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matching the commit under Stack B, and calls `create_status_from_github!`, writing a forged success status onto B's commit and potentially triggering `schedule_continuous_delivery` for Stack B.

### Citations

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
