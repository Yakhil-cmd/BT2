### Title
Cross-organization webhook signature verification does not bind the authenticated org to the repository/commit actually mutated - unauthorized cross-repository status writes and deploy triggering (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App/organization derived from `repository_owner` (`params.dig('repository','owner','login')` or `organization.login`), but several handlers — most notably `StatusHandler` — never re-check that the object they mutate (a `Commit`, found only by `sha`) actually belongs to the repository/organization whose secret validated the signature. This is analogous to the Backd bug where a value (`feeRatio`) that gates a later computation is never checked for consistency against another value (`minFeePercentage`) that can independently change: here, the "org that authenticated the request" and "the repository/commit that is written" are two different values that are never asserted equal.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` (L24-49) selects the webhook secret to validate the HMAC solely from `repository_owner`: [1](#0-0) [2](#0-1) 

This proves only that the payload was signed by *some* GitHub App installation configured for that org — Shipit supports multiple orgs each with independent `webhook_secret`s (see `test/dummy/config/secrets_double_github_app.yml`). Once verified, the raw JSON `params` are handed unchanged to every registered handler for the event: [3](#0-2) 

`StatusHandler#process` resolves the target purely from the globally-unique `sha` field of the payload, with no scoping to `payload['repository']`: [4](#0-3) 

`Commit.where(sha: params.sha)` searches across **every stack/repository tracked by this Shipit instance**, not just the repository named in the payload that was used to pick the verification secret. Compare this with `Handler#stacks`, which does correctly scope by `repository.full_name` for handlers like `PushHandler`/`CheckSuiteHandler`: [5](#0-4) 

Because `StatusHandler` skips that scoping, the binding that should hold — "the org whose secret validated the signature == the org/repository the write applies to" — is never enforced for status events.

`Commit#create_status_from_github!` writes an actual `Status` row and, through `add_status`, can flip the commit's aggregate `status` and directly triggers `stack.schedule_merges` and (via the `after_commit` callback graph) `schedule_continuous_delivery`, which gates `Commit#deployable?` and ultimately fires `ContinuousDeliveryJob`: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

### Impact Explanation
An attacker who controls (or can trigger events for) any repository under an organization that this Shipit instance has a valid GitHub App installation/webhook secret for — even a repository completely unrelated to Stack B — can forge or replay a `status` event whose `sha` collides with a real commit SHA tracked under a *different* organization's stack (Stack B), because `Commit.sha` lookups are global and unscoped by repository/org. The forged event passes `verify_signature` (it is legitimately signed by Org A's secret) yet writes a `Status` onto a commit belonging to Org B's `Stack`. If that commit's stack has `continuous_deployment?` enabled and depends on CI success (`stack.ignore_ci?` false), injecting a `success` status can make an otherwise-blocked commit `deployable?`, causing an **unauthorized deploy** to be scheduled on a stack the attacker never had any authorization over — a cross-repository, cross-organization write and potential unauthorized-deploy trigger, which maps directly to the "Critical: cross-repository writes / unauthorized deploy" impact bucket.

The likelihood of an exact SHA collision between two independent repositories is low in the general case (SHA1 is effectively unique across unrelated histories), which somewhat limits real-world exploitability, but the underlying access-control defect — no verification that `payload['repository']` matches the commit's actual stack/repository before mutating state — is real and directly analogous to the reported bug class (a value used for one authorization/gating check is silently allowed to diverge from the value the code actually operates on).

### Likelihood Explanation
Exploitation requires: (1) the attacker to control or trigger status/webhook delivery for a repository under some org configured in this Shipit instance (a realistic bar in multi-tenant/multi-org Shipit deployments, e.g. `secrets_double_github_app.yml`-style configs), and (2) a SHA collision or, more practically, a scenario where the same commit SHA legitimately exists in two different repos tracked by Shipit (e.g., forks, mirrors, or repos sharing history) — which is far more plausible than a genuine SHA1 collision and turns this into a concrete cross-repo status-spoofing vector for any Shipit deployment that tracks forks/mirrors of the same upstream commits under different `Repository`/`Stack` records.

### Recommendation
In `StatusHandler` (and any other handler that does DB lookups keyed only by a payload value like `sha`), scope the lookup to the repository named in the verified payload, analogous to how `Handler#stacks` already does for `PushHandler`/`CheckSuiteHandler`:
```ruby
def process
  Commit.joins(:stack).merge(stacks).where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
More generally, every handler should assert that `payload.dig('repository', 'full_name')` (the value implicitly trusted by `verify_signature`) matches the repository owning any record it mutates, rather than trusting globally-unique-looking identifiers (SHA, team id, etc.) alone.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own GitHub App/`webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Create `Stack` B tracking `OrgB/private-repo`, with `continuous_deployment: true` and status checks required (`ignore_ci?` false), containing a pending `Commit` with `sha = S` awaiting a required "ci/build" success status.
3. Create/mirror a repository `OrgA/decoy-repo` (attacker-controlled or with push access) so that a commit with the identical `sha = S` exists in `OrgA`'s history (e.g., via cherry-pick/fork with identical tree at that point, or a repo mirrored from the same upstream).
4. Trigger a GitHub `status` webhook for `OrgA/decoy-repo`'s commit `S` reporting `state: success`. GitHub signs this with `OrgA`'s legitimate `webhook_secret`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'OrgA')` from `repository.owner.login == 'OrgA'` and successfully verifies the signature.
6. `StatusHandler#process` runs `Commit.where(sha: 'S')`, which matches the commit belonging to `Stack` B under `OrgB`, and calls `create_status_from_github!`, writing a spoofed success status onto `OrgB`'s commit and triggering `schedule_continuous_delivery`, resulting in an unauthorized deploy of `Stack` B despite the attacker having no access to `OrgB` or its repository.

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
