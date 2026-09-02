### Title
Cross-organization commit-status forgery via `StatusHandler`'s unscoped `sha` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate an inbound webhook using the *authenticating* organization derived from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) [2](#0-1) . Once the signature is valid for that organization's GitHub App secret, the raw JSON body is dispatched unchanged to event handlers [3](#0-2) . `StatusHandler#process`, however, resolves the target purely by commit SHA, globally, with no scoping to the repository/organization that was actually authenticated: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) . This breaks the intended binding "organization that authenticated == repository that is written," letting an admin of *any* Shipit-onboarded organization (org A) forge deployability-affecting commit statuses on commits belonging to a completely unrelated organization's stacks (org B), as long as they happen to share a SHA value (or the attacker can predict/observe one, e.g. via a fork or via GitHub commit ID collisions across mirrored history).

### Finding Description
- `verify_signature` picks the webhook-secret owner solely from the `repository.owner.login` (or `organization.login`) field of the JSON payload and uses that organization's configured `webhook_secret` for HMAC validation [1](#0-0) .
- After a valid signature, `WebhooksController#create` forwards the parsed JSON straight to `Shipit::Webhooks.for_event(event)` handlers with no re-check that the "repository" the handler will act on matches the organization whose secret validated the request [3](#0-2) .
- Most handlers use `Handler#stacks`, which is scoped by `payload.dig('repository', 'full_name')` looked up via `Repository.from_github_repo_name` [5](#0-4) , so a forged `full_name` differing from the authenticated org would simply resolve to no stacks (safe) in the common case — but this coupling is incidental, not enforced.
- `StatusHandler`, uniquely, ignores repository scoping entirely and matches on `sha` across the whole `Commit` table: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) .
- `Commit#create_status_from_github!` writes a real `Status` row, recomputes the commit's aggregate state, and can trigger `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` — i.e. it directly feeds `Commit#deployable?`/`#blocked?`, which gate continuous deployment and merge scheduling [6](#0-5) [7](#0-6) [8](#0-7) .

**Binding broken (as equality):** `organization authenticated by HMAC (repository.owner.login) == organization/repository whose Commit row the status is written to`. The engine enforces the LHS only at the controller and enforces nothing binding it to the RHS inside `StatusHandler`.

### Impact Explanation
Any organization onboarded into the multi-tenant Shipit instance (i.e., any org with its own configured GitHub App / `webhook_secret`, an "unprivileged" party from the perspective of any *other* tenant org) can send a validly-signed `status` webhook for their own org and set an arbitrary `sha`. If that SHA happens to also exist as a `Commit` row belonging to a different organization's stack (plausible for shared/forked upstream history, vendored branches, or simply by an attacker who has read access to org B's public commit history and pushes/rebuilds a branch on their own org A repo containing the very same commit hash), the handler will write a fabricated CI status onto org B's commit. Because that status feeds `deployable?`, `blocked?`, and continuous-delivery scheduling, this can force an unsafe deploy to proceed (fake "success") or block a legitimate deploy (fake "failure") for a stack the attacker has no authorization over — an unauthorized/forced deploy scenario, matching the "unauthorized deploy" Critical/High impact class.

### Likelihood Explanation
Requires the attacker to control (or have push access on) any org integrated with the same Shipit instance and to know/produce a target SHA that also exists in the victim organization's Commit table — feasible for forked/mirrored repositories, shared submodules, or reused open-source history, and is entirely plausible in any multi-tenant Shipit deployment (which the engine explicitly supports via "Using Multiple Github Applications" [9](#0-8) ). No secret, session, or elevated GitHub App permission belonging to the victim org is required — only a legitimately configured, unprivileged sibling org's own webhook secret.

### Recommendation
In `StatusHandler#process` (and any other handler that queries by content rather than by `Handler#stacks`), scope the `Commit` lookup to the stacks belonging to the authenticated repository, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)`, or otherwise validate that `payload.dig('repository','full_name')`'s owner matches the organization used in `verify_signature`. More generally, `WebhooksController` should assert that the repository/organization used to select the HMAC secret is the same one referenced by every write performed by the invoked handler.

### Proof of Concept
1. Attacker operates (or compromises) org-A's GitHub App integration registered in Shipit's `secrets.yml`, with its own valid `webhook_secret`.
2. Attacker pushes/creates a commit in an org-A repo whose SHA equals (or is engineered to equal, e.g. by cherry-picking the exact same tree/parent/author/committer metadata) a SHA already present as a `Commit` in org-B's stack (`shipit_commits` table row for a real, tracked stack).
3. Attacker sends `POST /webhooks` with header `X-Github-Event: status`, `X-Hub-Signature` computed with org-A's own webhook secret, and body `{"repository":{"owner":{"login":"org-a"},"full_name":"org-a/some-repo"},"sha":"<shared-sha>","state":"success", ...}`.
4. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches org-A's `webhook_secret`, and the HMAC validates successfully [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which matches the org-B commit row regardless of the `repository.full_name` field, and calls `create_status_from_github!(params)` on it, writing a forged `success` status into org B's stack [4](#0-3) .
6. If org-B's stack is on continuous delivery and the commit was previously blocked pending CI, the forged status can flip `deployable?` to true, triggering `ContinuousDeliveryJob` for a deploy the org-B maintainers never authorized [10](#0-9) .

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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
