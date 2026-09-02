### Title
Unscoped `Commit.where(sha:)` in `StatusHandler` lets a webhook authenticated under any known GitHub organization forge a `status` for a commit belonging to a different, unrelated stack, triggering auto-deploy on continuous_deployment-enabled stacks - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to verify a webhook using `repository_owner`, which falls back to `params.dig('organization', 'login')` when `repository` is omitted [1](#0-0) . `StatusHandler#process`, however, looks up the target commit purely by `sha` with no repository/stack scoping at all: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . Because the field used to pick the verifying secret (`organization.login`) is independent of the field that actually determines which commit/stack is mutated (the global `sha` match), an attacker who can get any organization's webhook accepted (e.g. one configured with no `webhook_secret`, which `GitHubApp#verify_webhook_signature` treats as always-valid [3](#0-2) ) can inject a forged `success` status for a commit sha belonging to a completely different stack.

### Finding Description
The broken binding is: the entity that authenticates the webhook (`Shipit.github(organization: repository_owner)`, keyed off `params.dig('repository','owner','login') || params.dig('organization','login')`) must equal the entity whose data is mutated by the handler. It does not.

Trace:
1. `WebhooksController#create` parses the raw JSON body and dispatches to handlers for the `X-Github-Event` header without ever re-validating that `repository.full_name` in the body corresponds to the org used for signature verification [4](#0-3) .
2. `verify_signature` calls `repository_owner`, which prefers `repository.owner.login` but falls back to top-level `organization.login` if `repository` is absent from the payload [1](#0-0) .
3. `Shipit.github(organization: repository_owner)` returns the `GitHubApp` config for whichever org string was supplied, and `verify_webhook_signature` returns `true` unconditionally when that org's config has no `webhook_secret` set [3](#0-2) . Any org configured in the host's Shipit config without a secret (a real, plausible misconfiguration for a multi-tenant deployment) becomes a "free pass" verifier for the attacker who controls a repo in that org and can trigger a webhook from it.
4. Once signature verification passes, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which does `Commit.where(sha: params.sha)` — a global, unscoped lookup across every stack in the installation — and calls `commit.create_status_from_github!(params)` on every match [2](#0-1) .
5. `create_status_from_github!` records the status against the commit's own `stack_id` (from the DB row, not from the payload), and `add_status` re-evaluates deployability and calls `stack.schedule_merges` when the new status is `pending?` or `success?` [5](#0-4) [6](#0-5) .
6. Separately, `Commit#schedule_continuous_delivery` (invoked `after_commit` at creation, and indirectly whenever `deployable?` state is reached via status refresh) enqueues `ContinuousDeliveryJob` if `deployable? && stack.continuous_deployment? && stack.deployable?` [7](#0-6) . On a continuous_deployment-enabled victim stack, forging a `success` status for its most recent undeployed commit (whose sha is public information — it's simply the tip of the victim's public GitHub repo/branch) causes `deployable?` to flip true and the commit gets shipped automatically.

Existing guards do not stop this: `drop_unhandled_event` only checks that a handler exists for the event type, not that the body is internally consistent [8](#0-7) ; `verify_signature` authenticates the request against the *attacker-chosen* org, not the org that owns the target commit; and `StatusHandler`'s `ExplicitParameters` schema only validates types (`sha`, `state`, etc.), not repository ownership [9](#0-8) .

### Impact Explanation
An attacker who controls (or can trigger webhooks as) any GitHub organization known to the Shipit instance — particularly one configured without a `webhook_secret` — can forge a `status` webhook naming the sha of a commit in a victim's stack that they do not own or control. The forged status is written against the victim's real stack (`create_status_from_github!` uses the commit's actual `stack_id`), and if the victim stack has `continuous_deployment` enabled, this can move a real commit into a deployable state and trigger `ContinuousDeliveryJob`, i.e. an unauthorized deploy of code the attacker did not author sign-off on. This matches "a payload for one repository mutating another's stack, commit... or an unauthorized deploy" (Critical).

### Likelihood Explanation
Preconditions: (1) the Shipit instance must have at least one organization configured with no `webhook_secret` (or one whose secret the attacker can otherwise satisfy) that the attacker can trigger webhooks from — this is a realistic misconfiguration in multi-tenant/multi-org Shipit deployments, since `verify_webhook_signature` explicitly treats a blank secret as "always valid" [10](#0-9) ; (2) the target commit's sha must be known, which is trivial for any public GitHub repository; (3) the victim stack must have `continuous_deployment` enabled for the deploy-triggering amplification (the cross-tenant status write itself is possible regardless). The attacker needs no Shipit session, API token, or GitHub App secret — only the ability to `POST /webhooks` with a crafted body and a valid signature for the lenient org. The attack is fully repeatable against any sha/stack combination once the lenient org exists.

### Recommendation
Scope `StatusHandler` (and equivalent handlers like `CheckRunHandler`/others that query by `sha`) to the repository that authenticated the webhook: after signature verification, resolve the concrete `Repository`/`Stack` from `params.dig('repository', 'full_name')` (or an equivalent trusted identifier established during verification) and constrain `Commit.where(sha: ..., stack: matching_stacks)` rather than querying `sha` globally. Additionally, require `repository.full_name` and `repository.owner.login`/`organization.login` to be present and mutually consistent before accepting a webhook, and reject events lacking a `repository` object for handlers that mutate repository-scoped data.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/status_handler_test.rb`, using `t0kEn`/no-secret org from `GitHubApp#token`/test env, no live GitHub):
1. Create `stack_a` (victim) with `continuous_deployment: true`, and a `commit_a` with `sha: 'deadbeef...'` belonging to `stack_a`.
2. Configure Shipit with two orgs: `victim-org` (owns `stack_a`, has a real `webhook_secret`) and `attacker-org` (configured with no `webhook_secret`).
3. POST to `/webhooks` with header `X-Github-Event: status`, body: `{"sha": "deadbeef...", "state": "success", "organization": {"login": "attacker-org"}}` (no `repository` key), and any/no `X-Hub-Signature` value.
4. Assert: (a) response is `200 OK` (signature accepted via `attacker-org`'s blank secret); (b) `commit_a.reload.statuses.last.state == 'success'`; (c) `ContinuousDeliveryJob` was enqueued for `stack_a` — asserting the equality-violation: the org that authenticated the request (`attacker-org`) is not equal to the org/stack that was mutated (`victim-org`/`stack_a`), yet the mutation and deploy trigger occurred.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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
