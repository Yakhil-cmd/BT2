### Title
Webhook signature verification binds to the payload's declared organization, not the repository/commit the handlers actually mutate — cross-tenant status/deploy forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/org config (and therefore which `webhook_secret`) to validate the HMAC signature against based on `repository_owner`, a value read straight out of the untrusted JSON payload. The `create` action then re-parses the same raw body and hands it to event handlers that resolve the actual target repository/stack from other fields in that same attacker-controlled payload (`repository.full_name`), or — in the case of `StatusHandler` — from no repository scoping at all. The equality the code implicitly assumes, `org whose secret signed the payload == org/repo the handler acts on`, is never enforced.

### Finding Description
`verify_signature` picks the signing secret like this: [1](#0-0) 

`repository_owner` is derived purely from the JSON body: [2](#0-1) 

The signature is verified over the *entire raw body* using the `webhook_secret` configured for whatever organization the attacker put in `repository.owner.login` (or `organization.login`). If the request produces a valid HMAC, the request is accepted and the full JSON body is dispatched to handlers: [3](#0-2) 

Handlers, however, do not re-check that `repository_owner` against the entity they operate on:

- `Handler#repository_name`/`#stacks` resolve the target purely from `payload.dig('repository', 'full_name')`, a separate field from `repository.owner.login`: [4](#0-3) 

- `StatusHandler` is worse: it does not scope by repository at all, only by commit SHA, globally across the whole installation: [5](#0-4) [6](#0-5) 

Because `repository.owner.login` (used only to pick the verification secret) and `repository.full_name` / `sha` (used by handlers to decide what gets mutated) are independent, attacker-controlled fields inside the same unauthenticated JSON body, an entity that legitimately controls the `webhook_secret` for **its own** organization/GitHub App configured in this Shipit instance can forge a payload that:
1. Sets `repository.owner.login` (or `organization.login`) to their own org so `Shipit.github(organization: repository_owner)` picks a secret they know, and
2. Signs the whole raw body with that known secret, while
3. Setting `repository.full_name` (for `PushHandler`, PR handlers) to a completely different org/repo's stack, or setting `sha` (for `StatusHandler`) to a commit belonging to a completely different org's stack.

The signature check passes (it validated the attacker's own secret against the attacker's own bytes), yet the handler acts on a resource outside the attacker's org. This is the exact "organization that authenticated versus the repository that is written" binding break: `repository_owner_used_for_auth != repository_owner_of_object_mutated`.

### Impact Explanation
The most severe reachable consequence is via `StatusHandler`: it looks up `Commit.where(sha: params.sha)` with **no repository filter whatsoever**, then calls `create_status_from_github!`, which persists a `Status` for that commit and can flip its state to `success`: [6](#0-5) 

`Commit#deployable?` and `Commit#schedule_continuous_delivery` react to this status update, and if the victim stack has `continuous_deployment?` enabled, a `ContinuousDeliveryJob` is enqueued for the victim stack purely as a result of the forged status: [7](#0-6) [8](#0-7) 

An attacker who only controls a webhook secret for their own tenant/org registered in the same multi-tenant Shipit instance can therefore fabricate a passing CI status for a commit belonging to an entirely different organization's stack and trigger an unauthorized deploy of that victim stack — satisfying the Critical bar ("an unauthorized deploy"). `PushHandler` and the PR handlers are also reachable via the org/full_name mismatch, letting the attacker force a `sync_github`/archive/provisioning action on a victim org's stack, though those are lower-impact than the deploy-trigger path through `StatusHandler`.

### Likelihood Explanation
This requires the attacker to already possess a valid `webhook_secret` for at least one organization configured in `Shipit.github(...)` on the same instance — i.e., they must be a legitimate tenant/org-admin of this multi-tenant Shipit deployment, not an arbitrary unauthenticated internet user. Given that constraint, the exploit itself is trivial: craft one JSON body, sign it with the secret you already legitimately hold, and set the `sha`/`repository.full_name` fields to point at another tenant's commit/stack. No additional session, API token, or GitHub write access is needed beyond the webhook secret the attacker's own org already has, which is the credential/repository boundary this analog breaks.

### Recommendation
After parsing the payload, re-derive the repository/stack the handler is about to act on and assert its owning organization equals `repository_owner` (the org whose secret validated the signature) before dispatching to handlers. For `StatusHandler` specifically, scope the `Commit` lookup by the stack/repository resolved from the verified organization (e.g., join through `stack.repository.owner == repository_owner`) rather than matching by SHA alone across all tenants.

### Proof of Concept
1. Attacker is an admin of `org-attacker`, which is configured in this Shipit instance with `webhook_secret = S`.
2. Attacker identifies a target commit `sha=X` belonging to `stack` under `org-victim`, which has `continuous_deployment` enabled and requires a CI status context that currently isn't `success`.
3. Attacker builds a JSON body:
   ```json
   {
     "sha": "X",
     "state": "success",
     "context": "<required-context>",
     "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-attacker/whatever" }
   }
   ```
4. Attacker signs the raw body with `S` and sends `POST /webhooks` with header `X-Github-Event: status` and the computed `X-Hub-Signature`.
5. `verify_signature` computes `repository_owner = "org-attacker"`, fetches `Shipit.github(organization: "org-attacker")`, verifies successfully against secret `S`.
6. `create` dispatches to `StatusHandler`, which runs `Commit.where(sha: "X")` — matching the victim's commit regardless of organization — and creates a `success` status on it.
7. `Commit#schedule_continuous_delivery` fires because the commit is now `deployable?` and the victim stack is continuously deployed, enqueuing an unauthorized deploy of `org-victim`'s stack.

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
