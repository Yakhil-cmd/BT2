### Title
Webhook signature is bound to the payload's `repository.owner.login` while every event handler acts on the unrelated `repository.full_name` (and `StatusHandler` ignores repository scoping entirely) - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC signature using `repository_owner` (`params.dig('repository','owner','login')`), i.e. it authenticates *which organization* sent the payload. [1](#0-0) 
But every downstream `Handler` resolves the target `Stack`/`Repository` from a completely different, unverified field of the same JSON body — `repository.full_name` [2](#0-1) 
— and `StatusHandler` doesn't even do that: it looks up commits globally by `sha` with no repository scoping whatsoever. [3](#0-2) 

This is the same class of bug as the report: a party that is legitimately authorized for one identity (its own org / its own low-LTV vault) can act on a different identity (another org's repository / another user's larger collateral) because the enforcement check validates one field while the action is performed using a sibling field that was never bound to the check.

### Finding Description
Shipit is multi-tenant: `Shipit.github(organization: repository_owner)` picks a distinct GitHub App config (and `webhook_secret`) per onboarded GitHub organization. [4](#0-3) 
The signature check therefore only proves "this request was signed with Org A's webhook secret" — it says nothing about which repository the payload actually describes. The equality the code implicitly (and incorrectly) assumes is:

`verified_org == payload.repository.owner.login` **⟺** `verified_org == payload.repository.full_name.split('/').first`

There is no code enforcing the right-hand side. Once `verify_signature` passes for Org A (because the request was HMAC-signed with Org A's secret — which anyone who administers Org A's own GitHub webhook legitimately possesses), the controller hands the *entire, unauthenticated-per-field* JSON body to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [5](#0-4) 
Each `Handler` then trusts `repository.full_name` from that same body to pick the `Stack` [2](#0-1) 
— a value Org A's administrator fully controls and can set to any other onboarded organization's repository (e.g. `"Victim/other-repo"`).

`StatusHandler` is the most severe instance: it doesn't consult `repository_name`/`stacks` at all, it matches by `Commit.where(sha: params.sha)` across the *entire installation*, and directly writes a `Status` via `commit.create_status_from_github!(params)`. [3](#0-2) [6](#0-5) 
`Commit#deployable?` and continuous delivery scheduling are driven directly by that injected status. [7](#0-6) [8](#0-7) 

### Impact Explanation
An administrator of any single GitHub organization that Shipit has onboarded (an "unprivileged attacker" with respect to every *other* tenant/repository in the same Shipit instance) can forge signed webhook deliveries — signed with their own legitimately-possessed webhook secret — whose `repository.full_name`/`sha` fields target a different tenant's `Stack`/`Commit`. This can:
- Force a `push` re-sync (`PushHandler` → `stacks...find_each { |stack| stack.sync_github(...) }`) against another org's stack, or
- Forge a passing CI `status` for a commit belonging to another org's stack, flipping `Commit#deployable?` to true and triggering `schedule_continuous_delivery`, enabling an unauthorized deploy of code that never actually passed CI in the target repository.

This crosses the "cross-repository writes / unauthorized deploy" impact bar because the org-level signature verification is never bound to the repository actually mutated.

### Likelihood Explanation
Requires only that the attacker controls a GitHub org already onboarded to the same Shipit instance (a normal, low-privilege tenant relationship in a shared/multi-tenant Shipit deployment) — no `ApiClient` token, session, or GitHub App private key is needed, since the attacker legitimately owns the webhook secret for their own org and can hand-craft the HTTP POST to `/webhooks` themselves rather than relying on GitHub to deliver it.

### Recommendation
In `WebhooksController#verify_signature`/`Handler`, verify that `payload.dig('repository','owner','login')` (the identity used to select the signing secret) matches the owner segment of `payload.dig('repository','full_name')` before dispatching to handlers, and scope `StatusHandler` (and any handler that queries by `sha` alone) to commits belonging to a `Stack` resolved from the verified repository, never a global `Commit.where(sha:)` lookup.

### Proof of Concept
1. Attacker administers `AttackerOrg`, onboarded to the shared Shipit instance with webhook secret `S` (known to the attacker, since they configured it on the GitHub side too).
2. Attacker crafts a `status` webhook payload: `{"repository":{"owner":{"login":"AttackerOrg"}, "full_name":"AttackerOrg/whatever"}, "sha": "<victim_commit_sha>", "state":"success", ...}`.
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S, body)` themselves and POSTs to `/webhooks`.
4. `verify_signature` selects `Shipit.github(organization: "AttackerOrg")` and confirms the signature — passes, since it was in fact signed with `AttackerOrg`'s own secret. [4](#0-3) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` with no ownership check, finds the victim's commit in a different `Stack`, and calls `create_status_from_github!`, injecting a fabricated success status. [3](#0-2) 
6. If that stack has continuous deployment enabled, `Commit#schedule_continuous_delivery` fires and the forged commit ships. [8](#0-7)

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
