### Title
Cross-organization commit-status forgery via unscoped `sha` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an incoming GitHub webhook against the GitHub App secret of the organization named in the payload (`repository.owner.login`) [1](#0-0) , but the `status` event handler that subsequently runs never re-checks that binding when applying the payload: it looks up commits globally by `sha` alone, across every stack/repository configured in the Shipit instance [2](#0-1) .

### Finding Description
This mirrors the Vader `_burn`-address bug class: a value that is correct in one caller context (the org whose secret validates the signature) is blindly reused to act on a different, unverified entity (any commit belonging to any stack, regardless of which org/repo the verified signature actually covers).

Concretely:
- `verify_signature` picks the `GitHubApp` (and therefore the HMAC secret) to check using `repository_owner`, derived from the attacker-supplied JSON body (`params.dig('repository','owner','login')`) [3](#0-2) . This only proves the request was signed by *some* configured organization's webhook secret — it never constrains which `Stack`/`Commit` the payload is allowed to reference.
- `StatusHandler#process` performs `Commit.where(sha: params.sha)` with no scoping to the stack/repository tied to the authenticated organization [2](#0-1) , then calls `commit.create_status_from_github!(params)` for every match found, even if that commit belongs to a completely different organization's stack.
- `Commit#create_status_from_github!` / `#add_status` writes the forged status and, if it flips the commit's state to green, triggers `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` [4](#0-3) .
- Commit deployability is gated by `Commit#deployable?`, which depends purely on the locally stored status/check-run state (`success? && !blocked?`) [5](#0-4) , so a forged "success" status can make an otherwise-failing/pending commit in an unrelated organization's stack appear deployable, and can also trigger `schedule_continuous_delivery` if continuous deployment is enabled [6](#0-5) .

**Equality that should hold but doesn't:** `organization whose signature was verified == organization/repository whose commit is written`. After the attacker's request, the left side is the attacker's own onboarded org (whose secret they control, e.g. via their own legitimate GitHub App installation) while the right side is *any* stack in the installation whose commit happens to share the forged `sha`.

### Impact Explanation
An attacker who operates any organization/repository legitimately onboarded to the shared Shipit instance (a routine, unprivileged scenario for a multi-tenant Shipit deployment — no `webhook_secret`, `ApiClient` token, or session is needed beyond their own org's normal webhook signing capability) can forge GitHub `status` webhooks referencing a `sha` belonging to a *different* organization's stack (commit SHAs are public information visible via GitHub). This lets them inject fabricated CI status for someone else's commit, potentially satisfying `deployable?` and causing an unauthorized deploy of that commit via continuous delivery — matching the "unauthorized deploy" Critical/High impact category.

### Likelihood Explanation
Requires only that the attacker's own organization is configured in Shipit's multi-org `github` secrets (a normal, low-privilege tenant, not a privileged Shipit account) and knowledge of a target commit's SHA (public). No repository write access, GitHub App private key, or Shipit-side secret of the victim org is needed — only the ability to trigger (or forge, since only the correct HMAC for the attacker's *own* org is required) a `status` webhook naming their own org while embedding an arbitrary `sha`.

### Recommendation
Scope the `StatusHandler` (and analogous handlers) lookup by the repository/organization that was actually verified during signature check, e.g. resolve commits only within stacks belonging to `repository_owner`/`full_name` from the verified payload, instead of a global `Commit.where(sha: ...)` lookup.

### Proof of Concept
1. Attacker controls org `attacker-org`, onboarded to the shared Shipit instance with its own legitimate GitHub App/webhook secret.
2. Attacker learns the SHA of a pending/failing commit belonging to `victim-org`'s stack (public via GitHub).
3. Attacker crafts a GitHub `status` webhook payload: `{"sha": "<victim_sha>", "state": "success", "repository": {"owner": {"login": "attacker-org"}}}`, signs it with `attacker-org`'s webhook secret, and POSTs it to `/webhooks`.
4. `verify_signature` succeeds because it only checks the signature against `attacker-org`'s secret [1](#0-0) .
5. `StatusHandler#process` finds the commit by `sha` alone (belonging to `victim-org`) and applies the forged "success" status to it [2](#0-1) .
6. If that flips `deployable?` to true, `Hook.emit(:deployable_status, ...)` fires and, with continuous deployment enabled on `victim-org`'s stack, an unauthorized deploy can be triggered [6](#0-5) .

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

**File:** app/models/shipit/commit.rb (L365-386)
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
