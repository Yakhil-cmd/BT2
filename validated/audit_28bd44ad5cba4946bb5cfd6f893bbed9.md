### Title
Webhook signature verification keys off `repository.owner.login`, but downstream handlers act on the unrelated `repository.full_name` / a global `Commit.sha` lookup — breaking the "organization that authenticated" vs "repository/commit that is written" binding - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate an inbound webhook's HMAC against using a value taken from the same untrusted JSON body it is trying to authenticate — `repository.owner.login` (falling back to `organization.login`). Every downstream `Shipit::Webhooks::Handlers::Handler` then resolves the repository/stack to mutate using a *different* field of that same body, `repository.full_name`, and `Shipit::Webhooks::Handlers::StatusHandler` doesn't scope by repository at all, matching purely on `Commit.sha` across the whole instance. In a multi-organization Shipit deployment (as documented/supported in `config/secrets.development.shopify.yml`, each org with its own `webhook_secret`), an attacker who legitimately administers one configured GitHub org — and therefore knows that org's own `webhook_secret` — can forge a correctly-signed webhook whose `repository.owner.login` names their own org (so verification passes) while `repository.full_name` / `sha` refer to a completely different org's stack/commit. This lets the attacker inject state (push syncs, commit statuses) into repositories they do not own.

### Finding Description
Binding that should hold: `organization authenticated by HMAC == organization whose repository/commit is mutated`.

- `verify_signature` computes `repository_owner` from the payload and looks up the app config for it: [1](#0-0) [2](#0-1) 

- `verify_webhook_signature` only checks the raw body's HMAC against the `webhook_secret` configured for that org; it has no knowledge of, or binding to, which repository is referenced elsewhere in the payload: [3](#0-2) 

- Once the signature is "verified" (against the attacker's own org secret), the full raw payload is dispatched unmodified to handlers: [4](#0-3) 

- Every generic `Handler` resolves the target repository from `repository.full_name` — a field never covered by the signature-selection logic, so it is attacker-controllable independent of which org's secret was used: [5](#0-4) 

- `PushHandler` uses that repository lookup to trigger a GitHub sync with an attacker-chosen `expected_head_sha` for any stack under that repo: [6](#0-5) 

- `StatusHandler` is even less scoped: it doesn't consult `repository` at all, it matches globally by `Commit.sha`, so a forged, validly-signed `status` event can attach a commit status to *any* commit in *any* stack in the instance simply by guessing/observing a target repo's public commit SHA: [7](#0-6) 

- `Commit#create_status_from_github!` / `add_status` writes the forged status and can flip `deployable?`/trigger continuous delivery for the target stack: [8](#0-7) [9](#0-8) [10](#0-9) 

Before the attacker's request: `repository_owner` (used for auth) and `repository.full_name`/`sha` (used for effect) are implicitly assumed to describe the same GitHub repository, because in a genuine GitHub-originated webhook they always do.
After the attacker's crafted request: `repository_owner = "attacker-org"` (a real org the attacker administers and whose `webhook_secret` they legitimately know), while `repository.full_name = "victim-org/victim-repo"` or `sha = <victim commit sha>`. The HMAC check passes (it only verifies against attacker-org's own secret), but the mutation lands on victim-org's stack/commit.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope. Concretely:
- Forging `push` events lets an attacker cause `stack.sync_github(expected_head_sha:)` to run for a stack they do not control, using a `sha` of their choosing.
- Forging `status` events lets an attacker create a fabricated `Status` (e.g., `state: "success"`) on any commit anywhere in the instance purely by knowing its SHA (often public), which can satisfy `Commit#deployable?` and `stack.schedule_merges`/`ContinuousDeliveryJob`, contributing to an unauthorized deploy of a repository/stack the attacker has no legitimate access to. This matches the "unauthorized deploy" Critical impact category.
- This requires the attacker to be a legitimate admin of at least one GitHub org already configured in this shared, multi-tenant Shipit instance (so they know that org's `webhook_secret`) — no Shipit session, `ApiClient` token, or the target org's own `webhook_secret` is needed, satisfying the "unprivileged attacker" requirement relative to the victim org/repo.

### Likelihood Explanation
Requires a multi-organization Shipit deployment where the attacker is a legitimate administrator of one configured GitHub org (able to view/rotate that org's own GitHub App webhook secret) but not of the target org/repo. This is a realistic and documented deployment topology (`config/secrets.development.shopify.yml` shows multiple orgs configured side by side, each with independent `webhook_secret`). Crafting the payload requires only knowledge of the target's public repository name and, for the status path, a public commit SHA (trivially observable for public GitHub repos) or a guessed/leaked SHA for private ones.

### Recommendation
Bind the verified organization to the resource being mutated: after verifying the signature, re-derive `repository_owner` from `repository.full_name` (or explicitly assert `repository.owner.login == full_name.split('/').first`) and reject the request if they diverge. Additionally, scope `StatusHandler` (and any other handler) by resolving the repository via `stacks`/`Repository.from_github_repo_name` before matching commits, rather than a bare, cross-tenant `Commit.where(sha:)`.

### Proof of Concept
1. Deploy Shipit configured with two orgs, `attacker-org` (attacker is the GitHub App owner, knows `webhook_secret_A`) and `victim-org` (Shipit tracks a stack for `victim-org/victim-repo`, unrelated `webhook_secret_B` unknown to attacker).
2. Attacker crafts a `status` webhook body:
```json
{
  "sha": "<known commit sha of victim-org/victim-repo>",
  "state": "success",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_A, raw_body)>` using their own known `webhook_secret_A`.
4. POST to `/webhooks` with `X-Github-Event: status`. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `webhook_secret_A`, and the HMAC validates successfully.
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which runs `Commit.where(sha: params.sha)` — matching the victim commit regardless of repository — and calls `create_status_from_github!`, creating a forged `success` status on `victim-org`'s commit despite the attacker never possessing `webhook_secret_B`.

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
