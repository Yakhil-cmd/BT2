## Analysis

The strongest reachable analog to the `process.mainModule.require` bug class here is a **check-vs-act mismatch**: the code that verifies authenticity looks at one field of the GitHub webhook payload, while the code that performs the state-changing action keys off a *different, unauthenticated* field of the same payload. This exactly matches the required binding: *"an organization that authenticated versus the repository that is written."*

`Shipit::WebhooksController#verify_signature` authenticates the request by resolving the GitHub App/webhook secret for `repository_owner`, i.e. `params.dig('repository','owner','login')` (or `organization.login`), and verifying the HMAC signature against that org's secret: [1](#0-0) 

Once the signature check passes for that org, `create` dispatches the *entire* raw JSON payload to the registered handler for the event, with no further scoping: [2](#0-1) 

For the `status` event, `Shipit::Webhooks::Handlers::StatusHandler#process` does not consult `repository` at all — it looks up commits **globally by SHA** across the entire installation and writes a CI status to any matching commit, regardless of which stack/repository it belongs to: [3](#0-2) 

Compare this with the base `Handler` class, which *does* provide a `repository_name`/`stacks` scoping helper based on `payload.dig('repository','full_name')`, but `StatusHandler` never uses it: [4](#0-3) 

So the equality that should hold — *organization whose secret signed the request == organization owning the repository/commit being mutated* — is never enforced. The signature only proves "this request was signed by whoever owns the `webhook_secret` configured for org X"; it says nothing about which `sha` the payload claims to update. In a multi-org Shipit deployment (the config format explicitly supports per-organization `webhook_secret`s, see `config/secrets.development.example.yml` lines 18-38), an attacker who controls (or is a legitimate low-privilege member/admin of) any one configured organization's GitHub App/webhook can sign an arbitrary `status` payload with `repository.owner.login` set to their own org (passes `verify_signature`) but with `sha` copied from a commit belonging to a completely unrelated organization's stack.

That forged status is then persisted via `Commit#create_status_from_github!` → `Status::Group`, and directly feeds `Commit#deployable?`, which requires `success?` (derived from stored statuses) to allow a deploy: [5](#0-4) [6](#0-5) 

Because `deployable?` also gates `continuous_deployment`/`schedule_continuous_delivery`, a forged "success" status on a target commit in a victim's stack can make an otherwise-blocked commit eligible for continuous deployment or manual deploy approval, i.e. an unauthorized deploy signal is injected cross-organization without ever touching the target org's own webhook secret.

### Title
Cross-organization commit-status forgery via webhook signature/repository binding mismatch - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a GitHub webhook against the organization named in `repository.owner.login` of the payload, but `StatusHandler#process` (and the dispatch in `WebhooksController#create`) never re-checks that the *commit/sha being mutated* actually belongs to a repository owned by that authenticated organization. `StatusHandler` looks up `Commit.where(sha: params.sha)` globally, with no repository filter, so a signature valid for org A can be used to write commit statuses onto commits that belong to stacks tracking a repository of org B.

### Finding Description
- Signature verification is scoped to `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:24-30`), which picks the `Shipit.github(organization:)` config (and thus the `webhook_secret`) used to validate `X-Hub-Signature`.
- The verified boolean only gates the *whole request*; it never constrains which entity inside the JSON body may be mutated.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) resolves target `Commit` records purely by `sha`, with no join/filter on `repository` or `stack` ownership — unlike the base `Handler#stacks`/`repository_name` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), which it doesn't use.
- Result: the binding "organization that authenticated == repository that is written" is not enforced. Any org configured in `Shipit.github` (multi-org deployments, per `config/secrets.development.example.yml`) can sign a `status` payload naming its own `repository.owner.login`, but with a `sha` that collides with a commit tracked under a different organization's stack, and that status will be recorded against the victim commit.

### Impact Explanation
Forged commit statuses directly influence `Commit#deployable?` and downstream continuous-deployment/merge scheduling (`app/models/shipit/commit.rb:227-229`, `:281-287`, `:379-384`). An attacker controlling one legitimately-configured (but unrelated/lower-trust) GitHub organization's webhook secret can inject a fabricated "success" (or "failure"/blocking) CI status onto a commit belonging to a different organization's stack, potentially enabling an unauthorized deploy decision or disrupting/blocking legitimate deploys in a stack they have no authorization over. This crosses a repository/organization trust boundary using credentials that were never meant to authorize actions on that repository — matching the required "unauthorized deploy" / cross-repository-write impact class.

### Likelihood Explanation
Requires the operator to run Shipit with more than one configured GitHub organization (each with its own `webhook_secret`) — a supported and documented configuration. An attacker only needs control of, or the ability to trigger events matching, one such org's webhook (e.g., being able to fire a `status` event with an arbitrary `sha` field, which GitHub's status API/webhooks readily allow for any commit hash string) plus knowledge of a target commit SHA in another tracked repository (often public information, e.g. from the target's GitHub commit history). No access to the victim org's secret, GITHUB_TOKEN, or Shipit session is required.

### Recommendation
In `StatusHandler` (and any other handler that mutates records by cross-cutting identifiers like `sha`), scope the lookup to the repository/stacks derived from `payload.dig('repository','full_name')` — as the base `Handler#stacks` helper already supports — instead of a bare global `Commit.where(sha:)`. Additionally, in `WebhooksController#verify_signature`, consider validating that the organization used to select the webhook secret is consistent with every repository referenced by the event payload before dispatch, rather than trusting the payload's self-reported repository fields uniformly.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per the multi-org `github:` config format).
2. Note a commit SHA `S` that exists in a stack tracked under `org-b/some-repo`.
3. As an operator/holder of `org-a`'s webhook secret, POST to `/webhooks` a `status` event:
```json
{
  "sha": "S",
  "state": "success",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-a/unrelated-repo" }
}
```
signed with `org-a`'s `webhook_secret` in `X-Hub-Signature`.
4. `verify_signature` resolves `Shipit.github(organization: "org-a")` and successfully verifies the signature.
5. `StatusHandler#process` runs `Commit.where(sha: "S")`, finds the commit belonging to `org-b/some-repo`'s stack (no ownership check), and calls `create_status_from_github!`, persisting a forged "success" status on it — potentially unblocking `deployable?` for that commit in `org-b`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
