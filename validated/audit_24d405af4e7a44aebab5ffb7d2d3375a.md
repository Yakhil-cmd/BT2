Confirmed: the webhook signature-selection field (`repository.owner.login`, used to pick which org's `webhook_secret` verifies the HMAC) and the write-target field (`repository.full_name`, used by `Handler#stacks`/`Repository.from_github_repo_name` to resolve which `Stack`/`Repository` receives the event data) are two independent, attacker-controlled JSON fields inside the same signed payload, and nothing enforces that `full_name` is consistent with `owner.login`.

### Title
Webhook events are applied to a repository never covered by the signature-selecting field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/organization (and thus the `webhook_secret` used for HMAC verification) using `repository.owner.login` from the raw JSON body, while every event handler (`Shipit::Webhooks::Handlers::Handler#stacks`) resolves the target `Repository`/`Stack` using the sibling field `repository.full_name`. Because the HMAC covers the whole payload, an attacker cannot forge a signature without knowing a valid `webhook_secret` for *some* configured organization — but once they have any single valid organization's secret (e.g. their own GitHub org onboarded into the same Shipit instance), they can craft a signed delivery where `owner.login` matches their own org (so verification succeeds against their own secret) while `full_name` names a *different*, victim organization's repository, causing the handler to write state (commits, statuses, check-runs, PR/membership updates, merges) against a stack/repository they do not own.

### Finding Description [1](#0-0) 
`verify_signature` derives `repository_owner` via `repository_owner` helper and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)`. This selects the `webhook_secret` for the org named in the payload's `repository.owner.login` (or `organization.login`): [2](#0-1) 

Once the signature validates against that org's secret, `create` dispatches the full parsed payload to `Shipit::Webhooks.for_event(event)` handlers without any further validation that `owner.login` matches `repository.full_name`.

Every handler resolves the target repository from a *different* field, `repository.full_name`: [3](#0-2) 

`Repository.from_github_repo_name` splits this `full_name` value on `/` and looks the repository up purely from payload-controlled strings, with no cross-check against `owner.login`: [4](#0-3) 

Because `verify_webhook_signature` only proves "this payload was HMAC-signed with organization X's secret", and the handlers act on `full_name` (a completely separate, unsigned-in-effect field from the trust perspective — the same signature validates for any content, including a mismatched `full_name`), an org that authenticates the request is not bound to the repository the request actually mutates. This is the shipit-engine analog of the "amount value should not be zero" class of bug: a field that is acted upon (`full_name`) is never actually checked for consistency with the field used to establish trust (`owner.login`).

### Impact Explanation
Any organization onboarded to a shared Shipit instance (multiple orgs are routinely configured together, e.g. `test/dummy/config/secrets_double_github_app.yml`) can, using its own legitimate `webhook_secret`, send crafted webhook deliveries whose `repository.full_name` targets another organization's repository/stack. Depending on the event type this enables cross-repository state corruption: forging commit `status` updates (`app/controllers/shipit/webhooks_controller.rb` dispatches to status handlers), fabricating `check_suite`/`push` events that alter another org's `Stack`'s commit history and deploy eligibility, or manipulating `pull_request`/`membership` events tied to a victim repository/team — all without ever holding write access to the victim's actual GitHub repository. This crosses the required "cross-repository writes" impact bar, since state belonging to Org B's stack is written using only Org A's webhook credentials.

### Likelihood Explanation
Requires the attacker to control (or already legitimately possess) the `webhook_secret` for at least one organization configured on the shared Shipit instance — which is realistic in any multi-tenant/multi-org Shipit deployment (the codebase explicitly supports and tests multiple github orgs, see `test/dummy/config/secrets_double_github_app.yml`). No privileged Shipit account, session, or `ApiClient` token is needed; only the ability to construct and correctly HMAC-sign an arbitrary HTTP POST to `/github/webhooks`, which is exactly the unprivileged-attacker capability this class of finding targets.

### Recommendation
After `verify_webhook_signature` succeeds, additionally assert that the organization used to select the verifying secret (`repository.owner.login` / `organization.login`) matches the owner embedded in `repository.full_name` before dispatching to handlers, e.g. reject (422) when `repository.full_name.split('/').first != repository_owner`. Alternatively, thread the verified `repository_owner` through to `Handler#stacks` and have `Repository.from_github_repo_name` require an explicit, verified owner parameter rather than trusting `full_name` alone.

### Proof of Concept
1. Attacker controls Org A, which is configured in Shipit with `webhook_secret: SECRET_A`.
2. Attacker crafts a JSON payload for a `status` (or `push`/`pull_request`) webhook where:
   - `repository.owner.login = "OrgA"` (so `repository_owner` resolves Org A, and `Shipit.github(organization: "OrgA").verify_webhook_signature` is used).
   - `repository.full_name = "OrgB/victim-repo"` (a repository belonging to Org B, unrelated to the attacker).
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(SECRET_A, raw_body)` using their own valid secret for Org A.
4. POST to `/github/webhooks` with this signature header; `verify_signature` passes because it only checks the HMAC against Org A's secret for the Org-A-named owner.
5. `WebhooksController#create` invokes `Shipit::Webhooks.for_event('status').each { |handler| handler.call(params) }`; the handler resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")`, applying attacker-supplied status/commit/PR state to Org B's stack — a cross-repository write achieved with only Org A's credentials.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
