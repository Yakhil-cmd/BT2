### Title
Webhook signature verification org-selection field is decoupled from the repository field used to route webhook effects, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects **which** GitHub App/webhook secret to validate an inbound webhook's HMAC signature against using `repository_owner`, a value read straight out of the *unverified* JSON body. Every webhook handler, however, resolves the **stack/repository to act on** using a different field of the same unverified body: `repository.full_name`. Nothing enforces that these two fields describe the same repository/organization. Anyone who legitimately knows the `webhook_secret` for *any* organization configured on a shared, multi-tenant Shipit instance (a supported configuration, see `docs/setup.md` "Using Multiple Github Applications") can forge a signature that is valid for their own org while pointing `repository.full_name` at a completely different, untrusted org's repository — causing Shipit to process the forged event as if it legitimately came from that other org/repo.

### Finding Description
`verify_signature` computes the organization used to fetch the right `GithubApp`/secret from an attacker-controlled field, before the signature is checked: [1](#0-0) [2](#0-1) 

`repository_owner` is derived from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`) — both attacker-supplied JSON fields that are read *before* the HMAC over the raw body is validated.

Once the signature validates (using whatever org's secret matched the attacker-chosen `repository_owner`), the request body is dispatched to handlers: [3](#0-2) 

Every handler resolves the actual `Stack`/`Repository` to act on via `repository.full_name`, a sibling field in the same payload, unrelated to the field used for signature/org selection: [4](#0-3) [5](#0-4) 

Nothing in `verify_signature` or in the handlers checks that `repository.owner.login` (used to pick the verifying secret) matches the owner embedded in `repository.full_name` (used to pick the target stack). This is the exact bug class from the report: two computations that should be tied to the same authoritative value (here, "which org/repo is this event legitimately for") are instead derived independently from different, both attacker-controlled, fields — one used for the trust decision (signature verification), the other for the effect (which repository's stacks get mutated).

Binding broken (as equality that should hold but doesn't):
`organization used to authenticate the webhook (repository.owner.login / organization.login)` ⧧ `repository whose stacks are actually written to (repository.full_name)`

### Impact Explanation
On a Shipit instance configured for multiple GitHub organizations (an explicitly documented and supported setup), any party who administers their own GitHub App installation on the shared instance — and thus legitimately possesses *their own* `webhook_secret` — can compute a valid `X-Hub-Signature` for a payload whose `repository.owner.login` is their own org, then set `repository.full_name` to target a stack that belongs to a completely different, unrelated organization also hosted on that Shipit instance. This forged, "verified" webhook is then processed exactly as a genuine event for the victim org's repository, e.g.:
- Forged `push` events can trigger `stack.sync_github(expected_head_sha: ...)` for a foreign stack.
- Forged `status` events can create a fabricated commit `Status` (as validated in `test/controllers/webhooks_controller_test.rb` `:state create a Status for the specific commit`) on a foreign stack's commit, which can affect CI-gated flows such as `continuous_deployment`/merge-queue automerge — a path toward an **unauthorized deploy**.
- Forged `membership`/`check_suite`/other events can create/alter `Team`/`User` records or enqueue jobs scoped to the victim's stacks.

This crosses a genuine trust boundary between tenants of the same Shipit installation without requiring any Shipit session, `ApiClient` token, or GitHub write access to the victim's repository — only knowledge of a webhook secret for *some other, unrelated* organization on the same instance.

### Likelihood Explanation
Exploitability requires the deployment to use Shipit's documented multi-organization mode, and the attacker to be a legitimate administrator (or leaker) of a `webhook_secret` for any one of the configured organizations — not the victim organization. Given multi-org configuration is a first-class, documented feature intended precisely to let multiple, mutually distrusting organizations share one Shipit instance, this is a realistic scenario rather than a theoretical one.

### Recommendation
After verifying the HMAC using the org selected via `repository_owner`, additionally verify that the payload's actual repository (`repository.full_name`'s owner) matches `repository_owner`/the organization whose secret validated the signature, rejecting the webhook (422) on mismatch. Alternatively, derive the verifying organization from the same canonical field (`repository.full_name`) that handlers use to select the target repository, rather than from a separate, independently-attacker-controlled field.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `orgA` and `orgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications").
2. As an administrator of `orgA` (untrusted with respect to `orgB`), craft a JSON payload:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": {
       "owner": { "login": "orgA" },
       "full_name": "orgB/victim-repo"
     }
   }
   ```
3. Compute `X-Hub-Signature: sha1=HMAC(orgA_webhook_secret, payload)` — computable by `orgA`'s administrator since they own that secret.
4. POST to `/webhooks` with header `X-Github-Event: push` and the above body/signature.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"orgA"`, fetches `Shipit.github(organization: "orgA")`, and the signature validates successfully.
6. `PushHandler#process` resolves `Repository.from_github_repo_name("orgB/victim-repo")` and triggers `sync_github`/queues jobs against `orgB`'s stack, despite the request never having been signed by `orgB`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
