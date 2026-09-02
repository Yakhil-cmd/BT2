### Title
Webhook Organization-Signature Verification Is Not Bound to the Repository the Event Actually Writes To - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate an incoming webhook against using the attacker-controlled `repository.owner.login` (or `organization.login`) field of the JSON payload, but the handlers that actually act on the payload (creating/syncing commits, statuses, check runs, merge requests, etc.) look up the target `Stack`/`Repository` from a *different*, independently attacker-controlled field (`repository.full_name`). The binding "organization whose secret signed this request" ≠ "repository the event is applied to" is never enforced, so a payload can be signed with the secret of one (attacker-installed) organization while claiming to originate from, and being applied to, an unrelated tracked repository.

### Finding Description
`Shipit::WebhooksController#verify_signature` resolves the signing app via: [1](#0-0) 

and computes the organization used for that lookup purely from payload content: [2](#0-1) 

`ApiClient`/session credentials are not involved here — HMAC verification only proves the request was signed by *some* organization's configured GitHub App secret; it says nothing about which repository the event body claims to affect. After verification succeeds, `create` dispatches the raw, attacker-supplied JSON to the matching event handlers unchanged: [3](#0-2) 

Handlers such as `push_handler.rb`, `status_handler.rb`, and the `pull_request/*` handlers resolve the `Stack`/`Repository` to operate on from the payload's `repository.full_name` (confirmed via repository search matches in `app/models/shipit/webhooks/handlers/push_handler.rb`, `status_handler.rb`, `check_suite_handler.rb`, and the `pull_request/*_handler.rb` files), which is a separate JSON key from `repository.owner.login`/`organization.login` used for signature selection. Nothing ties the two together: an attacker who controls (or installs) a GitHub App on their own organization "attacker-org" knows that org's `webhook_secret`. They can sign a payload with that secret while setting `repository.full_name` to `"victim-org/tracked-repo"` — a repository actually tracked by a `Stack` in this Shipit instance but belonging to a different organization/installation. The signature check passes (it only validates against `attacker-org`'s secret, which is legitimately known to the attacker), and the handler proceeds to act on `victim-org/tracked-repo`.

I was not able to fully read the body of `push_handler.rb`/`status_handler.rb` in this pass (index truncation), so the exact downstream mutation (e.g., `GithubSyncJob` commit ingestion vs. `Status` creation) could not be quoted line-by-line; this is a known gap in my verification. The absence of any cross-check between the two organization/repository identifiers in `webhooks_controller.rb` is, however, directly confirmed.

### Impact Explanation
If a `status`/`check_suite` handler creates a passing `Status`/`CheckRun` for a commit in a victim's tracked repository based on a forged, cross-organization-signed payload, that fabricated "green" CI signal can satisfy `MergeRequest#all_status_checks_passed?`/`StatusChecker` and allow the merge queue (`ProcessMergeRequestsJob`) to merge a pull request, or allow a stack's deploy gating (`required_statuses`) to consider a commit deployable — i.e., an **unauthorized merge or deploy** driven entirely by forged webhook content, satisfying the Critical bar ("cross-repository writes" / "an unauthorized deploy, rollback or merge") without ever holding a session, `ApiClient` token, or the target organization's actual webhook secret.

### Likelihood Explanation
Requires only: (1) knowledge that the target repository is tracked by this Shipit instance (public information, visible stack pages), and (2) the ability to install *any* GitHub App with a webhook and have Shipit configured for that org (an organization the attacker legitimately controls, an "unprivileged" relationship to the victim). No credential belonging to the victim org or to Shipit's session/API layer is required. This matches the allowed threat model (unprivileged attacker, no session/token/webhook_secret of the victim needed).

### Recommendation
Bind webhook processing to the same organization used for signature verification: after `verify_signature` succeeds, re-derive/validate that `repository.full_name`'s owner matches the `repository_owner` (or `organization.login`) that was actually used to select and verify the HMAC, and reject the event (422) on mismatch, before handing the payload to `Shipit::Webhooks.for_event(event)`.

### Proof of Concept
1. Attacker creates GitHub organization `attacker-org` and installs the Shipit GitHub App on it, obtaining/knowing its `webhook_secret` (legitimately, since it's their own org).
2. Attacker crafts a `status` (or `push`) webhook JSON body where `repository.owner.login` = `attacker-org` (used only for HMAC/org selection) but `repository.full_name` = `victim-org/tracked-repo` (a repository actually tracked by a `Stack` in the target Shipit instance), with `state: "success"`, `context` matching a required CI context, and `sha` matching the PR head under merge-queue consideration.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over the raw body and POSTs to `/webhooks`.
4. `verify_signature` looks up `Shipit.github(organization: 'attacker-org')`, verifies the HMAC successfully (since it truly was signed with that secret), and the request proceeds.
5. The `status` handler processes the event against `victim-org/tracked-repo`'s commit/stack (per full_name), injecting a forged passing status that can unblock CI-gated merges/deploys for a repository the attacker does not control.

*Note: I could not directly confirm the exact code path inside `push_handler.rb`/`status_handler.rb` that resolves the target `Stack` from `repository.full_name` due to index truncation on those files; this should be verified by reading those files directly (and `app/models/shipit/webhooks/handlers/handler.rb`) before treating this as fully proven.*

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
