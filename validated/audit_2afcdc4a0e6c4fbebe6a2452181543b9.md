### Title
Webhook organization selected for signature verification can diverge from the organization whose repository is acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate a delivery against by reading `repository_owner`, which is derived from the controller's standard `params` object. [1](#0-0)  `repository_owner` is computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [2](#0-1)  Critically, the `create` action re-parses the event payload from a *separate*, locally-scoped variable, `params = JSON.parse(request.raw_post)`, which shadows the method `params` only inside `create` and is passed directly to the event handlers. [3](#0-2)  Because `verify_signature` runs as a `before_action`, in a separate method scope, it never sees this local shadow — it resolves `repository_owner` from Rails' own `params` helper (which is influenced by query-string and route parameters, in addition to any auto-parsed JSON body), not from the exact bytes of `request.raw_post` that are cryptographically verified via `verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)`. [1](#0-0) 

This is the same class of bug as the reported Solidity issue: a value used to pick which trusted entity's authority applies (the splitter/pair address; here, the organization whose `webhook_secret` is used) is not the same value that is actually bound and acted upon by the privileged operation (the withdrawal target; here, the repository/organization inside the HMAC-verified raw body that handlers subsequently process).

### Finding Description
- `verify_webhook_signature` computes an HMAC over `request.raw_post` using the `webhook_secret` configured for a specific organization, retrieved via `Shipit.github(organization: repository_owner)`. [1](#0-0)  Multiple organizations can be configured, each with a distinct `webhook_secret`, as shown in the sample multi-org secrets file. [4](#0-3) 
- `repository_owner`, used only to *select which secret* to verify against, is read from the generic `params` accessor rather than from the exact JSON body that is verified and later dispatched to handlers. [2](#0-1) 
- The `create` action independently parses `request.raw_post` into a locally-scoped `params` variable and dispatches that hash to all registered handlers for the event (push, pull_request, status, membership, check_suite, etc.), without re-checking that the repository/organization inside that hash matches the organization whose secret validated the request. [3](#0-2) [5](#0-4) 
- As a result, whichever organization's identity is used to *choose the verification key* is not architecturally guaranteed to be the same organization whose repository/stack the verified payload ultimately drives — this is the "payload field acted on but never covered by the verified signature" pattern from the rules, and also matches "an organization that authenticated versus the repository that is written."

Because this mirrors the audited bug (using a caller-influenced identifier to select a different trust context than the one the privileged action actually executes against), the same root cause exists here: `repository_owner`'s resolution path is decoupled from the exact signed bytes acted upon.

### Impact Explanation
If this divergence is exploitable (i.e., if an attacker can influence the value seen by `repository_owner` independently of `request.raw_post`, for example via query-string parameters that Rails merges into `params` alongside the JSON body), an actor who legitimately controls one configured organization/app (and therefore knows that organization's own `webhook_secret`) could sign an arbitrary payload with their own secret while having `verify_signature` select their own organization's secret for validation, yet have the `create` action process a payload whose `repository`/`organization` fields describe a *different*, unrelated organization or repository configured on the same Shipit instance. This would let the attacker forge `push`, `pull_request`, `status`, `check_suite`, or `membership` events against a victim organization/repository they do not control, potentially triggering unauthorized `GithubSyncJob` runs, fabricated CI statuses that gate deploys, or unauthorized team membership changes — this falls under "cross-repository writes" / "unauthorized deploy" impact criteria.

### Likelihood Explanation
Exploitability depends on two facts I could not fully verify within the available tool budget:
1. Whether Rails, for this controller (`ActionController::Base`, JSON content type, with `skip_before_action :verify_authenticity_token`), actually merges query-string parameters into `params` in a way that lets an attacker set `repository[owner][login]` or `organization[login]` independently of the POST body seen by `JSON.parse(request.raw_post)`.
2. The exact semantics of `Shipit.github(organization:)` and whether a Shipit deployment typically hosts more than one organization with independently attacker-influenceable webhook secrets (this affects whether the "known secret" belongs to a genuinely lower-privileged actor or requires administrator-level configuration access, which would put it out of scope).

I was not able to locate and inspect `Shipit.github`'s implementation (in `lib/shipit.rb`) before running out of tool calls, so I could not confirm point 2, and I could not run/trace an actual Rails request to confirm point 1. These are the key open questions that determine whether this is a genuinely exploitable unprivileged-attacker path or a purely theoretical code-structure smell.

### Recommendation
- In `WebhooksController#verify_signature`, derive `repository_owner` from the exact same parsed `request.raw_post` JSON that is HMAC-verified and later dispatched to handlers, rather than from the generic `params` accessor, e.g. by parsing `request.raw_post` once in a `before_action` and reusing that parsed hash for both signature-org selection and dispatch.
- Add an explicit check that the `repository`/`organization` login used to select the verification secret and the `repository`/`organization` login inside the verified payload are identical before dispatching to handlers.
- Add a regression test that sends a request with mismatched query-string vs. body organization/repository identifiers and asserts the request is rejected.

### Proof of Concept
Not executed — this report is based on static code review of `app/controllers/shipit/webhooks_controller.rb`. A full PoC would require: (1) confirming Rails' parameter-merging behavior for this controller/request format, and (2) confirming that `Shipit.github(organization:)` can resolve to an organization whose `webhook_secret` is known to an attacker who is unprivileged with respect to the victim organization. I was unable to complete this verification before running out of tool-call budget; this should be validated in a running instance (e.g., via a Devin session) by crafting a POST to `/webhooks` with a query string like `?repository[owner][login]=org-b` while the JSON body's `repository.owner.login` is `org-a`, signed with `org-b`'s `webhook_secret`, and observing whether `verify_signature` passes and `org-a`'s stack/webhook handlers still execute on the forged body.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** app/models/shipit/webhooks.rb (L1-23)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    class << self
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end
```
