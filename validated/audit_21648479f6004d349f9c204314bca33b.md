### Title
Webhook signature is verified against the organization derived from the payload, but the repository that is written to is a separate, unauthenticated field in the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature with by reading `repository.owner.login` (or `organization.login`) out of the *same* untrusted JSON body it is about to validate [1](#0-0) . Once the signature check passes, the raw payload is dispatched to handlers that resolve the target `Repository`/`Stack` using a *different* field, `repository.full_name` [2](#0-1) . Nothing ties the organization whose secret validated the signature to the repository/owner that the handler actually writes commit statuses, check-runs, or push updates for.

### Finding Description
The equality that should hold is: `organization that authenticated == owner of repository that is written`. In this engine that binding is never enforced:

- `verify_signature` picks the signing secret via `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner)` to get that org's `webhook_secret` [3](#0-2) .
- The signature itself (`X-Hub-Signature`) is a valid HMAC over the raw JSON body computed with whichever organization's secret was selected — it says nothing about which repository inside the JSON is legitimate for that organization.
- After verification, `Handler#stacks` resolves the target repository purely from `payload.dig('repository', 'full_name')` [2](#0-1) , with no check that this repository's owner matches `repository.owner.login`/the organization used to validate the signature.

Because a JSON body can freely contain a `repository.owner.login` of one organization and a `repository.full_name` naming a completely different org/repo (these are independent string fields with no structural coupling), anyone who knows the `webhook_secret` configured for *any* organization onboarded to this Shipit instance can forge a payload whose `repository.full_name` points at a stack belonging to a *different* organization, and the engine will accept and process it as if GitHub sent it for that other repository. `Shipit` is explicitly documented to support multiple organizations sharing one instance, each with its own `webhook_secret` in `secrets.yml` — this is the exact configuration where the mismatch becomes exploitable.

### Impact Explanation
This breaks the binding between the credential that authenticated the request (an organization's `webhook_secret`) and the resource actually mutated (an arbitrary repository/stack's commits, statuses, check-runs). An attacker who administers one onboarded organization's webhook (and therefore possesses that organization's `webhook_secret`, which is routine for whoever set up the GitHub webhook integration for their own org) can inject forged `push`, `status`, or `check_suite` events for stacks belonging to a *different* organization hosted on the same Shipit instance. This is a cross-repository/cross-organization write: it can create fake commits, mark unsafe commits as `success` status (bypassing CI gating for deploys), or flip check-run states used to decide `deployable?`, ultimately enabling an unauthorized deploy through a different organization's repository — squarely a "cross-repository writes / unauthorized deploy" class impact.

### Likelihood Explanation
Any actor who has legitimate access to configure or already knows a webhook secret for one organization onboarded to a multi-org Shipit deployment can exploit this without needing credentials for the target organization at all — they only need to know (or guess, since it's often static) the target repository's `full_name`. No GitHub App private key, session, or `ApiClient` token is required; only the HTTP webhook endpoint and one org's `webhook_secret`.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler#stacks`), enforce that the organization used to select/verify the webhook secret matches the owner of the repository the handler resolves — i.e., derive the stack lookup from the same `repository_owner` value the signature was verified against (or reject/compare `repository.owner.login` against the resolved `Repository#owner` before dispatching), rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Configure two organizations, `org-a` and `org-b`, in `secrets.yml`, each with a distinct `webhook_secret`, both with stacks tracked in the same Shipit instance.
2. As someone with legitimate knowledge of `org-a`'s `webhook_secret` (e.g., the person who configured `org-a`'s GitHub webhook), craft a JSON body for a `status` (or `push`) event where:
   - `repository.owner.login = "org-a"` (so `verify_signature` selects `org-a`'s secret and the HMAC validates), and
   - `repository.full_name = "org-b/target-repo"` (the field actually used by `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name`).
3. Compute `X-Hub-Signature` with `org-a`'s `webhook_secret` over this crafted body and POST it to `/github/webhooks`.
4. `verify_signature` succeeds (secret matches the body it's hashing), and the handler processes the event against `org-b/target-repo`'s stacks — writing a status/commit for a repository the attacker has no authorization over.

### Citations

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
