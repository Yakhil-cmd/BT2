## Finding

Based on the confirmed code, this maps to the reward-calculation bug class ("a binding uses two different data-sets that should have matched but don't") as a **verified-organization vs. acted-upon-repository mismatch** in the webhook pipeline.

### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on the independently-controlled `repository.full_name` field, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / webhook secret to validate a request against using one JSON field (`repository.owner.login`, falling back to `organization.login`), while every webhook `Handler` subclass resolves the target `Stack`/`Repository` to act on using a *different* JSON field (`repository.full_name`) from the exact same, attacker-supplied request body.

### Finding Description
`verify_signature` picks the verifying GitHub App like this: [1](#0-0) [2](#0-1) 

That is, `Shipit.github(organization: repository_owner)` is looked up from `params.dig('repository','owner','login')`. In a multi-org Shipit deployment (documented and directly supported via `github_app_config`), each organization has its own `webhook_secret`. [3](#0-2) [4](#0-3) 

Once the signature check passes, the full raw payload is dispatched to every registered handler: [5](#0-4) 

Every `Handler` subclass resolves the repository/stack to operate on from a **separate** field, `repository.full_name`, with no cross-check against the `repository.owner.login` value that was used for signature verification: [6](#0-5) 

Concretely, `PushHandler` uses this `stacks` helper to enqueue a GitHub sync job for whatever stack matches `repository.full_name`: [7](#0-6) 

Since GitHub's real webhooks always keep `repository.owner.login` consistent with `repository.full_name`, this discrepancy is invisible under normal operation. But nothing in Shipit enforces that consistency itself — the HMAC only guarantees the **body was signed with some org's secret**, not that the `owner.login`/`full_name` pair inside that body is internally consistent.

**The broken binding, as an equality that must hold but doesn't:**
`organization_that_authenticated_the_request (repository.owner.login) == organization_that_owns_the_repository_being_acted_on (repository.full_name)`

An attacker who legitimately administers their **own** GitHub App installation on OrgB (a normal, unprivileged action - they only need to be an admin of a GitHub organization that the operator of this shared Shipit instance has also configured, e.g., in a multi-org managed CI setup) knows OrgB's `webhook_secret`. They can then POST an arbitrary, non-GitHub-originated JSON body to `/webhooks` with:
- `repository.owner.login = "OrgB"` (or omit `repository` and set `organization.login = "OrgB"`) so `verify_signature` picks OrgB's app/secret and the HMAC (computed by the attacker, who knows OrgB's secret) validates.
- `repository.full_name = "OrgA/victim-repo"` pointing at a stack belonging to a *different* organization (OrgA) also hosted on the same Shipit instance, which the attacker has no privileges over.

This request passes signature verification (it's legitimately signed with OrgB's secret) and is then routed to handlers that resolve the target purely from `repository.full_name = "OrgA/victim-repo"`, letting the attacker drive actions against a stack/org they don't control.

### Impact Explanation
This breaks the cross-organization write isolation that a multi-tenant Shipit instance depends on: an admin of one configured GitHub organization can forge webhook events that are processed as if they originated from a repository belonging to a completely different configured organization. Confirmed impact via `PushHandler` is forcing `GithubSyncJob` for an arbitrary stack in a different org with an attacker-chosen `expected_head_sha`. Other handlers built on the same `Handler` base (e.g., status/check-suite/pull-request handlers, which similarly resolve `repository.full_name` independently of the verified owner) are reachable through the identical bypass and could allow writing forged commit/CI state or pull-request/review-stack lifecycle events against another organization's stacks — I was not able to fully inspect `status_handler.rb`/`check_suite_handler.rb` before running out of iterations, so I cannot confirm with code citations whether they permit forging a "success" CI status that would feed into `Commit#deployable?` and continuous delivery (which would elevate this to an unauthorized-deploy-class Critical). This should be verified directly against those two files.

### Likelihood Explanation
Requires only that the attacker administers/knows the webhook secret for *any one* organization configured on the shared Shipit instance — not the target organization, no GitHub App private key, no `ApiClient` token, and no Shipit session. This is a realistic, low-privilege prerequisite in exactly the "Using Multiple GitHub Applications" deployment topology that Shipit documents and supports.

### Recommendation
`WebhooksController#verify_signature` and `Handler#repository_name`/`#stacks` must derive the organization from the *same* payload field, and handlers should additionally assert that the resolved repository/stack actually belongs to the organization whose secret validated the signature (e.g., compare `repository.full_name.split('/').first` against `repository_owner` used in verification, rejecting mismatches with a 422).

### Proof of Concept
1. Operator configures Shipit with two orgs, `OrgA` and `OrgB`, each with its own `github.<org>.webhook_secret` per `docs/setup.md`'s "Using Multiple GitHub Applications" section.
2. Attacker is an admin of `OrgB`'s GitHub App and thus knows `OrgB`'s `webhook_secret` (a fully unprivileged action relative to `OrgA`).
3. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgB_webhook_secret, body)>` and sets `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgB")` (from `repository.owner.login`) and the signature validates successfully. [1](#0-0) 
6. `PushHandler.call(params)` resolves `stacks` via `Repository.from_github_repo_name("OrgA/victim-repo")` and enqueues `GithubSyncJob` for OrgA's stack, using the attacker-supplied `expected_head_sha`, despite the request never being authenticated as belonging to OrgA. [8](#0-7)

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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
