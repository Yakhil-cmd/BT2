This confirms the vulnerability. The `WebhooksController#verify_signature` selects which GitHub App's secret to verify against using `repository_owner` (`params.dig('repository', 'owner', 'login')`), while every event handler (`Handler#repository_name`, `PushHandler`, `PullRequest::*Handler`) instead trusts `payload.dig('repository', 'full_name')` to select the `Repository`/`Stack` that gets acted upon. Both fields live in the same attacker-crafted JSON body. In the documented multi-org configuration (`docs/setup.md` "Using Multiple Github Applications"), each organization has its own `webhook_secret`. Anyone who legitimately controls the GitHub App webhook configuration for **one** onboarded organization (Org A) can compute a valid HMAC over a forged body whose `repository.owner.login` is `"OrgA"` (so signature verification passes using Org A's secret) but whose `repository.full_name` is `"OrgB/some-repo"` — a completely different tenant's repository configured in the same Shipit instance. Handlers act on `full_name`, not `owner.login`, so this forges pushes/statuses/check-runs/PR events against Org B's stacks using only Org A's key. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

### Title
Cross-organization webhook forgery: signature verified against `repository.owner.login`'s GitHub App but handlers act on `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` picks the HMAC secret to check based on the attacker-supplied `repository.owner.login` (or `organization.login`) field of the JSON body, but the downstream `Webhooks::Handlers::Handler` (and subclasses like `PushHandler`, PR handlers) resolve the target `Repository`/`Stack` using a *different* field of the same body: `repository.full_name`. Because nothing ties these two fields together, a party who legitimately controls the webhook secret for one onboarded organization can sign a payload as "from" their own org while pointing `full_name` at a repository belonging to a different organization configured in the same Shipit instance, causing Shipit to act on that other tenant's stacks.

### Finding Description
`WebhooksController#verify_signature` computes `repository_owner` from the request body (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`), and uses it purely to select `Shipit.github(organization: repository_owner)`, i.e., which per-organization `webhook_secret` to validate the `X-Hub-Signature` against.

Once the signature check passes, `WebhooksController#create` hands the exact same parsed JSON body to `Shipit::Webhooks.for_event(event)` handlers. Every handler built on `Shipit::Webhooks::Handlers::Handler` (used by `PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler`, `EditedHandler`, `LabelCapturingHandler`) resolves the acted-upon repository via `repository_name`, which reads `payload.dig('repository', 'full_name')` - a separate field from the one used to pick the signing secret.

Binding that should hold, expressed as an equality:
`organization(repository.owner.login) == organization(repository.full_name)`

GitHub itself always keeps these consistent in real webhook deliveries, but since Shipit does not itself enforce that relationship, an attacker crafting the raw body can set them independently. In the documented "Using Multiple Github Applications" configuration, each organization gets its own `webhook_secret` in `config/secrets.yml`. Someone who is the legitimate holder of Org A's webhook secret (e.g., an admin of Org A's own GitHub App installation, who is completely unprivileged with respect to Org B) can build a body with:
```json
{"repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/target-repo"}, ...}
```
sign the raw request body with Org A's `webhook_secret`, and send it to the shared `/webhooks` endpoint. `verify_signature` looks up `Shipit.github(organization: "OrgA")` and validates successfully, because the HMAC was legitimately computed with Org A's secret over that exact body. The handler then acts on `full_name = "OrgB/target-repo"`, an entirely different tenant's `Repository`/`Stack`.

### Impact Explanation
This breaks the tenant-isolation boundary the multi-organization feature is meant to provide: `PushHandler` can trigger `stack.sync_github` (an unauthorized GitHub sync/write path) for Org B's stacks, and pull-request handlers can archive/unarchive Org B's review stacks or manipulate merge-queue-relevant labels, all without ever holding Org B's own webhook secret, session, or API token. In a shared Shipit instance onboarding multiple GitHub organizations, this is a cross-repository/cross-organization forgery: an unprivileged (with respect to the victim org) actor using only their own org's legitimate signing key can make Shipit act as if events came from a different organization's repository.

### Likelihood Explanation
Requires only that the Shipit instance is configured for more than one GitHub organization (a documented, supported feature) and that the attacker controls a legitimately configured organization's `webhook_secret` for their own tenant - which is the normal, expected level of access any onboarded organization admin has. No access to the victim organization, its GitHub App, or Shipit sessions/API tokens is needed.

### Recommendation
Verify the webhook signature using the same field that handlers use to select the acted-upon repository (`repository.full_name`'s owner segment), or explicitly assert that `repository.owner.login`/`organization.login` matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications"), and onboard a stack for `OrgB/target-repo`.
2. As the holder of `OrgA`'s `webhook_secret` (e.g., an OrgA admin, unprivileged for OrgB), build a push-event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already present on OrgB/target-repo>",
  "repository": {
    "owner": {"login": "OrgA"},
    "full_name": "OrgB/target-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` and POST to `/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgA")` and validates the signature successfully (it was legitimately computed with OrgA's secret over this exact body).
5. `PushHandler#process` resolves the stack via `payload.dig('repository', 'full_name') == "OrgB/target-repo"` and calls `stack.sync_github(expected_head_sha: ...)`, causing Shipit to act on OrgB's stack even though the request was authenticated as belonging to OrgA.

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
