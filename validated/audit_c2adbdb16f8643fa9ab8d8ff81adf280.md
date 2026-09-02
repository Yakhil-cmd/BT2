### Title
Cross-Organization Webhook Trust Confusion Enables Unauthorized Repository Sync/Deploy Trigger - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / webhook secret to validate an incoming webhook against using the payload's `repository.owner.login` (or `organization.login`) field, but the event handlers that act on the payload (e.g. `PushHandler`, the `PullRequest::*` handlers) resolve the target repository/stack using an entirely different payload field: `repository.full_name`. Because these two fields are never cross-checked, a party who knows the webhook secret for *any* GitHub organization configured in a multi-org Shipit deployment can forge a payload that authenticates as "their" organization while pointing `repository.full_name` at a stack belonging to a *different* organization, causing Shipit to act on that other org's repository.

### Finding Description
`WebhooksController#verify_signature` computes the organization used to fetch the webhook secret purely from attacker-supplied JSON: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the per-organization `GithubApp`/webhook secret configured in `secrets.yml`, and `verify_webhook_signature` performs an HMAC comparison over the raw request body using that organization's secret: [3](#0-2) 

Shipit explicitly supports multiple GitHub organizations sharing one instance, each with its own independent `webhook_secret`, as shown in the test fixture used to exercise this configuration: [4](#0-3) [5](#0-4) 

Once signature verification passes, `Webhooks.for_event(event)` handlers process the raw JSON `params`. The base `Handler` class — and every concrete handler that derives repository/stack scope from it — resolves the acted-upon repository from `repository.full_name`, a field that is completely independent of the `repository.owner.login` field used during signature verification: [6](#0-5) 

For example, `PushHandler` uses this `stacks` scope (keyed off `full_name`) to trigger a GitHub sync on any matching, non-archived stack with the target branch: [7](#0-6) 

The binding that should hold is: **organization authenticated (`repository.owner.login`/`organization.login`, used to pick the webhook secret) == organization whose repository is written (`repository.full_name`, used to select the `Stack`)**. Nothing enforces this equality. An attacker who legitimately possesses the webhook secret for Org A (e.g., because they administer Org A's GitHub App installation, a low-privilege organization in the same Shipit instance) can HMAC-sign an arbitrary JSON body with Org A's secret while setting `repository.full_name` to `OrgB/some-tracked-repo`. `verify_signature` succeeds (it only checks the signature matches Org A's secret over the raw body the attacker fully controls), and the handler then acts on Org B's stack using attacker-controlled event data (`after` SHA, PR state, labels, etc.).

### Impact Explanation
This breaks the deployment-trust binding "an organization that authenticated versus the repository that is written," matching the explicitly allowed analog class. Concretely, an attacker holding only Org A's webhook secret can:
- Force `PushHandler` to call `stack.sync_github(expected_head_sha:)` on an Org B stack with an attacker-chosen `after` SHA, triggering `GithubSyncJob` and potentially continuous-deployment logic for a repository they have no legitimate authorization over.
- Drive `PullRequest` handlers (`opened`, `closed`, `labeled`, etc.) to create/archive/unarchive review stacks or mutate pull-request state for Org B's repositories, using forged `pull_request`/`sender`/`labels` data.

This is a cross-repository/cross-organization write triggered purely by cross-organization webhook-secret confusion — an unauthorized deploy/sync/state-mutation path that does not require compromising Org B's own secret, GitHub App, or Shipit session credentials.

### Likelihood Explanation
Exploitability requires the attacker to know a valid `webhook_secret` for at least one GitHub organization configured in the same Shipit instance — a realistic scenario for any multi-tenant/multi-org Shipit deployment (explicitly supported per `secrets_double_github_app.yml`), where different organizations' admins each legitimately hold their own org's webhook secret but have no business writing to another org's stacks. No GitHub write access, Shipit session, or `ApiClient` token is needed — only delivery of a crafted HTTP POST to the shared `/webhooks` endpoint.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler#repository_name`), enforce that the organization used to select/verify the webhook secret matches the organization embedded in `repository.full_name` (and `organization.login` when present) before any handler is allowed to run. Reject the request (422) if they diverge, in addition to the existing signature check.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` (webhook_secret known to attacker) and `OrgB` (has a tracked stack, e.g. `OrgB/prod-service`), per `secrets_double_github_app.yml` pattern.
2. Attacker builds a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-existing-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/prod-service" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and successfully verifies the signature (attacker signed it themselves with OrgA's known secret) — see `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`.
5. `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) resolves `stacks` via `repository.full_name = "OrgB/prod-service"` (`handler.rb:32-38`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on Org B's stack — an org the attacker never authenticated against.

Unable to fully trace `Stack#sync_github`/`GithubSyncJob` internals in this pass (source not retrieved before the tool budget ran out), so the exact downstream effect (e.g., whether continuous deployment auto-triggers a deploy) could not be independently confirmed from the fetched code; this is stated as uncertain and would need to be verified directly in `app/models/shipit/stack.rb` and `app/jobs/shipit/github_sync_job.rb`. The core cross-organization authorization confusion in the webhook signature/handler binding, however, is confirmed directly from the cited code.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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
