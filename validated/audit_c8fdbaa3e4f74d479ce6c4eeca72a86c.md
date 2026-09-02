### Title
Webhook signature verification keys off `repository.owner.login` while every handler acts on `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to authenticate an incoming webhook from an attacker-controlled field in the *unverified* JSON body (`repository.owner.login`, or `organization.login` as fallback), then verifies the raw body against that org's `webhook_secret`. Every event handler, however, resolves the actual `Stack`/`Repository` it acts on from a *different* field in the same unverified body: `repository.full_name` [1](#0-0) . Nothing ties the org that produced a valid signature to the org/repo the handler subsequently mutates.

### Finding Description
`verify_signature` picks the `GitHubApp` instance using a value pulled straight out of the untrusted payload before any cryptographic check has happened: [2](#0-1) [3](#0-2) 

`Shipit.github(organization:)` looks up per-organization config, including an **optional** `webhook_secret` (explicitly documented as optional, and multi-org configuration is a first-class supported setup) [4](#0-3) . When a secret is blank, verification is a no-op: [5](#0-4) 

Meanwhile, none of the handlers use `repository.owner.login` to scope which repository/stack they touch — they resolve it from `repository.full_name`: [1](#0-0) [6](#0-5) 

This is exactly the bug class in the reference report: a field the code trusts and acts on (`repository.full_name` → which `Stack` gets synced/mutated) is not the field that was actually covered by the authentication decision (`repository.owner.login` → which org's secret gated the request). The binding that should hold is:

`org whose webhook_secret authenticated the request == org that owns the repository/stack being mutated`

but the code never enforces it — it only enforces "some configured org's secret matched (or that org has no secret at all)".

### Impact Explanation
On a Shipit instance configured with multiple GitHub organizations (an officially supported and documented topology), if any one configured organization has no `webhook_secret` set (which the setup docs call out as optional), an unauthenticated network attacker can send a POST to `/webhooks` with:
- `X-Github-Event: push`
- body `repository.owner.login` = the org with no secret (or `organization.login` for the membership fallback path)
- body `repository.full_name` = a stack belonging to a *different*, properly secured organization

`verify_signature` resolves the no-secret org, trivially "verifies" (any/no signature accepted), and the request proceeds. `PushHandler` (and the `pull_request`/`status` handlers, which behave identically) then look up and act on the `Stack` identified by `repository.full_name`, which belongs to the org that was never authenticated for this request. For push events this triggers `stack.sync_github(expected_head_sha:)`, letting an outsider inject an attacker-chosen `expected_head_sha` into a protected stack's sync/build pipeline. This is a genuine authentication-boundary crossing (organization authenticated vs. repository/stack actually written), matching the report's core defect of "field acted upon but not covered by the check that gated processing."

I was not able to fully trace `Stack#sync_github` / `GithubSyncJob` to confirm whether this can be escalated all the way to an actual unauthorized deploy or merge (tool budget ran out before reading `app/models/shipit/stack.rb` and `app/jobs/shipit/github_sync_job.rb`), so the downstream severity (unauthorized deploy vs. merely forged sync/status state) is not fully confirmed.

### Likelihood Explanation
Requires: (a) a multi-org Shipit deployment (documented, supported configuration), and (b) at least one configured org left without a `webhook_secret` — which the setup docs explicitly present as optional/acceptable. Given that, the attack requires only an unauthenticated HTTP POST with a crafted JSON body; no session, API token, or GitHub credentials of any kind are needed. This makes exploitation straightforward whenever the precondition holds, but the precondition (an org intentionally or accidentally left with no webhook secret in a multi-org setup) is not the default single-org configuration.

### Recommendation
After signature verification succeeds, re-derive the acting organization from the same, now-trusted request and enforce that `repository.full_name`'s owner matches the organization whose secret validated the request (or explicitly require every configured `webhook_secret` to be present in multi-org mode, refusing to start with any organization missing one). Do not let `repository.full_name`/`organization.login` be trusted for repository/stack resolution unless it is consistent with the org that authenticated the request.

### Proof of Concept
1. Configure Shipit with two GitHub orgs per the documented multi-org format: `OrgA` (no `webhook_secret` set) and `OrgB` (a real, secret-protected stack, e.g. `OrgB/protected-repo`).
2. As an anonymous attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/protected-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`; since `OrgA` has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally [7](#0-6) .
4. `PushHandler` resolves the stack via `repository.full_name` = `OrgB/protected-repo` [1](#0-0)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` [8](#0-7) , despite the request never being authenticated against `OrgB`'s credentials.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
