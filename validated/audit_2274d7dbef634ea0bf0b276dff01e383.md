### Title
Webhook signature verified against organization named in payload while stack writes are scoped by a different, unvalidated repository field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), both taken directly from the attacker-supplied JSON body. Once the signature check passes, `Shipit::Webhooks::Handlers::Handler#stacks` resolves the actual `Repository`/`Stack` to act on using a *different* field from the same body: `payload.dig('repository', 'full_name')`. Neither value is cross-checked against the other, so the field that selects the trusted secret and the field that selects the write target are independent and both attacker-controlled.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` does: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the unauthenticated JSON payload and used to pick which configured `Shipit::GitHubApp` (and its `webhook_secret`) verifies the request via `Shipit.github(organization: repository_owner)` / `GithubApp#verify_webhook_signature`, which does a `SecureCompare` HMAC-SHA1 check against that organization's secret: [3](#0-2) 

Shipit explicitly supports hosting multiple GitHub organizations/App configs simultaneously (confirmed by `test/unit/shipit_test.rb`'s multi-app test and `TOP_LEVEL_GH_KEYS`/`Shipit.github(organization:)` lookup in `lib/shipit.rb`).

After the signature is accepted, `WebhooksController#create` dispatches to handlers with the raw parsed payload: [4](#0-3) 

Every handler subclasses `Shipit::Webhooks::Handlers::Handler`, whose `stacks` method looks up the affected repository using a *different* payload key, `repository.full_name`, with no comparison back to `repository.owner.login` used for signature selection: [5](#0-4) 

Because the entire raw POST body is attacker-controlled JSON (it's simply what gets HMAC'd), an attacker who knows/controls the `webhook_secret` for **any one** organization configured on the multi-tenant Shipit instance can craft a body where:
- `repository.owner.login` (or top-level `organization.login`) = the org whose secret they know (call it `attacker-org`), so `verify_signature` selects `attacker-org`'s secret and the HMAC matches, and
- `repository.full_name` = `"victim-org/victim-repo"`, an entirely different, unrelated organization/repository hosted on the same Shipit instance.

`verify_signature` never checks that `repository.owner.login` agrees with `repository.full_name`'s owner segment, and handler `stacks`/`repository` lookups never re-derive or validate against the field used for signature selection. This is exactly the "organization that authenticated vs. repository that is written" trust binding: equality `signing_org == written_repo.owner` is assumed but never enforced.

### Impact Explanation
This is a cross-repository/cross-organization write from an attacker who is only trusted for one tenant on a shared Shipit instance:
- `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) enqueues `stack.sync_github(expected_head_sha: ...)` for any `victim-org/victim-repo` stack matching the forged `full_name`/branch, causing Shipit to fetch/append commits and re-cache the deploy spec for a repo the attacker doesn't own.
- `PullRequest::OpenedHandler`/`ClosedHandler`/`LabeledHandler`/`UnlabeledHandler` (`app/models/shipit/webhooks/handlers/pull_request/*.rb`) can create, archive, unarchive, or deprovision **review stacks** for the victim repository, and `ReviewStackAdapter#unarchive!`/`#create!` enqueue `Shipit::ReviewStackProvisioningQueue.add(stack)`, which can trigger real provisioning/deprovisioning side effects.
- `CheckSuiteHandler` schedules check-run refreshes against victim commits.

This satisfies the "cross-repository writes" Critical impact category defined in the rules, achieved purely by forging a webhook body — no Shipit session, `ApiClient` token, or GitHub App private key for the victim org is required, only knowledge of one (possibly low-value/attacker-controlled) tenant's `webhook_secret`.

### Likelihood Explanation
Requires: (1) the Shipit instance to serve more than one GitHub organization (an explicitly supported configuration per `lib/shipit.rb`/`TOP_LEVEL_GH_KEYS` and the multi-app test fixture), and (2) the attacker to know/control the `webhook_secret` of at least one of those organizations — e.g., their own org onboarded onto the same shared instance, or a leaked/rotated secret for a low-trust tenant. Given that, forging the request is trivial (a single signed HTTP POST with an internally-inconsistent payload). No other authentication boundary needs to be crossed.

### Recommendation
In `Shipit::Webhooks::Handlers::Handler`, derive the "owner" used to authorize/verify the webhook the same way the write target is resolved, and require they match: reject the event if `repository.full_name`'s owner segment does not equal the `repository.owner.login`/`organization.login` that selected the signing secret in `verify_signature`. Concretely, pass the verified `repository_owner` (already computed in `WebhooksController`) into the handler dispatch and have `Handler#stacks`/`#repository` assert `repository_name.split('/').first.casecmp?(verified_owner)` before performing any lookup or mutation, raising/dropping the event otherwise.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`) with two organizations, `attacker-org` and `victim-org`, each with its own `github.webhook_secret` (a normal multi-tenant Shipit setup).
2. As a party who knows `attacker-org`'s webhook secret (e.g., because you administer the `attacker-org` GitHub App installation), build a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(attacker-org secret, body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `webhook_secret`, and the HMAC matches → request is accepted (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `PushHandler#process` calls `Handler#stacks`, which resolves `Repository.from_github_repo_name("victim-org/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and triggers `sync_github` on `victim-org`'s stack(s) — a write to a repository/organization the attacker never authenticated for.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L26-38)
```ruby
        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
