### Title
Webhook organization used for signature verification is never checked against the repository the event actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a webhook's HMAC using `repository_owner`, which is read from the `repository.owner.login` field of the raw JSON body [1](#0-0) [2](#0-1) . Once the signature check passes, the event is dispatched to handlers that instead resolve the target `Stack`/`Repository` from a *different* field of the same body, `repository.full_name`, via `Handler#repository_name`/`#stacks` [3](#0-2) . Nothing ties `repository.owner.login` (the identity whose secret authenticated the payload) to `repository.full_name` (the identity whose data actually gets written).

### Finding Description
Shipit supports hosting multiple GitHub organizations from a single instance, each with its own `webhook_secret` [4](#0-3) . `Shipit.github(organization: repository_owner)` picks the secret for `repository_owner` and `verify_webhook_signature` HMACs the *entire raw body* against that secret [5](#0-4) . Because the HMAC covers the whole body, anyone who legitimately knows one organization's `webhook_secret` (e.g., an admin of their own low-value org onboarded onto the same Shipit instance) can compute a valid signature for an arbitrary JSON payload, as long as `repository.owner.login` in that payload equals their own org.

The vulnerable binding is:
`authenticated_org (repository.owner.login, verified by signature) == acted_upon_repo (repository.full_name, used by PushHandler/StatusHandler/CheckSuite/PullRequest handlers)`

This equality is never checked. An attacker who controls org `A`'s webhook secret can submit a payload where `repository.owner.login = "A"` (so it authenticates against `A`'s secret) but `repository.full_name = "victim-org/victim-repo"` (an unrelated tracked repository belonging to org `B`). `PushHandler#process` resolves stacks purely from `full_name` and enqueues `stack.sync_github` for whatever stack matches, regardless of who authenticated the request [6](#0-5) . `StatusHandler`, `check_suite_handler.rb`, and the `pull_request/*` handlers (which create/archive Review Stacks) follow the same pattern, all deriving their target purely from `repository.full_name`/`payload['repository']['full_name']` without cross-checking the org used for signature verification.

This is the direct analog to the reported Solana bug: `deposit`/`solana_ibc::cpi::set_stake` trusted `remaining_accounts` without validating that the accounts operated on were the ones actually authorized for the caller. Here, Shipit trusts `repository.full_name` to select the object to mutate without validating it against the organization whose credential (`webhook_secret`) actually authenticated the request.

### Impact Explanation
An attacker with legitimate access to one organization's webhook secret (a normal, low-privilege condition for any org onboarded to a shared Shipit instance) can forge webhook events that are processed as if they came from GitHub for a completely different, unrelated tracked repository/organization. This allows unauthorized state changes on stacks the attacker does not own or have any GitHub permission over — e.g., forcing `GithubSyncJob` enqueues, creating/archiving Review Stacks for arbitrary tracked repositories via the `pull_request` handlers — a cross-repository write crossing an authentication boundary that should isolate tenants from one another. This matches the report's "Critical: cross-repository writes" category.

### Likelihood Explanation
Requires only knowledge of a `webhook_secret` for *any one* organization configured on the shared Shipit instance (an expected, low-privilege credential for a tenant admin, not a Shipit session, GitHub App private key, or `api_clients_secret`), plus the ability to craft an arbitrary JSON POST to the public `/webhooks` endpoint. No GitHub interaction is required since the controller does not validate that GitHub itself sent the request beyond the HMAC, and the HMAC is computed over attacker-controlled bytes.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), after signature verification, assert that the organization derived from `repository.full_name` (or `organization.login` for org-level events) equals the `repository_owner` used to select the signing secret, and reject (422) any payload where they diverge. Handlers should also independently confirm the mutated repository/stack belongs to the authenticated organization before acting.

### Proof of Concept
1. Attacker is the admin of GitHub org `attacker-org`, configured in Shipit's multi-org `github:` secrets with `webhook_secret: S`. This is legitimate access to their own tenant's secret.
2. Attacker crafts a `push` event body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S, body)` — valid, since `verify_signature` looks up the secret for `attacker-org` (from `owner.login`) [1](#0-0) .
4. `POST /webhooks/github` with `X-Github-Event: push` passes signature verification.
5. `PushHandler` resolves `stacks` from `repository.full_name = "victim-org/victim-repo"` [3](#0-2)  and enqueues `sync_github` for that stack [6](#0-5) , despite the attacker having no relationship to `victim-org`.

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

**File:** docs/setup.md (L181-209)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
