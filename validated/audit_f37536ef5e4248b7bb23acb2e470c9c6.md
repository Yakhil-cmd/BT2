### Title
Cross-Organization Webhook Forgery via Mismatched Signature-Selector and Handler-Target Fields - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment (as documented and fixtured for in `test/dummy/config/secrets_double_github_app.yml`), each GitHub organization has its own `webhook_secret`. `WebhooksController#verify_signature` selects *which* organization's secret to validate the HMAC signature against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) [2](#0-1) . However, the event handlers that actually act on the payload (e.g. `PushHandler`) look up the target `Repository`/`Stack` using a **different** field: `payload.dig('repository', 'full_name')` [3](#0-2) [4](#0-3) . These two fields are never cross-checked against each other.

### Finding Description
This mirrors the reported bug class: a value used for authorization/selection (`msg.sender` selecting who gets rewarded in the Solidity report, here `repository.owner.login` selecting which secret authenticates the request) is not the same value the code subsequently acts on (`user` in the Solidity report, here `repository.full_name` used to resolve the `Repository`/`Stack`). The binding that should hold is:

`organization whose secret validated the signature == owner of the repository/stack the handler mutates`

but the code never enforces this equality. An attacker who administers `OrganizationA`'s own GitHub App installation in this shared Shipit instance knows `OrganizationA`'s `webhook_secret` and can compute a valid `X-Hub-Signature` over an arbitrary payload of their choosing. They can craft a payload with:
- `repository.owner.login = "OrganizationA"` (so `verify_signature` selects and validates against OrganizationA's known secret) [1](#0-0) 
- `repository.full_name = "OrganizationB/target-repo"` (a repository belonging to a different, unrelated organization also hosted on the same Shipit instance)

Because `PushHandler` (and other handlers) resolve the acted-upon `Stack` purely from `repository.full_name` via `Repository.from_github_repo_name` [5](#0-4) , the forged, validly-signed request is dispatched against `OrganizationB`'s stacks, e.g. triggering `stack.sync_github(expected_head_sha:)` and enqueuing `GithubSyncJob` [4](#0-3) .

### Impact Explanation
If `OrganizationB`'s stack has continuous delivery enabled, this forged push notification (asserting a specific `expected_head_sha`) can cause Shipit to automatically fetch and deploy `OrganizationB`'s real HEAD commit through its own legitimate GitHub credentials for `OrganizationB`, entirely triggered by an attacker who only ever proved control of `OrganizationA`'s webhook secret — i.e. an unauthorized deploy of another organization's stack, without ever presenting `OrganizationB`'s webhook secret or any authorization for that organization. This crosses a cross-repository/organization trust boundary that the verification step is supposed to enforce.

### Likelihood Explanation
Requires: (1) a Shipit instance configured for multiple GitHub organizations (an explicitly supported and documented configuration — see `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`), and (2) the attacker legitimately controls (as an org admin) the GitHub App/webhook secret for at least one of the organizations sharing that Shipit instance. Given multi-org Shipit installs are meant to let independent teams/orgs share one instance without trusting each other, this is a realistic unprivileged-attacker (relative to the victim org) scenario.

### Recommendation
In `WebhooksController#verify_signature`, after selecting the `github_app` config by `repository_owner`, cross-validate that the same organization value matches the owner segment of `repository.full_name` (and any other repository-identifying field consumed downstream) before dispatching to handlers; reject the request otherwise. Alternatively, derive the verifying secret strictly from a value that handlers also use to resolve the target repository, so the same field is both the thing verified and the thing acted upon.

### Proof of Concept
1. Configure Shipit with two organizations, `OrganizationA` and `OrganizationB`, each with distinct `webhook_secret`s (per `test/dummy/config/secrets_double_github_app.yml` pattern).
2. As an attacker with legitimate admin access to `OrganizationA`'s GitHub App (and thus its `webhook_secret`), build a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha claimed to exist on OrganizationB/target-repo>",
  "repository": {
    "owner": { "login": "OrganizationA" },
    "full_name": "OrganizationB/target-repo"
  }
}
```
3. Sign the raw JSON body with `OrganizationA`'s `webhook_secret` using HMAC-SHA1, as `Hook::DeliverySigner`/`GitHubApp#verify_webhook_signature` expect [6](#0-5) .
4. `POST` to `/github_webhooks` (or the mounted webhooks path) with `X-Github-Event: push` and the computed `X-Hub-Signature`.
5. `verify_signature` resolves `Shipit.github(organization: "OrganizationA")` and successfully verifies the signature [1](#0-0) .
6. `PushHandler#process` resolves stacks via `repository.full_name = "OrganizationB/target-repo"` and enqueues `GithubSyncJob` for `OrganizationB`'s stack [4](#0-3) , triggering sync/deploy activity for an organization the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
