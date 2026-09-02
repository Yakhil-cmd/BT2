### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, while the repository actually mutated is derived from the unverified `repository.full_name` field, enabling cross-repository/cross-organization writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the HMAC signature against using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) from the raw, attacker-suppliable JSON body: [1](#0-0) [2](#0-1) 

Shipit supports multiple configured GitHub Apps/organizations, each with its own independent `webhook_secret` (confirmed by the `secrets_double_github_app.yml` test fixture and `lib/shipit/github_app.rb`'s per-instance `@webhook_secret`) [3](#0-2) . `verify_webhook_signature` only proves that the raw body was HMAC-signed with *some* organization's secret — the one picked by `repository_owner` — using a constant-time compare [4](#0-3) .

Once the signature check for `repository_owner`'s secret passes, control reaches the handlers, which resolve the actual `Repository`/`Stack` to mutate using a *different* field of the same JSON body — `repository.full_name` — never cross-checked against `repository.owner.login`: [5](#0-4) 

For example, the push handler syncs commits into whatever stack matches `repository.full_name` and the target branch: [6](#0-5) 

and several PR handlers (`OpenedHandler`, `LabeledHandler`, `ClosedHandler`, etc.) resolve the acted-upon repository the same way, via `params.repository.full_name`, independent of `repository.owner.login`: [7](#0-6) 

The binding the code should enforce but doesn't is: `organization authenticated by webhook signature == organization owning the repository that gets written`. Instead the code enforces only: `organization authenticated == repository.owner.login (attacker-controlled field)`, and separately trusts `repository.full_name (also attacker-controlled, same payload)` to select the write target, with no equality check between the two.

### Impact Explanation
In a multi-org Shipit deployment, an attacker who can obtain (or configure, e.g. via their own legitimately-registered webhook on a repository they control in Org A) the `webhook_secret` for Org A can forge a raw webhook POST directly to Shipit's public `/webhooks` endpoint with:
- `repository.owner.login = "OrgA"` (used only to pick the verification secret)
- `repository.full_name = "OrgB/victim-repo"` (used to pick the Stack/Repository that is actually mutated)

The signature check passes (it is valid for Org A's secret), and the handler proceeds to act on Org B's stack: syncing pushes/commits, setting commit statuses, updating PR labels, archiving/unarchiving review stacks, etc. — all state belonging to a repository/organization the attacker never had legitimate access to and whose real webhook secret they never compromised. This matches the "cross-repository writes" Critical-impact category, since it lets an attacker use credentials scoped to one org to write into a completely different, unrelated repository's Shipit state.

### Likelihood Explanation
Exploitability requires: (1) a Shipit deployment configured with more than one GitHub App/organization (a supported, documented configuration per `docs/setup.md` and the `secrets_double_github_app.yml` fixture), and (2) the attacker possessing a valid webhook secret for at least one configured organization — which is realistic since organization admins/repo owners routinely have access to configure and thus know the webhook secret used for their own org's Shipit integration. No GitHub App private key, session, or `ApiClient` token is required — only the ability to send an HTTP POST with a correctly computed HMAC for one org's secret to the public, unauthenticated webhook endpoint.

### Recommendation
After verifying the webhook signature, cross-check that the organization used to select the verification secret matches the actual owner of `repository.full_name` (or resolve the target `Repository`/`Stack` strictly from the same trusted identity that was used for signature verification, e.g. verify webhook secrets per-repository rather than per-organization-from-payload, or require `repository.owner.login` to equal the owner segment of `repository.full_name`).

### Proof of Concept
1. Deploy Shipit configured with two GitHub Apps/organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as supported per `test/dummy/config/secrets_double_github_app.yml`).
2. As an attacker with legitimate access to `OrgA` (and thus its `webhook_secret`), craft a raw JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "OrgB/victim-repo",
    "owner": { "login": "OrgA" }
  }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature verifies successfully.
5. `PushHandler#process` (via `Handler#stacks`/`#repository_name`) resolves the target stacks using `repository.full_name == "OrgB/victim-repo"`, and triggers `sync_github` / other mutations on `OrgB`'s stack — despite the request only being validly signed for `OrgA`.

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
