### Title
Webhook signature verification binds the wrong organization to the repository actually written by the handler - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC signature against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. But the handlers that actually act on the payload (`Shipit::Webhooks::Handlers::Handler#repository_name`, and every `PullRequest::*Handler#repository`) locate the target `Shipit::Repository` using a *different* field of the same JSON body: `payload.dig('repository', 'full_name')`. These two fields are never checked against each other, so a valid signature for organization A only proves the request body was signed by A's secret - it proves nothing about which repository the same body's `repository.full_name` field claims to target.

### Finding Description
The equality the system implicitly relies on is:

`organization whose webhook_secret authenticated the request == organization owning the repository that is written by the handler`

In `verify_signature`, the org used to fetch the `GitHubApp`/secret is derived from `repository.owner.login` (or `organization.login`): [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` only checks the HMAC of `raw_post` against that org's configured `webhook_secret`, and explicitly returns `true` with no check at all if that org has no `webhook_secret` configured: [3](#0-2) 

The default install scaffold (`template.rb`) leaves `webhook_secret:` blank for both the development and production GitHub App config, so an unconfigured/no-secret organization is a realistic, expected default state rather than a misconfiguration: [4](#0-3) 

Meanwhile, every handler that actually performs a write resolves the target repository/stacks from a **separate** field in the same body - `repository.full_name` - never cross-checked against `repository.owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-upon repository) are independent, attacker-controlled strings within the same unsigned-or-weakly-signed body, an attacker who can produce a payload that passes signature verification for *any* configured organization (e.g. one with no `webhook_secret` set, or an org whose secret has otherwise leaked/is weak) can set `repository.owner.login`/`organization.login` to that organization while setting `repository.full_name` to `victim-org/victim-repo` - a completely different, properly-secured repository. The `PushHandler` will then locate and act on the victim's `Stack`s via `Repository.from_github_repo_name(repository_name)`: [8](#0-7) 

This lets the attacker call `stack.sync_github(expected_head_sha:)` on stacks belonging to a repository/org whose secret they never possessed, purely because the signature check validated a different organization than the one whose data gets mutated.

### Impact Explanation
This breaks the binding "the organization that authenticated the webhook == the repository that is written," letting an attacker who controls (or can forge for) one weakly-configured/no-secret organization spoof push, pull_request, and check_suite events against a different, properly secured repository/stack that they have no legitimate access to. Depending on the handler reached, this can trigger unintended repository/stack synchronization (`sync_github`), archive/unarchive of review stacks, and team/membership creation - all without ever having the victim organization's real webhook secret. This is a cross-repository/cross-organization write triggered purely by request forgery.

### Likelihood Explanation
Requires only network access to the public webhooks endpoint plus knowledge of any one organization name configured in the Shipit instance that has no `webhook_secret` set (a documented/default configuration state per `template.rb`) or whose secret is otherwise known/guessable. No GitHub App private key, `ApiClient` token, or authenticated Shipit session is needed — only the ability to send an HTTP POST with a crafted JSON body and `X-Github-Event` header.

### Recommendation
Handlers should resolve and enforce the target organization/repository using the same field used for signature verification, e.g. reject the payload (or re-verify) if `repository.full_name`'s owner segment does not match `repository.owner.login`/`organization.login`, or simply derive the org used for signature verification from `repository.full_name` itself so both checks are bound to the same value. Additionally, requiring a non-blank `webhook_secret` for every configured organization (failing closed rather than open when absent) would remove the "any org with no secret authenticates anything" bypass.

### Proof of Concept
1. Shipit is configured with two organizations: `victim-org` (has a `webhook_secret` and a tracked repository/stack `victim-org/victim-repo`) and `attacker-org` (configured but with no `webhook_secret`, matching the default scaffold in `template.rb`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and since that org has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:77`) — no valid signature is required at all.
4. `PushHandler#process` (via `Handler#stacks` / `Handler#repository_name`) reads `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"`, resolves the real `victim-org/victim-repo` stacks, and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on them — an action on a repository the attacker never authenticated against.

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

**File:** template.rb (L97-111)
```ruby
    production:
      app_name: My Shipit
      secret_key_base: <%= ENV['SECRET_KEY_BASE'] %>
      host: <%= ENV['SHIPIT_HOST'] %>
      redis_url: <%= ENV['REDIS_URL'] %>
      github:
        domain: # defaults to github.com
        app_id: <%= ENV['GITHUB_APP_ID'] %>
        installation_id: <%= ENV['GITHUB_INSTALLATION_ID'] %>
        webhook_secret:
        private_key:
        oauth:
          id: <%= ENV['GITHUB_OAUTH_ID'] %>
          secret: <%= ENV['GITHUB_OAUTH_SECRET'] %>
          # teams: MyOrg/developers # Enable this setting to restrict access to only the member of a team
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L49-54)
```ruby

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
