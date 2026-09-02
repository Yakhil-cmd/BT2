### Title
Cross-organization webhook forgery via mismatched signature-org and payload-repository fields - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC validation based on `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`), but the webhook handlers that actually mutate state resolve the target repository/stack from a *different* payload field: `payload.dig('repository','full_name')`. Because the two fields are never cross-checked against each other, a party who legitimately possesses the webhook secret for *one* organization onboarded to this Shipit instance can forge a signed payload whose `repository.owner.login` matches their own org (so signature verification passes) while `repository.full_name` points at a stack belonging to a completely different organization, causing that unrelated stack to be acted upon.

### Finding Description
`verify_signature` picks the `GithubApp` (and thus the HMAC secret) using `repository_owner`: [1](#0-0) [2](#0-1) 

The HMAC is computed with `webhook_secret`, which is configured per-organization inside `GithubApp#initialize` and checked in `verify_webhook_signature`: [3](#0-2) [4](#0-3) 

Once the signature is accepted, `Handler#stacks`/`#repository_name` resolves the actual write target from a *different* JSON field, `repository.full_name`, with no assertion that this repository actually belongs to `repository_owner`: [5](#0-4) 

`PushHandler#process` then triggers `stack.sync_github(expected_head_sha: params.after)` for every matching stack, using attacker-chosen `ref`/`after` values: [6](#0-5) 

The equality the system is supposed to enforce is:
`organization whose secret authenticated the request == organization that owns the repository/stack being written`

Because signature verification is keyed off `repository.owner.login`/`organization.login` while the mutation is keyed off `repository.full_name`, this equality is never checked. Anyone holding a valid webhook secret for *any* organization configured in the Shipit instance (i.e., anyone who legitimately administers a GitHub App/webhook for their own onboarded org) can substitute an arbitrary `repository.full_name` belonging to a different organization and have the corresponding handler act on that unrelated stack.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding explicitly called out as in-scope. A holder of one organization's webhook secret can direct writes (e.g., forcing `GithubSyncJob`/`sync_github` calls with attacker-chosen `expected_head_sha`, or reaching other handlers keyed similarly) against stacks belonging to an entirely different, unrelated organization hosted on the same Shipit instance — a cross-repository/cross-organization write achieved without any credentials for the victim organization. This matches the Critical "cross-repository writes" impact category.

### Likelihood Explanation
Exploitation requires only possession of a legitimately-issued webhook secret for *some* organization on the shared Shipit instance — something any onboarded org administrator has by design — plus the ability to POST an arbitrary JSON body with a matching HMAC signature to the public `/github/webhooks` endpoint. No Shipit session, API token, or access to the victim repository is required, so likelihood is high in any deployment that hosts more than one organization/customer behind a single Shipit engine instance.

### Recommendation
After verifying the signature, re-derive `repository_owner` from `repository.full_name` (or another field consistently tied to the same trust domain) and reject the request if it does not match the organization/App whose secret validated the signature. Alternatively, have handlers re-verify that `Repository.from_github_repo_name(repository_name)`'s owning organization equals `repository_owner` before performing any mutation.

### Proof of Concept
1. Obtain the webhook secret configured for organization `attacker-org` (legitimately onboarded to the shared Shipit instance).
2. Craft a payload:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
3. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(attacker-org secret, raw_body)`.
4. POST to `/github/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and the signature validates. `PushHandler` then resolves stacks via `repository.full_name = "victim-org/victim-repo"` and calls `sync_github(expected_head_sha: "deadbeef...")` on the victim's stack, despite the attacker having no relationship to `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
```
