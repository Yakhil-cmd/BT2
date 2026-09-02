### Title
Cross-Organization Webhook Forgery via Decoupled Signature-Verification Field and Repository-Routing Field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and thus which `webhook_secret`) to verify a webhook against using `repository_owner`, a value read directly from the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`). Every webhook handler, however, decides *which repository/stack to actually act on* using a different field from the same untrusted body: `repository.full_name`, read in the shared `Handler#repository_name` method. These two fields are never checked for consistency, and are not covered together by any single cryptographic binding.

### Finding Description
`verify_signature` in [1](#0-0)  computes `repository_owner` from the request body itself: [2](#0-1) 
and uses it purely to pick which organization's `github_app`/`webhook_secret` config to validate the HMAC signature against: [3](#0-2) 

Note that `verify_webhook_signature` short-circuits to `true` when that organization's `webhook_secret` is blank — a state explicitly documented as a supported, optional configuration ("Webhook secret (optional)", `docs/setup.md`), and used by default in the dummy/test config (`webhook_secret: # nil`).

Separately, every concrete handler (`PushHandler`, pull-request handlers, etc.) resolves the target repository/stack from a *different* JSON field, `repository.full_name`, in the shared base class: [4](#0-3) 
which is then used, e.g. in `PushHandler#process`, to look up and mutate stacks belonging to that repository: [5](#0-4) 

`Repository.from_github_repo_name` blindly splits and looks up whatever owner/name pair is supplied: [6](#0-5) 

Because Shipit explicitly supports multi-tenant configuration where each GitHub organization has its own independent `webhook_secret` (`docs/setup.md` "Using Multiple Github Applications", `config/secrets.development.example.yml`), the equality the code implicitly assumes — `repository.owner.login (verified) == repository.full_name's owner (acted upon)` — is never enforced. A real GitHub-originated webhook always keeps these consistent, but this endpoint accepts arbitrary POST bodies from any network client at `/webhooks`, so an unprivileged attacker can set them independently.

**Binding broken:** organization authenticated (`repository_owner` used to pick the `webhook_secret`) ≠ repository that is written (`repository.full_name` used by every `Handler` subclass to resolve stacks and mutate their state).

### Impact Explanation
If any organization configured in the (multi-org) `Shipit.github` config has a blank `webhook_secret` — an explicitly documented, supported, non-privileged configuration state — `verify_webhook_signature` returns `true` unconditionally for a payload naming that organization as `repository.owner.login`, regardless of the actual `X-Hub-Signature` header value. An attacker can then set `repository.full_name` to an arbitrary victim repository/organization hosted on the same Shipit instance. Every handler downstream (push, pull_request, check_suite, status, etc.) resolves the *actual* target purely from `repository.full_name`, so the forged event is dispatched against the victim stack: triggering `sync_github`, refreshing check runs/statuses that back automated merge/deploy decisions, and otherwise injecting attacker-controlled state into a repository the attacker never authenticated against. This is a cross-repository write achieved purely by satisfying signature verification for an unrelated, low-security-posture tenant — matching the "cross-repository writes / unauthorized deploy" Critical impact class.

### Likelihood Explanation
Requires no credentials, no `ApiClient` token, no GitHub App private key, and no repository write access — only that the Shipit deployment hosts at least one organization without a webhook secret (a documented "optional" setting) alongside a higher-value victim organization. `/webhooks` is a public unauthenticated endpoint (`skip_before_action :verify_authenticity_token`) reachable by any network client.

### Recommendation
Bind the field used for signature routing/verification to the same field used to resolve the acted-upon repository: derive `repository_owner` from `repository.full_name` (or validate that `repository.owner.login` and `repository.full_name`'s owner segment match) before dispatch, and require a non-blank `webhook_secret` for every configured organization (disallow the blank/`return true` bypass in `verify_webhook_signature`).

### Proof of Concept
1. Deploy Shipit with a multi-org config: `victim-org` (has a stack, has `webhook_secret` set) and `attacker-org` (installed, but `webhook_secret` left blank per the documented optional setting).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
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
3. `verify_signature` resolves `repository_owner = "attacker-org"`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` immediately — no valid signature required.
4. `PushHandler#process` (via `Handler#repository_name`) resolves the target repository from `repository.full_name = "victim-org/victim-repo"`, looks up `victim-org`'s stacks, and invokes `stack.sync_github(...)`, all without the attacker ever possessing `victim-org`'s webhook secret.

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
