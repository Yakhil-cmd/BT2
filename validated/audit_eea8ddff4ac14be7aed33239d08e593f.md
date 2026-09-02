### Title
Webhook signature-verification key selection can be bound to a different GitHub organization than the repository whose data gets written - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify a payload against using an attacker-controlled JSON field (`repository.owner.login`, falling back to `organization.login`), rather than the repository that the corresponding handler actually writes to (`repository.full_name`). If any configured organization has no `webhook_secret` set, `GitHubApp#verify_webhook_signature` unconditionally returns `true` for that organization, allowing an unauthenticated caller to submit an arbitrary, unsigned payload whose `repository.full_name` points at a different (victim) organization/repo, and have it processed as if it came from GitHub.

### Finding Description
The webhook signature check picks which organization's secret to verify against straight from the untrusted payload: [1](#0-0) [2](#0-1) 

`repository_owner` is read directly from the request body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`) before any authenticity is established. This value is used only to pick `Shipit.github(organization: repository_owner)` and thus which webhook secret to HMAC-verify against: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` when no `webhook_secret` is configured for that organization (webhook secret is documented as *optional* per-organization: `docs/setup.md` line 30). Meanwhile, the actual data-mutating logic in every handler determines the target repository independently, from a *different* payload field, `repository.full_name`: [4](#0-3) [5](#0-4) 

Because GitHub normally guarantees `repository.owner.login` and `repository.full_name` refer to the same repository, Shipit never validates that the organization used to authenticate the request equals the organization whose repository/stack is actually mutated. An attacker who knows (or controls) an organization configured on this Shipit instance with no `webhook_secret` set can send `POST /webhooks` with `X-Github-Event: push`, `repository.owner.login` set to that secretless organization, but `repository.full_name` set to `victim-org/victim-repo`. `verify_signature` will pass unconditionally (no secret to check against), and `PushHandler#process` will then locate the victim stack via `Repository.from_github_repo_name(params.repository.full_name)` and enqueue `stack.sync_github(expected_head_sha: params.after)` with an attacker-chosen `after` sha — a write into a repository/organization that never authenticated the request at all.

This is the "organization that authenticated versus the repository that is written" binding: the equality `organization_verified == organization_of(repository_written)` is assumed by the code but never enforced.

### Impact Explanation
If reachable (i.e., if any onboarded organization in a multi-org Shipit deployment has no `webhook_secret` configured, which the setup docs explicitly allow), this permits an unauthenticated actor to inject fabricated GitHub events (push shas, statuses, pull-request/membership/team events) that get processed as if verified, for repositories belonging to organizations that never authorized the request. Downstream effects include forcing `GithubSyncJob` to sync a stack against an attacker-chosen `expected_head_sha`, manipulating commit/status state, or team/membership changes — all of which can feed into unauthorized deploy/merge decisions. This matches the "cross-repository writes" / "unauthorized deploy" impact bar in scope.

### Likelihood Explanation
Exploitability is conditional: it requires that at least one organization configured in `Shipit.github` mapping has `webhook_secret` blank (explicitly supported/optional per `docs/setup.md`). In single-organization/single-secret deployments this does not apply. In deployments supporting multiple GitHub organizations (`test/dummy/config/secrets_double_github_app.yml` demonstrates multi-org config exists as a supported feature) where one org's secret was left unset, the attack requires no credentials at all — just knowledge of that org's login and any target repo's `full_name`, both public/discoverable information. No session, API token, or webhook secret is needed.

### Recommendation
- Cross-check that `repository_owner` used for secret selection is consistent with the organization of `repository.full_name` (or `organization.login`) actually processed by handlers, rejecting mismatches.
- Do not allow `verify_webhook_signature` to silently pass when `webhook_secret` is unset for a configured organization; require an explicit signature for every organization capable of triggering repository/stack mutations, or refuse to process events for organizations without a secret.
- Consider deriving the verification target strictly from a canonical, single payload field and re-deriving the acted-upon repository from that same field, rather than trusting independently-read JSON keys.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `victim-org` (with `webhook_secret` set) and `no-secret-org` (with `webhook_secret` left blank/omitted), as supported by `Shipit.github(organization:)` multi-org lookup.
2. Send:
```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "no-secret-org" }
  }
}
```
(No `X-Hub-Signature` header required, or any arbitrary value.)
3. `verify_signature` calls `Shipit.github(organization: "no-secret-org")`; since that org has no `webhook_secret`, `verify_webhook_signature` returns `true` (`lib/shipit/github_app.rb` line 77), bypassing signature checking entirely.
4. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `stack.sync_github(expected_head_sha: "deadbeef...")`, mutating the victim organization's stack state, despite the request never being authenticated for `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
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
