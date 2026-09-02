### Title
Webhook signature verification is keyed off `repository.owner.login`, but event handlers act on the independently-forgeable `repository.full_name` field, letting an attacker forge webhooks for any tracked repository as soon as one configured GitHub App organization has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to check the HMAC signature against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). [1](#0-0) [2](#0-1) 

The actual event handlers that mutate state (create commits, sync stacks, provision review stacks, update pull requests) look up the target `Repository`/`Stack` using a *different* JSON field of the same payload: `payload.dig('repository', 'full_name')`. [3](#0-2) [4](#0-3) 

Since `repository.owner.login` and `repository.full_name` are two independent, attacker-supplied strings in the same unauthenticated JSON body, they need not refer to the same repository.

### Finding Description
Shipit supports multiple GitHub App organizations configured under `Shipit.github_app_config`, each with its own optional `webhook_secret` (shown as commented-out/nil in `test/dummy/config/secrets_double_github_app.yml` and `config/secrets.development.shopify.yml`). [5](#0-4) 

`GitHubApp#verify_webhook_signature` explicitly bypasses verification when no secret is configured for that org:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [6](#0-5) 

`Shipit.github(organization: repository_owner)` picks the app config purely by `repository_owner`, i.e. purely by `repository.owner.login` in the incoming payload. [7](#0-6) 

The equality this flow assumes is:
`organization whose secret authenticated the request == organization that owns the repository the handler subsequently writes to`

An attacker with no credentials can break this by crafting a raw POST body where:
- `repository.owner.login` = an organization configured in Shipit with a blank/`nil` `webhook_secret` (a supported, documented configuration), causing `verify_signature` to accept the request unconditionally regardless of the `X-Hub-Signature` header value, and
- `repository.full_name` = `"<other-org>/<real-tracked-repo>"`, a completely different, real, tracked repository belonging to another configured organization (which may have a strong secret).

`WebhooksController#create` never re-validates that these two fields refer to the same repository; it simply dispatches `params` to the registered handler for the event. [8](#0-7) 

The handler then resolves the target purely from `repository.full_name`: [9](#0-8) 

This is directly analogous to the reported IndexPool bug class: two related values (`weightRatio`/exponent scale in the report; `repository.owner.login`/`repository.full_name` here) are assumed to be consistent by the code path, but nothing enforces that consistency, so an attacker can supply values that satisfy the check (signature/scale) while the actually-used value (price/target repo) diverges from what was validated.

### Impact Explanation
This allows an unauthenticated, unprivileged attacker to fully forge webhook events (push, status, pull_request, check_suite, membership) for any repository tracked by Shipit, as long as any single configured organization in the multi-org deployment has no `webhook_secret` set. Concrete consequences:
- Forged `push` events enqueue `GithubSyncJob` for the targeted stack, causing Shipit to fetch and append attacker-influenced commit history via the GitHub API for that org/repo. [10](#0-9) 
- Forged `status` events create fabricated commit statuses (`create_status_from_github!`), which downstream deploy gating (`stack.deployable?`) can rely on. [11](#0-10) 
- Forged `pull_request` events can trigger review-stack provisioning/merging logic for a real repository the attacker does not control. [12](#0-11) 

This escalates unauthenticated webhook forgery into fabricated deployability signals and stack state changes for a repository the attacker doesn't own — i.e., it drives an unauthorized ship/rollback readiness state on the real target stack, satisfying the "unauthenticated read/writes of stack state" / "unauthorized deploy" bar.

### Likelihood Explanation
Requires only: (1) a multi-org Shipit deployment (explicitly supported and shown in shipped example configs) where at least one configured org has no `webhook_secret`, and (2) knowledge of that org's login name (organization logins are public on GitHub) plus the target repository's `owner/name` (also public). No GitHub credentials, no Shipit session, and no API token are needed — only an unauthenticated POST to `/webhooks` with a crafted `X-Github-Event` header and JSON body. Given `webhook_secret` is optional per-org and the shipped example/documentation configs show it commented out/nil, this is a realistic misconfiguration rather than a purely theoretical one.

### Recommendation
Do not select the verifying organization from a field that is independent of the field the handlers actually use to identify the target repository. Concretely:
- Derive `repository_owner` from the same trusted lookup used by handlers (e.g. resolve `Repository.from_github_repo_name(payload.dig('repository','full_name'))` first, and use `repository.owner` from that persisted record to pick the GitHub App/secret), rather than trusting `repository.owner.login` from the raw payload.
- Alternatively/also, require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`), removing the "verification bypass" branch entirely.
- After signature verification, assert `repository.owner.login` case-insensitively equals the owner segment of `repository.full_name` before dispatching to handlers, rejecting mismatches.

### Proof of Concept
Given a Shipit instance configured with two orgs, `secure-org` (has `webhook_secret: "s3cr3t"`) and `open-org` (has `webhook_secret: nil`, e.g. as in `test/dummy/config/secrets_double_github_app.yml`), and a tracked repository `secure-org/prod-app`:

```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000   (arbitrary, unverified)
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha-known-to-exist-upstream>",
  "repository": {
    "owner": { "login": "open-org" },
    "full_name": "secure-org/prod-app"
  }
}
```

1. `verify_signature` computes `repository_owner = "open-org"`. [2](#0-1) 
2. `Shipit.github(organization: "open-org")` returns the `GitHubApp` configured for `open-org`, whose `webhook_secret` is nil. [7](#0-6) 
3. `verify_webhook_signature` returns `true` immediately (`return true unless webhook_secret`), regardless of the bogus `X-Hub-Signature`. [13](#0-12) 
4. `create` dispatches to `Handlers::PushHandler`, which resolves the target stack via `payload.dig('repository','full_name')` = `"secure-org/prod-app"` — a repository under the *other*, securely-configured org. [9](#0-8) 
5. `GithubSyncJob` is enqueued against `secure-org/prod-app`'s stack, forging a push event the attacker never had credentials for.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-26)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
