### Title
Webhook signature verification is keyed on `repository.owner.login` while all processing acts on the independent `repository.full_name` field, allowing cross-organization forged webhooks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The `WebhooksController#verify_signature` selects which GitHub App secret to validate a webhook's HMAC signature against using `repository.owner.login` (or `organization.login`) parsed from the *attacker-supplied* JSON body, but every event handler that actually acts on the request resolves the target `Stack`/`Repository` using the independent `repository.full_name` field from the same body. Because `owner.login` and `full_name` are two unrelated JSON fields inside one request, and GitHub apps can be configured with `webhook_secret: nil` (documented as optional), an attacker can craft a payload that authenticates as an organization whose app has no secret configured, while pointing `full_name` at a victim repository belonging to a different, properly-secured organization.

### Finding Description
`WebhooksController#verify_signature` picks the app/secret via: [1](#0-0) 
using [2](#0-1) 

`Shipit.github(organization:)` resolves the config purely from that attacker-controlled login string: [3](#0-2) 

`GitHubApp#verify_webhook_signature` trivially returns `true` (bypassing verification entirely) whenever that organization's app has no `webhook_secret` configured, which the setup docs explicitly say is optional: [4](#0-3) [5](#0-4) 

Meanwhile, every handler resolves the actual `Repository`/`Stack` to act on from `repository.full_name`, not from `owner.login`: [6](#0-5) 

`PushHandler` uses this to trigger `stack.sync_github`, i.e. writes to stack state / triggers sync jobs based on attacker-controlled `after` sha: [7](#0-6) 

`StatusHandler` uses it (via commit lookup) to create arbitrary commit statuses that affect deployability/merge checks: [8](#0-7) 

The binding broken: **organization authenticated (`repository.owner.login` used to pick the verifying secret) ≠ repository written (`repository.full_name` used by every handler)**. Nothing in `verify_signature` or in the handlers cross-checks that the two fields refer to the same organization/app installation, and multi-tenant Shipit deployments (documented "Using Multiple Github Applications" setup) are exactly the scenario where several orgs, potentially with mixed secret configuration, share one webhooks endpoint.

### Impact Explanation
In a multi-org Shipit deployment, if **any** configured organization has `webhook_secret` left blank (an explicitly supported/optional configuration per `docs/setup.md`), an unauthenticated external attacker can forge `push` or `status` webhooks for **any other organization's repository** hosted on the same Shipit instance, by simply setting `repository.owner.login` to the unsecured org while setting `repository.full_name` to the victim org/repo. This can:
- Force `GithubSyncJob`/`sync_github` calls with attacker-chosen `expected_head_sha`, corrupting the stack's view of HEAD and potentially triggering unwanted deploy eligibility changes.
- Inject forged commit statuses (`state`, `context`, `target_url`) via `StatusHandler`, which stacks use to gate deployability/merge decisions - enabling deploy/merge gating bypass without any credential.

This crosses an authentication boundary (High: "unauthenticated read/write of stack state ... unauthorized deploy" territory) purely due to a design flaw independent of any single organization's own secret hygiene.

### Likelihood Explanation
Requires (a) a multi-org Shipit deployment, and (b) at least one configured organization with a blank `webhook_secret`. Both are explicitly supported/documented configurations (`docs/setup.md` marks webhook secret as "optional"; multi-org config is a documented first-class feature), making this plausible in real deployments rather than purely theoretical, though it depends on operator configuration choices outside the engine's default single-org template.

### Recommendation
- Do not select the verifying app purely from an unauthenticated field; alternatively, verify the payload's HMAC against **all** configured organizations' secrets that could plausibly own `full_name`'s owner segment, and reject if the winning secret's organization does not match `full_name`'s owner.
- Stop treating a blank `webhook_secret` as "verification succeeds" — require every configured GitHub App in multi-org mode to have a non-blank secret, or explicitly refuse to process events for orgs without one.
- Cross-validate that `repository.owner.login` (or `organization.login`) matches the owner segment of `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Shipit is configured for two orgs: `unsecured-org` (no `webhook_secret`) and `victim-org` (has `webhook_secret` and an active `Stack` tracking `victim-org/app`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "victim-org/app"
  }
}
```
No valid `X-Hub-Signature` is required, because `verify_signature` calls `Shipit.github(organization: 'unsecured-org')`, whose `verify_webhook_signature` returns `true` unconditionally (blank secret).
3. `PushHandler#process` resolves `stacks` from `payload.dig('repository','full_name')` = `victim-org/app`, and calls `stack.sync_github(expected_head_sha: 'deadbeef...')` on the real victim stack — all without ever presenting a valid signature for `victim-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
