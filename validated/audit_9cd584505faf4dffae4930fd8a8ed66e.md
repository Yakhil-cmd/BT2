### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` bypasses per-organization webhook signature binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to use for HMAC verification based solely on the payload's `repository.owner.login` (or `organization.login`) field, then trusts the entire payload once that check passes. `StatusHandler`, however, never re-checks that field: it resolves the target `Commit` purely by `sha`, with no scoping to the repository/organization whose key validated the signature. This breaks the binding "organization whose webhook_secret authenticated the request == repository being mutated," letting a webhook that is cryptographically valid for organization A write a GitHub commit status onto a commit that belongs to a completely different stack/repository/organization B, as long as the sender can supply B's commit SHA (commit SHAs are not secret).

### Finding Description
`WebhooksController#verify_signature` picks the verifying key like this: [1](#0-0) 
using [2](#0-1) 
to derive `repository_owner`, and `Shipit.github(organization: repository_owner)` looks up a distinct `GitHubApp`/`webhook_secret` per organization when multiple GitHub Apps are configured (as documented and fixtured): [3](#0-2) [4](#0-3) 

Once `verify_signature` passes, `WebhooksController#create` hands the *entire* parsed JSON body, unmodified, to the matching handler: [5](#0-4) 

`StatusHandler` then acts on the payload with no repository/organization scoping at all: [6](#0-5) 

Compare this to `PushHandler` and `CheckSuiteHandler`, which correctly scope their queries through `stacks`, itself derived from `Repository.from_github_repo_name(repository_name)`: [7](#0-6) [8](#0-7) 

`StatusHandler` uniquely bypasses this scoping and matches `Commit.where(sha: params.sha)` globally across every stack/repository/organization hosted by the Shipit instance, then calls `commit.create_status_from_github!(params)` for every match. The `sha` value is attacker-supplied and requires no proof of ownership of the target repository — only a valid signature for *some* organization configured on the instance.

This is the same class of bug as the Sherlock finding: a value that should be constrained to the authenticated principal (the payer/organization) is instead accepted from untrusted, unchecked payload input and used to select which object is mutated, and the check that *is* performed (`msg.sender == payer` / HMAC signature) does not actually cover that value.

### Impact Explanation
`Commit#create_status_from_github!` persists a CI status (state, context, description, target_url) on the resolved commit. Stacks can be configured with `required_statuses`/`blocking_statuses`/`ci.require` gates in `shipit.yml` that block deploys until specific status contexts report success. An attacker who only controls (or has compromised) the webhook delivery for one organization's GitHub App on a shared, multi-tenant Shipit instance can forge a `status` event that is validly signed for their own organization, but whose `sha` targets a commit belonging to an entirely different organization's stack. Because `StatusHandler` never checks that the commit's repository matches the authenticated organization, the forged status is recorded against the victim's commit, potentially satisfying a required-status deploy gate and enabling an unauthorized deploy of that commit. This matches the "unauthorized deploy" High-impact criterion.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (a documented, supported configuration) and knowledge of a target commit SHA in another organization's repository — SHAs are not secret and are routinely visible in PRs, CI logs, or other public artifacts. No repository write access, GitHub App private key, or privileged Shipit account is required, only legitimate webhook delivery capability for the attacker's own (possibly unrelated) organization/app installation. This is a realistic, moderately likely scenario for shared Shipit instances serving multiple GitHub organizations.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` and `CheckSuiteHandler` do: resolve commits only through `stacks` (i.e., `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) rather than a bare, cross-tenant `Commit.where(sha:)` lookup, so a status event can only affect commits belonging to the repository/organization whose key validated the webhook signature.

### Proof of Concept
1. Configure Shipit with two GitHub Apps/organizations, `OrgA` and `OrgB`, each with a distinct `webhook_secret` (per `docs/setup.md` "Using Multiple Github Applications").
2. Attacker controls (or is a legitimate integrator for) `OrgA`'s GitHub App and can trigger/replay a `status` webhook signed with `OrgA`'s `webhook_secret`.
3. Attacker crafts the payload body with `repository.owner.login = "OrgA"` (so `verify_signature` validates it against `OrgA`'s secret) but sets `sha` to a known commit SHA belonging to a stack under `OrgB`, and `state: "success"`, `context: "<required-status-context>"`.
4. `WebhooksController#verify_signature` succeeds (valid signature for `OrgA`).
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, finds the `OrgB` commit (no org/repo filter), and calls `create_status_from_github!`, writing a forged "success" status onto `OrgB`'s commit — potentially clearing a required-status deploy gate for `OrgB`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
