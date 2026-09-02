### Title
GitHub webhook signature verification is bound to the wrong field, allowing forgery of events (push, status, check_suite) for repositories other than the authenticating organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/webhook secret to validate a webhook against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`) [1](#0-0) [2](#0-1) . However, the handlers that actually act on the payload (`PushHandler`, `CheckSuiteHandler`, and the base `Handler#stacks`) resolve the target repository/stack using a **different field**: `payload.dig('repository', 'full_name')` [3](#0-2) . Nothing ties `repository.owner.login` to `repository.full_name` — the HMAC signature only proves the payload was signed with *some* configured org's `webhook_secret`, not that the acted-upon repository actually belongs to that org.

### Finding Description
`verify_webhook_signature` is a plain HMAC-SHA1 check of the raw body against the secret configured for whichever organization the attacker names in `repository.owner.login`/`organization.login` [4](#0-3) . Shipit explicitly supports multiple independently-configured GitHub organizations, each with its own `webhook_secret` [5](#0-4) .

An attacker who controls (or has installed) their own GitHub App/org in this Shipit instance knows that org's `webhook_secret` — this is a normal, unprivileged capability (any org admin can install the same publicly-documented GitHub App as described in `docs/setup.md`) [6](#0-5) . Using that known secret, they can POST directly to `/webhooks` with a forged JSON body where:
- `repository.owner.login` = `"attacker-org"` (so `verify_signature` loads and validates against the attacker's own secret) 
- `repository.full_name` = `"victim-org/victim-repo"` (the value actually used to resolve the `Stack`/`Repository` acted upon)

Because `Handler#stacks` calls `Repository.from_github_repo_name(repository_name)` where `repository_name` is `payload.dig('repository', 'full_name')` [3](#0-2) , this resolves to the victim's stack — never the attacker's own org — despite the signature having been verified against the attacker's own webhook secret. This breaks the equality the system is meant to enforce: `organization that authenticated == repository that is written`.

The impact differs per handler:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for any stack matching the forged `full_name`+branch [7](#0-6) .
- `CheckSuiteHandler` schedules check-run refresh for arbitrary stacks/commits it can select via forged `full_name` [8](#0-7) .
- `StatusHandler` is even less scoped: it queries `Commit.where(sha: params.sha)` with **no repository filtering at all**, so once signature verification succeeds (using any attacker-controlled org's secret), an attacker can inject a fabricated commit status (`state`, `context`, `description`) onto any commit SHA tracked anywhere in the Shipit instance [9](#0-8) .

Since Shipit gates deploys on required commit statuses (`ci.require`), forging a `success` status for a required CI context on a victim's commit can be used to make an otherwise-failing/unreviewed commit appear deployable, enabling an unauthorized deploy on a repository the attacker does not own or have write access to.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" trust boundary explicitly listed in scope. The attacker never needs a Shipit session, an `ApiClient` token, or the victim's `webhook_secret` — only control of their own (unrelated) organization's webhook secret, which is a standard, unprivileged capability of any org that has installed the Shipit GitHub App. The realistic worst case (forged commit statuses satisfying `ci.require` on a victim stack) enables an **unauthorized deploy**, matching the Critical impact bar.

### Likelihood Explanation
Any entity that has installed the shared GitHub App/organization config in this Shipit instance (i.e., possesses one valid, but unrelated, `webhook_secret`) can exploit this with a single crafted HTTP POST to the public `/webhooks` endpoint — no additional preconditions, timing, or races are required. In multi-org Shipit deployments (explicitly supported and documented via `config/secrets.*.yml` multi-org schema) this is directly and trivially reachable.

### Recommendation
Bind the authentication decision to the same identity used for resolution:
- Verify that the organization derived for signature validation matches the owner segment of `repository.full_name` (or resolve the target `Repository`/`Stack` using the same `repository.owner.login`/`organization.login` that authenticated the request, not a separately attacker-controlled `full_name` field).
- In `StatusHandler`, scope `Commit.where(sha:)` to commits belonging to repositories owned by the verified organization, rather than querying globally.

### Proof of Concept
1. Attacker administers `attacker-org`, which has a legitimate Shipit GitHub App installation with known `webhook_secret` S.
2. Attacker crafts a `status` (or `push`/`check_suite`) webhook JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "required-ci-check"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, loads `attacker-org`'s secret, and the signature validates successfully [1](#0-0) .
5. `StatusHandler#process` finds the victim's commit by SHA regardless of repository and records the forged "success" status [9](#0-8) , potentially satisfying `ci.require` and enabling deploy of that commit on `victim-org/victim-repo`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** docs/setup.md (L20-30)
```markdown
## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
