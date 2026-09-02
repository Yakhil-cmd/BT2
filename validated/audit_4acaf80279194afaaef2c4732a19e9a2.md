## Confirmed finding

This confirms the exploit chain: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` [1](#0-0)  to select which `Repository`/`Stack` is acted on, while `WebhooksController#repository_owner` (used solely to pick the signing `github_app`) reads `params.dig('repository', 'owner', 'login')` [2](#0-1) . These are two independent, attacker-suppliable JSON fields that need not agree.

### Title
Cross-organization webhook forgery via mismatched signature-selection field and repository-target field — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a webhook against using `repository.owner.login` from the untrusted JSON body, while the handlers that actually act on the payload (`PushHandler`, `StatusHandler`, etc.) select the target `Stack`/`Repository` using the unrelated `repository.full_name` field from the same untrusted body. Additionally, `GithubApp#verify_webhook_signature` trivially returns `true` whenever `webhook_secret` is blank for the organization resolved from that first field [3](#0-2) . Because multi-org Shipit deployments can (and do, per the fixture `secrets_double_github_app.yml`) configure some organizations without a `webhook_secret`, an attacker who knows (or guesses) the name of any such loosely-configured organization can send a completely unsigned, forged webhook body that claims `repository.owner.login` = that org (to defeat/short-circuit signature verification) while setting `repository.full_name` to a target org/repo that is actually tracked by Shipit and does have a properly secured webhook.

### Finding Description
- `verify_signature` computes `repository_owner` from the payload and fetches `Shipit.github(organization: repository_owner)`, then calls `verify_webhook_signature(signature, raw_post)` on that app instance [4](#0-3) .
- `verify_webhook_signature` returns `true` unconditionally when that org's `webhook_secret` is not configured [3](#0-2) , i.e. HMAC verification is skipped entirely for that org.
- Once `verified` is true, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs with the full attacker-controlled `params` hash, unrelated to which org's key was used to "verify" it [5](#0-4) .
- Every built-in handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')` via `Handler#stacks`/`#repository_name` [6](#0-5)  — a field never checked against, or required to match, `repository.owner.login`.
- `Repository.from_github_repo_name` simply splits `owner/name` out of that string and looks up the record with no cross-check against the org used for signature selection [7](#0-6) .

Binding broken (as an equality that must hold but doesn't): `organization authenticated by verify_signature (repository.owner.login) == organization/repository actually written by the handler (repository.full_name)`. The controller enforces neither that these two fields match, nor that the org used to pick the (potentially unset) `webhook_secret` is the org that owns the repository being mutated.

Before the attacker's request: only genuine, HMAC-signed GitHub webhooks (or webhooks from orgs deliberately run with no secret, presumably trusted networks) can update commit statuses, sync pushes, or process check suites for a stack.
After the attacker's request: any external, unauthenticated party can forge a `status` (or `push`/`check_suite`) webhook for any Shipit-tracked repository by simply declaring `repository.owner.login` equal to any *other* configured organization that happens to have `webhook_secret: nil`, since verification is performed against that unrelated org and trivially passes.

### Impact Explanation
`StatusHandler#process` calls `commit.create_status_from_github!(params)` for every `Commit` matching the forged `sha` [8](#0-7) , with attacker-chosen `state`, `context`, etc. Because required/blocking CI statuses (`deploy_spec.required_statuses`/`blocking_statuses`) gate whether a commit is `deployable?`, an attacker can forge a "success" status for a required CI context on an arbitrary commit of a targeted stack's repository, making that commit pass the CI gate it would not otherwise pass, and thereby enabling an unauthorized deploy of that commit through the normal (legitimately authenticated) deploy UI/API. This lands squarely in the Critical impact bucket ("an unauthorized deploy") since it lets an outsider manipulate the deploy-eligibility state of a targeted repository without any GitHub, API-client, or session credential — only knowledge that some other configured org lacks a webhook secret.

### Likelihood Explanation
Requires: (1) a Shipit instance configured with more than one GitHub App/organization (a documented, supported configuration — see `secrets_double_github_app.yml` and `github_teams`/multi-org support in `lib/shipit/github_app.rb`), and (2) at least one of those configured organizations left with `webhook_secret` unset. This is a realistic operational misconfiguration for a secondary/low-traffic org onboarded without setting up the webhook secret, and the code does not warn about or refuse an unauthenticated-webhook org while other tracked repositories rely on signed webhooks. No credentials, session, or repository write access are needed by the attacker — only network access to the public webhook endpoint and the name of the loosely-configured org.

### Recommendation
Bind the two fields together: derive the GitHub App/secret to verify against from the same repository/org the handler will act on (`repository.full_name`'s owner), not a separately-read `repository.owner.login`/`organization.login`, and require every configured organization to have a mandatory, non-blank `webhook_secret` (removing the "trust unless secret present" fallback in `GithubApp#verify_webhook_signature`), or reject the webhook when the resolved organization's `webhook_secret` is blank.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `OrgA` (has `webhook_secret` set, tracks `OrgA/critical-repo`) and `OrgB` (has `webhook_secret: nil`), as in `test/dummy/config/secrets_double_github_app.yml`.
2. POST unsigned (no `X-Hub-Signature` needed) to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/critical-repo" },
  "sha": "<sha of a commit pending required CI>",
  "state": "success",
  "context": "<required-status-context>"
}
```
3. `verify_signature` resolves `repository_owner = "OrgB"`, fetches `OrgB`'s `github_app`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of signature.
4. `StatusHandler` runs using `repository.full_name = "OrgA/critical-repo"`, creating a forged successful status on the targeted commit, marking it deployable and allowing an unauthorized deploy of `OrgA/critical-repo`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
