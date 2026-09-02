### Title
Webhook signature is verified against `repository.owner.login`, but stack/commit resolution uses the unauthenticated `repository.full_name` field, allowing cross-organization status/commit forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/`webhook_secret` to validate an incoming webhook's HMAC using `repository.owner.login` (falling back to `organization.login`) taken from the raw JSON body itself. [1](#0-0)  Once the signature check passes, `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name` resolve the *target* repository/stack using a **different** field from the same body, `repository.full_name`. [2](#0-1)  Nothing binds these two fields together, so a valid signature computed with organization A's `webhook_secret` can be attached to a payload whose `repository.full_name` names a stack belonging to organization B.

### Finding Description
The equality that should hold but is never checked is:

`organization used to look up the verifying webhook_secret (params.dig('repository','owner','login'))` == `organization that owns the repository actually mutated (payload.dig('repository','full_name').split('/').first)`

`verify_signature` fetches the GitHub App config via `Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` against `request.raw_post` using that org's secret. [3](#0-2)  `Shipit::GithubApp#verify_webhook_signature` just does an HMAC compare with whatever `webhook_secret` was resolved. [4](#0-3) 

After the signature check, `create` dispatches the *entire raw JSON body* to the registered handlers for the event. [5](#0-4)  Every handler resolves the affected repository/stack via `payload.dig('repository', 'full_name')`, then looks it up with `Repository.from_github_repo_name`. [2](#0-1)  `Repository.from_github_repo_name` simply splits the string on `/` and does a DB lookup — it performs no cross-check against `repository.owner.login`. [6](#0-5) 

Because the signature is only proof that *some field* of the body was signed by a given org's secret — not that `repository.owner.login` and `repository.full_name` agree — an attacker who legitimately administers **any** organization/repository onboarded to a shared Shipit instance (and therefore knows that org's `webhook_secret`, which is routine self-service configuration, not a privileged Shipit credential) can forge a payload where:
- `repository.owner.login` = their own organization (so `verify_signature` resolves and validates against their own known secret), and
- `repository.full_name` = `"victim-org/victim-repo"` (any other stack hosted in the same Shipit instance).

The most damaging handler is `StatusHandler`, which writes the forged `state`/`context`/`target_url`/`description` directly onto a `Commit` with **no callback to the GitHub API to confirm the status is genuine**: [7](#0-6) 

Shipit's `ci.require` deploy-gate feature relies exactly on these `Commit` statuses to decide whether a commit is "deployable" (documented in README). [8](#0-7)  By forging a `state: "success"` status for the victim's commit, the attacker can flip that commit's CI-gate to "deployable" without ever touching the victim repository's real CI, GitHub App, or Shipit account.

`PushHandler` and `CheckSuiteHandler` are also reachable cross-organization (they can trigger `sync_github`/`schedule_refresh_check_runs!` on victim stacks) [9](#0-8) [10](#0-9) , but those ultimately re-fetch authoritative data from the real GitHub API for the victim repo, limiting their direct impact; `StatusHandler` does not re-verify anything.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding explicitly called out as in-scope. An attacker who is only an unprivileged participant with respect to the victim stack (no Shipit session, no `ApiClient` token, no GitHub write access on the victim repo — merely legitimate control of *some other* org onboarded to the same Shipit instance) can forge CI status for a victim's commit, defeating the `ci.require` safety gate and enabling an unauthorized deploy of a commit that has not actually passed CI. This lands in the High-impact bucket ("escalation... unauthorized deploy... cross-repository writes" analog) since it is effectively a cross-repository/cross-organization forged write into another tenant's commit state that removes a deploy safety control.

### Likelihood Explanation
Exploitability requires only knowledge of one legitimately configured organization's `webhook_secret` (something the attacker, as an admin of that org, is expected to know/configure) plus knowledge that the target Shipit instance also hosts stacks for another organization — both realistic for shared/multi-tenant Shipit deployments where multiple GitHub Apps/organizations are configured via `Shipit.github(organization:)` (evidenced by the `GithubOrganizationUnknown` handling path). [11](#0-10)  No GitHub write access to the victim repository, Shipit account, or API token is needed — only a correctly-signed HTTP POST to the public `/github` webhook endpoint.

### Recommendation
In `WebhooksController#verify_signature` and/or `Handler`, require that the organization derived from `repository.owner.login`/`organization.login` (used to select the verifying secret) match the organization portion of `repository.full_name` used for stack/commit resolution, rejecting the webhook (422) on mismatch. Additionally, `StatusHandler` should not blindly trust webhook-supplied commit status fields for gating deploy-readiness without corroborating them against the GitHub Commit Status/Checks API for the specific repository the commit belongs to.

### Proof of Concept
1. Attacker controls organization `attacker-org`, which has a `Shipit::GithubHook` configured on this shared Shipit instance, so they know `attacker-org`'s `webhook_secret`.
2. Victim stack `victim-org/victim-repo` exists on the same instance with `ci.require` configured, and has an undeployed `Commit` with sha `deadbeef`.
3. Attacker computes `sha1=HMAC(attacker-org secret, body)` for the JSON body:
```json
{
  "sha": "deadbeef",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. POST to `/github` with header `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s webhook_secret, and the signature matches → request is accepted. [12](#0-11) 
6. `StatusHandler#process` finds `Commit` with `sha: "deadbeef"` (belongs to `victim-org/victim-repo`) and writes the forged "success" status onto it, satisfying `ci.require` for a commit that never actually passed CI. [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** README.md (L444-450)
```markdown
<h3 id="ci">CI</h3>

**<code>ci.require</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to disallow deploys if any of them is missing on the commit being deployed.

For example:
```yml
ci:
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
