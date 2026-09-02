### Title
Webhook signature verification keys on `repository.owner.login`, decoupled from `repository.full_name` used for stack lookup, allowing cross-organization status/CI spoofing - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
This is the same bug class as the report: a value is checked/verified, but a *different* value derived from the same untrusted request is the one actually acted upon, and the two are never proven to refer to the same entity. In the NFT report, the marketplace call is verified by `ownerOf(tokenId) == address(this)` after the buy, but the *identity* of "which NFT this proves was bought" is never bound to the NFT that was actually supplied as collateral, so an unrelated NFT already sitting in the contract satisfies the check. Here, `WebhooksController#verify_signature` picks the GitHub App/secret to validate the HMAC using `repository_owner` (`params.dig('repository','owner','login')`), while every downstream `Handler` resolves the target `Stack`/`Repository` using a *different* field, `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`). Nothing enforces `repository.full_name.split('/').first == repository.owner.login`. The binding that should hold is:

`organization whose webhook_secret authenticated the request == owner of the repository whose stacks/commits are mutated`

and this equality is never checked.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb:24-38`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

The organization used to pick the `GithubApp`/secret comes from `repository.owner.login`. But `GithubApp#verify_webhook_signature` is permissive by design:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

If an organization is configured in `secrets.yml` without a `webhook_secret` (a legal, documented configuration — `webhook_secret: null` appears even in the test fixtures, see `test/dummy/config/secrets.test.json:12`), `verify_webhook_signature` unconditionally returns `true` for *any* payload claiming that `repository.owner.login`, with no signature required at all.

Once the request passes `verify_signature`, every `Handler` subclass resolves the actual target using a completely separate field:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`Repository.from_github_repo_name` simply splits `"owner/name"` and looks up by columns, with no cross-check against the organization that satisfied `verify_signature`:
```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [4](#0-3) 

Because `repository.owner.login` and `repository.full_name` are two independent JSON fields on the same attacker-controlled request body, an unauthenticated caller can set `repository.owner.login` to an organization with no `webhook_secret` (bypassing HMAC entirely) while setting `repository.full_name` to `"other-org/other-repo"` — a stack belonging to a completely different, properly configured organization. The handler will operate on that other stack's commits/statuses regardless of which "organization" was used to satisfy `verify_signature`.

### Impact Explanation
The most directly reachable handler is `StatusHandler`, which writes a forged CI status onto any existing commit purely from `sha`, with no repository-ownership check performed against the sha itself:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

`Commit.where(sha: params.sha)` is a global lookup — not scoped to the spoofed repository at all — so an attacker can inject a fabricated "success" status for a known commit SHA belonging to a *target* stack that uses `ci.require` gating for continuous deployment/merge queue eligibility. Forcing required CI checks green on a commit can unblock continuous deployment (`merge_queue_enabled`/`continuous_deployment`) or automatic merges that are otherwise gated on genuine GitHub CI status, resulting in an unauthorized deploy/merge — matching the "Critical: unauthorized deploy, rollback or merge" bar in scope. `CheckSuiteHandler` and `PushHandler` are reachable the same way and can trigger `stack.sync_github` / `schedule_refresh_check_runs!` against arbitrary stacks chosen independently of the verified organization.

### Likelihood Explanation
The webhook endpoint is unauthenticated by design (it exists specifically to receive unauthenticated GitHub calls, verified only by HMAC) — no `ApiClient` token, session, or GitHub credential of any kind is required, matching the "unprivileged attacker" requirement. The only precondition is that *some* organization configured in the Shipit instance has `webhook_secret` unset/blank (an explicitly supported configuration state, not a secret an attacker must obtain) — this is a configuration/design gap rather than a leaked credential, so it does not fall under the "requires webhook_secret" exclusion (the attacker needs zero knowledge of any secret; they exploit the *absence* of one for the org they name). Reachability of `Commit.where(sha:)` across all stacks without owner scoping strengthens likelihood further.

### Recommendation
- After parsing the payload, derive the organization strictly from `repository.full_name` (or validate `repository.full_name.split('/').first == repository.owner.login`) before selecting the `GithubApp` used for verification, so the entity whose secret authenticates the request is provably the same entity whose data is mutated.
- Do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is blank for organizations that have any registered `Repository`/`Stack`; either require a secret whenever repositories are registered, or scope `Commit.where(sha:)`/`Repository.from_github_repo_name` lookups by the verified organization only.
- Scope `StatusHandler#process` (and other handlers) to commits whose owning `Repository#owner` matches the organization that satisfied `verify_signature`, not merely to `Commit.where(sha:)` globally.

### Proof of Concept
1. Deploy an instance of shipit-engine configured with two GitHub organizations: `victim-org` (has stacks, `webhook_secret` configured) and `attacker-org` (no `webhook_secret` set, e.g. `webhook_secret: null`, a documented/legal config as shown in `test/dummy/config/secrets.test.json`).
2. Attacker (no GitHub credentials, no Shipit account) sends `POST /webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<known sha of a commit on a victim-org stack>",
  "state": "success",
  "context": "ci/required-check"
}
```
No `X-Hub-Signature` needs to be valid because `Shipit.github(organization: "attacker-org").verify_webhook_signature` returns `true` unconditionally per `lib/shipit/github_app.rb:76-83`.
3. `WebhooksController#verify_signature` passes; `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }`, writing the forged "success" status onto the victim's commit regardless of which organization's app was used for the (bypassed) signature check.
4. If `victim-org`'s stack has `ci.require: ["ci/required-check"]` feeding continuous deployment/merge-queue gating, the forged status can unblock an automatic deploy or merge that GitHub's real CI never approved.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
