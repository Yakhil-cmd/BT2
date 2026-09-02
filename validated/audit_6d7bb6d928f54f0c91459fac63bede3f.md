### Title
Cross-Repository Commit Status Forgery via Unscoped `sha` Lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GithubApp` (and thus the webhook secret used for HMAC verification) based on `repository.owner.login` (or `organization.login`) taken from the incoming payload [1](#0-0) . This authenticates that the payload was signed by *some* configured organization's app, but the `status` event handler never re-checks that the commit it mutates actually belongs to a repository owned by that same organization. `StatusHandler#process` looks up commits purely by `sha` across the entire Shipit installation and writes a GitHub-reported status onto whatever matching `Commit` record it finds [2](#0-1) , unlike every other handler (`PushHandler`, pull-request handlers, etc.) which scope through `Repository.from_github_repo_name(repository_name)` before acting [3](#0-2) .

### Finding Description
The trust binding that should hold is: *the organization whose webhook secret validated the request* == *the organization owning the repository whose state is mutated*. `verify_signature` derives the signing organization strictly from the payload's `repository.owner.login`/`organization.login` [4](#0-3) , then hands the *entire, already-parsed* JSON body to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .

`Handler#stacks`/`#repository_name` (used by `PushHandler` and the pull-request handlers) correctly re-derive the target repository from `payload.dig('repository', 'full_name')` before doing anything with it [3](#0-2) . `StatusHandler`, however, bypasses this entirely:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
`Commit.where(sha: params.sha)` is a global lookup with no repository or stack scoping. This is a Rails installation that supports multiple independently-configured GitHub Apps/organizations sharing one Shipit instance (see `Shipit::TOP_LEVEL_GH_KEYS` and multi-org fixtures such as `test/dummy/config/secrets_double_github_app.yml`), each with its own `webhook_secret` [6](#0-5) , and `verify_signature` explicitly supports per-organization app resolution: `Shipit.github(organization: repository_owner)` [1](#0-0) .

Because commit SHAs are content-addressed and identical across forks/mirrors (a very common real-world occurrence — any fork of a tracked repository that has not diverged shares SHAs with upstream), an attacker who legitimately controls one *tenant* organization/repository configured on the same Shipit instance (i.e., someone who can trigger a real, correctly-signed `status` webhook for their own org, e.g. by pushing a CI status via their own GitHub Actions/CI integration) can cause a `status` payload referencing a SHA that also exists in a completely different organization's tracked repository. `StatusHandler` will happily attach that forged status to the unrelated commit, because it never checks that the commit's repository matches the organization that produced the verified signature.

### Impact Explanation
Commit statuses drive Shipit's deploy/merge readiness gating (`Commit#create_status_from_github!`, consumed by `Status`/`Status::Group` and merge/deployable-status logic referenced in `app/models/shipit/merge_request.rb` and `app/models/shipit/stack.rb`). A forged, cross-organization status write lets a tenant on a shared Shipit instance manufacture or corrupt CI/status state on a commit belonging to another organization's stack, which can unblock merge/deploy gates that depend on required statuses — an unauthorized-deploy-adjacent, cross-repository-write class of impact. This satisfies the "cross-repository writes" / "unauthorized deploy" impact bar because the binding broken is exactly "organization that authenticated versus the repository that is written."

### Likelihood Explanation
Exploitation requires: (1) a Shipit deployment configured with more than one GitHub App/organization (a supported and documented configuration, see `test/dummy/config/secrets_double_github_app.yml`), and (2) a commit SHA collision between the attacker-controlled org's repository and the victim org's tracked repository — realistic for forks/mirrors that share history, which is a common setup pattern (upstream + downstream tracked forks). No privileged Shipit credentials, GitHub App keys, or webhook secrets belonging to the victim org are needed; the attacker only needs legitimate, unprivileged control of their own tenant's repository/CI to emit a correctly-signed webhook for themselves.

### Recommendation
Scope `StatusHandler#process` to the repository asserted in the payload, mirroring `Handler#stacks`/`#repository_name`: resolve the target repository via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` and restrict the `Commit.where(sha: ...)` lookup to commits belonging to that repository's stacks (or otherwise verify `commit.stack.repository == repository_name`) before calling `create_status_from_github!`.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (victim, tracks `OrgA/app`) and `OrgB` (attacker-controlled tenant, tracks `OrgB/app`, a fork of `OrgA/app` that has not diverged from a shared ancestor commit `deadbeef...`).
2. Attacker triggers (or directly crafts, since they control CI/webhooks for `OrgB`) a real GitHub `status` event on `OrgB/app` for commit `deadbeef...`, setting `state: "success"`. GitHub signs this payload with `OrgB`'s legitimate `webhook_secret`.
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'OrgB')` from `payload.dig('repository','owner','login') == 'OrgB'` and successfully verifies the signature [1](#0-0) .
4. `StatusHandler#process` runs `Commit.where(sha: 'deadbeef...')`, which also matches the corresponding commit tracked under `OrgA/app`'s stack, and writes the forged "success" status onto it [2](#0-1) .
5. `OrgA`'s stack now reflects an attacker-forged CI status on its commit, potentially satisfying deploy/merge gating logic without any interaction from `OrgA`.

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
