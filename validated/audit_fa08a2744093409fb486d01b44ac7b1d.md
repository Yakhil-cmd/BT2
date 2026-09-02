### Title
`StatusHandler#process` scopes status writes globally by `sha`, not by the organization that `verify_signature` bound the webhook to - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects a per-organization `GitHubApp` (and its `webhook_secret`) using `params.dig('repository','owner','login')`, but that organization identity is used only to pick the HMAC secret and is never passed to or checked by the handler. `StatusHandler#process` then runs `Commit.where(sha: params.sha)` unscoped by repository/organization, so a valid signature from *any* configured organization can attach a GitHub status to a commit belonging to a completely different organization's stack.

### Finding Description
The binding the code should enforce is: `organization used to verify signature (repository_owner from payload) == organization owning the commit whose status is mutated`. In practice: `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` [1](#0-0)  and only uses that app to check `verify_webhook_signature`, never storing/propagating `repository_owner` to the handler. `WebhooksController#create` then dispatches the raw, unfiltered `params` (the full JSON payload, including `repository`) to every registered handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1) .

`StatusHandler#process` ignores `payload['repository']` entirely and only requires `sha`/`state` from `params`, then does a bare `Commit.where(sha: params.sha)`: [3](#0-2) . This is a direct, cross-tenant, unscoped lookup — no join to `Repository`/`Stack` and no comparison against `repository_owner`. By contrast, other handlers such as `PushHandler` and `CheckSuiteHandler` do scope to `stacks` derived from `payload.dig('repository', 'full_name')` via the base `Handler#stacks` helper [4](#0-3) , but `StatusHandler` does not use `stacks` at all.

Multi-tenant configuration is real and supported: `Shipit.github(organization:)` looks up a distinct `GitHubApp`/`webhook_secret` per organization key in `secrets.github` [5](#0-4) , and `GitHubApp#verify_webhook_signature` only checks the HMAC against that org's own `webhook_secret` [6](#0-5) .

Attack: an attacker who owns/administers a GitHub organization ("attacker-org") that is legitimately configured in this Shipit instance (i.e., they possess their own valid `webhook_secret` for their own org — a normal, unprivileged capability for any org admin, not a Shipit secret) sends a `status` webhook with `repository.owner.login = "attacker-org"` (satisfying `verify_signature`, since `Shipit.github(organization: 'attacker-org').verify_webhook_signature` succeeds with their own secret) but with `sha` set to a commit SHA belonging to a victim organization's stack. `StatusHandler#process` finds that commit via `Commit.where(sha: params.sha)` with no organization check and calls `commit.create_status_from_github!(params)`, writing an arbitrary GitHub status object (state, description, target_url, context) onto the victim's commit.

None of the listed guards prevent this: `verify_signature` only gates whether the request is processed at all, not which records it may touch; `drop_unhandled_event` only filters by event type; `ExplicitParameters` schema only validates presence/type of `sha`/`state`, not ownership; there is no `force_github_authentication`, `User#authorized?`, or `stacks` scoping applied inside `StatusHandler`.

### Impact Explanation
An attacker in control of one legitimately-configured organization's webhook secret can inject fabricated commit statuses (arbitrary `state`, `description`, `target_url`, `context`) onto commits in any other organization's stack tracked by the same Shipit instance, by guessing/enumerating a target SHA (SHAs are often public via PRs/pushes and not secret). This is a genuine cross-tenant record-mutation: "a payload for one repository mutating another's commit," matching the Critical impact category. Downstream, deployable-status logic (`Commit#create_status_from_github!` → `add_status`/`deployable_status` hooks) can influence whether a commit is considered deployable, potentially enabling or masking a merge/deploy decision for the victim stack. This is repeatable per request against any SHA and is not limited to a single victim — any Shipit instance hosting multiple GitHub organizations is exposed.

### Likelihood Explanation
Preconditions: the Shipit instance must be configured for multiple organizations (`secrets.github` keyed by org, per `github_app_config`), which is a supported and documented configuration, not a corner case. The attacker needs only their own org's `webhook_secret` — something they legitimately possess as an org admin — and knowledge of a target commit SHA, which is generally discoverable (public repos, PRs, git history). No Shipit session, API token, or victim secrets are required. Cost is a single crafted HTTP POST to `/webhooks` with a valid signature for the attacker's own org and a forged `repository.owner.login`/`sha` combination; fully repeatable.

### Recommendation
In `StatusHandler#process` (and any other handler that trusts `payload['sha']`/similar identifiers without going through `Handler#stacks`), scope the commit lookup by the repository derived from the payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching `Commit`. More generally, `WebhooksController` should pass the already-verified `repository_owner` (or the whole verified organization context) down to handlers and every handler should assert that any repository/commit it touches belongs to that verified organization, not rely solely on signature verification as an authorization proxy.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual addition)
test "status webhook from attacker's own verified org can mutate a victim org's commit" do
  victim_stack = shipit_stacks(:shipit) # belongs to org "shopify"
  victim_commit = shipit_commits(:first)
  refute_equal 'attacker', victim_stack.repository.owner

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'description' => 'forged by attacker',
    'repository' => { 'owner' => { 'login' => 'attacker' }, 'full_name' => 'attacker/some-other-repo' }
  }

  # Simulates verify_signature succeeding using ONLY the attacker's own org's webhook_secret
  Shipit.github(organization: 'attacker').stubs(:verify_webhook_signature).returns(true)

  assert_difference -> { victim_commit.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end

  # Demonstrates the missing binding: verified org ('attacker') != commit's owning org ('shopify')
  assert_equal 'forged by attacker', victim_commit.statuses.last.description
end
```
This test demonstrates that `Shipit.github(organization: 'attacker')` verifying successfully places no restriction on which stack/commit `StatusHandler#process` is allowed to mutate, confirming the two sides of the claimed binding (`verified organization` vs. `commit's owning organization`) diverge.

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

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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
