Confirmed: multi-organization GitHub App configuration is supported, each org gets its own config (including `webhook_secret`) via `Shipit.github_app_config`, and `GitHubApp#verify_webhook_signature` explicitly returns `true` (skips verification) whenever that org's `webhook_secret` is blank.### Title
Webhook Signature Selection Bypasses Multi-Org Trust Binding: Attacker Can Forge Unsigned Events Against a Fully-Configured Org's Repositories - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) authenticates an incoming webhook based on the attacker-controlled `repository.owner.login` field of the *unauthenticated* JSON body [1](#0-0) . That org-selection field is never bound to the `repository.full_name` field the event handlers actually act on [2](#0-1) . In Shipit's multi-organization mode, each org has its own independent `webhook_secret`, and `GitHubApp#verify_webhook_signature` explicitly skips HMAC verification entirely when that org's secret is blank/unset [3](#0-2) . This is directly analogous to the reported bug class: a value used to authorize/compute an outcome (`hub_balance`) is not validated against the value it's supposed to be tied to (`prev_hub_balance`), letting an unvalidated field silently drive privileged behavior.

### Finding Description
Shipit supports hosting multiple GitHub organizations from one instance; each org has independent config under `secrets.github`, including its own `webhook_secret` [4](#0-3) . When a webhook arrives, the controller determines **which** org's app/secret to use for signature verification purely from the unauthenticated JSON payload:

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

That `repository_owner` is fed into `Shipit.github(organization:)` to build the `GitHubApp` used to verify the signature [1](#0-0) . Crucially, `verify_webhook_signature` treats a missing/blank `webhook_secret` as automatic success:

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

Meanwhile, every event handler resolves the actual repository/stack to mutate using a *different* field of the same unauthenticated payload — `repository.full_name` — completely independent of the `repository.owner.login`/`organization.login` value used for org/secret selection:

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

The `PushHandler`, for instance, uses this to trigger a `sync_github` for any stack matching that `full_name`/branch [6](#0-5) , and other handlers (`MembershipHandler`, PR handlers) similarly act on payload data resolved independently of the org used for authentication [7](#0-6) .

**The binding that is broken:** "org authenticated" (`repository.owner.login`, used to pick the `GitHubApp`/secret) ≠ "repository written" (`repository.full_name`, used by the handler to find/mutate the `Stack`/`Repository`/`Team`/`User`). Nothing in the code enforces that these two values refer to the same repository/org. If an attacker crafts a payload where:
- `repository.owner.login` = an organization configured in Shipit that happens to have **no `webhook_secret` set** (e.g., a legacy/test org, or any org onboarded without ever filling in the optional `webhook_secret` field — the setup docs even list it as **optional** [8](#0-7) ),
- `repository.full_name` = a fully protected org/repo that Shipit does host and does have `webhook_secret` configured,

then `verify_signature` selects the *unsecured* org's `GitHubApp`, which short-circuits to `verified = true` regardless of any `X-Hub-Signature` header content, and the request proceeds to `create`, where the handler dispatches based on `full_name` against the *protected* org's repository.

This is not a theoretical host-misconfiguration scenario in the excluded sense ("host application not mounting the engine as documented") — it is a documented, supported first-class feature of the engine (multi-org GitHub Apps, optional per-org `webhook_secret`) whose interaction the engine itself fails to bind correctly.

### Impact Explanation
Reachable impacts through this binding break, without any credential, are limited to the actions the default webhook handlers perform:
- Forced `GithubSyncJob` invocations on arbitrary stacks (`push` event) [9](#0-8) .
- Forged `membership` events creating/deleting `Team`/`Membership`/`User` records for the target org's teams [7](#0-6)  — this can add or remove memberships that feed into `Shipit.github_teams` authorization checks used to gate access to the whole application (`User#authorized?`) [10](#0-9) .
- Forged `pull_request`/`check_suite`/`status` events that flip review-stack archival state, provisioning, or commit statuses for stacks belonging to the properly-secured org.

Given the rules' required impact list, the closest qualifying outcome is **"escalation into `Shipit.github_teams` authorization"** via forged `membership` events for teams tied to an under-secured org config, and secondarily unauthorized triggering of syncs/deploy-adjacent jobs against a properly configured org's stacks. This is High severity per the rubric, contingent on the deployment having at least one org configured without a `webhook_secret` (a state the engine's own docs mark as optional/acceptable) while other orgs are secured.

### Likelihood Explanation
Likelihood is conditional but plausible for any multi-org Shipit deployment: `webhook_secret` is documented as optional per org [8](#0-7) , and nothing in `Shipit.github_app_config` or `verify_signature` warns/blocks when secrets are inconsistently applied across configured organizations. An attacker only needs to know (or guess) that some org hosted by the instance lacks a webhook secret, then send a crafted POST to `/webhooks` with mismatched `repository.owner.login` vs `repository.full_name` — no GitHub App private key, `webhook_secret`, or session is required.

### Recommendation
Bind the org used for signature verification to the same repository/org actually acted upon by the handler, and never allow the security decision to hinge on presence of a signature for an *organization other than* the one whose data the request targets:
1. Reject the request (422) if `repository.owner.login` (or `organization.login`) does not match the resolved `stacks`/`Repository` owner that the handler is about to act on, instead of relying solely on `webhook_secret` presence for the payload-selected org.
2. Treat a missing `webhook_secret` for a configured organization as a hard misconfiguration to be fixed (e.g., fail closed / refuse to serve webhooks for that org) rather than "verified = true".
3. Add validation in `Handler#repository_name`/`stacks` to cross-check `payload.dig('repository','owner','login')` against `payload.dig('repository','full_name')`'s owner segment before trusting the payload.

### Proof of Concept
Preconditions: Shipit instance configured with two orgs — `secure-org` (has `webhook_secret` set) and `legacy-org` (configured, but `webhook_secret` left blank, as permitted by setup docs) — and it hosts a stack for `secure-org/prod-app`.

1. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "secure-org/prod-app",
    "owner": { "login": "legacy-org" }
  }
}
```
2. POST to `/webhooks` with header `X-Github-Event: push`, and any (even garbage or absent) `X-Hub-Signature`.
3. `repository_owner` resolves to `legacy-org` [5](#0-4) ; `Shipit.github(organization: 'legacy-org')` returns a `GitHubApp` whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally [11](#0-10) .
4. `create` proceeds and dispatches to `PushHandler`, which resolves `stacks` via `repository.full_name` = `secure-org/prod-app` [2](#0-1) , and enqueues `GithubSyncJob` for `secure-org/prod-app`'s stack — despite never presenting a valid signature for `secure-org`.

Note: I could not fully verify from the index whether any additional cross-checks exist elsewhere in the request pipeline (e.g., Rack middleware) that might constrain `repository.owner.login`/`full_name` consistency before reaching the controller; this is based solely on the in-scope engine files reviewed above.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
