### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits globally by `sha` with no repository/organization scoping, while `WebhooksController#verify_signature` selects which org's `webhook_secret` to verify the payload against based on the attacker-controlled `repository.owner.login` field in the same payload. An attacker who owns any configured GitHub organization in a multi-org Shipit deployment can therefore sign a `status` webhook with their own org's secret but reference a victim commit's `sha`, causing `create_status_from_github!` to write a forged CI status onto that victim commit.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't: the organization whose `webhook_secret` verifies the payload (`repository_owner` from `params.dig('repository','owner','login')` in `WebhooksController#repository_owner`, [1](#0-0)  ) must equal the organization that owns the repository/stack of the `Commit` matched by `sha` in `StatusHandler#process`. Nothing enforces this equality.

`WebhooksController` verifies signatures via `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, where `repository_owner` is read straight out of the attacker-supplied JSON body [2](#0-1) . `Shipit.github` resolves the org's config/secret via `github_app_config(organization)` keyed off that same attacker-supplied string [3](#0-2) . This is legitimate multi-tenant design: each org is verified with its own secret. The problem is downstream — `StatusHandler#process` never checks that the verified org owns the matched commit's repository:

```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

Compare this to the sibling handler `CheckSuiteHandler`, which correctly scopes lookups through `stacks`, itself derived from `Repository.from_github_repo_name(repository_name)` (i.e., the payload's `repository.full_name`, tied to the repo actually verified) [5](#0-4) [6](#0-5) . The `PullRequest` handlers similarly scope through `Repository.from_github_repo_name(params.repository.full_name)` before touching any stack [7](#0-6) . `StatusHandler` has no such repository binding at all — it is the odd one out.

Exploit flow: attacker registers/owns organization `attacker-org` which is configured in Shipit (`github_app_config('attacker-org')` returns a valid secret known to the attacker, e.g. because they legitimately administer that org's GitHub App/webhook). Attacker crafts a `status` event body: `{"repository": {"owner": {"login": "attacker-org"}}, "sha": "<victim commit sha>", "state": "success", ...}`, signs it with `attacker-org`'s webhook secret, and POSTs to `/webhooks` with `X-Github-Event: status`. `verify_signature` passes because it only checks that the signature matches `attacker-org`'s secret — it never checks that `attacker-org` actually owns the commit referenced by `sha`. `StatusHandler#process` then finds the victim's `Commit` row purely by `sha` and calls `commit.create_status_from_github!(params)`, writing a forged status (state/description/target_url) that can flip a blocking CI check to `success` [8](#0-7) [9](#0-8) .

None of the listed guards prevent this: `verify_signature` only authenticates "this payload was signed by org X's secret," not "org X owns the repository of the referenced sha"; `drop_unhandled_event` and the `ExplicitParameters` schema for `StatusHandler` only validate shape (`sha`, `state`, etc.), not ownership [10](#0-9) ; there is no `force_github_authentication`/`require_permission!`/`stacks` scope used in this handler at all.

### Impact Explanation
A successful request lets the attacker write a fabricated `Status` (state, description, target_url, context) onto any commit in the system whose `sha` they know or can guess/observe, regardless of which organization actually owns that commit's stack/repository. Because `Commit#deployable?` and blocking-status checks derive from `Status` rows created this way, this is a payload-for-one-repository-mutating-another's-commit scenario, which can enable an unauthorized deploy by flipping a blocking check to `success`. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team ... or an unauthorized deploy." It is repeatable against any commit sha in the database and not limited to a single victim stack; blast radius spans all tenants sharing the same Shipit instance.

### Likelihood Explanation
This requires the Shipit instance to be configured for multiple GitHub organizations (the `github_app_config`/multi-org secrets schema in `lib/shipit.rb`) and the attacker to control (or be able to sign for) at least one of those configured orgs' webhook secrets — a realistic scenario for any shared/multi-tenant Shipit deployment where each org manages its own GitHub App/webhook secret. The attacker also needs to know or discover a victim commit's `sha`, which is often knowable (git history, PRs, public repos) or brute-forceable within an org's own commit history. Given these preconditions, exploitation cost is low: a single signed HTTP POST.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the verified repository/organization instead of matching `sha` globally — e.g., resolve the repository via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` (as other handlers do) and only update commits belonging to stacks of that repository, or otherwise assert `commit.stack.repository` matches the verified `repository_owner`/`full_name` before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (controller-level, no live GitHub, using existing fixtures):
1. Set up two orgs in test credentials: `org-a` (attacker-controlled secret known in test) and `org-b` (victim), matching `github_app_config` schema.
2. Create `stack_victim` under `org-b`'s repository, with `commit_victim` (`shipit_commits(:first)` or a new fixture) belonging to `stack_victim`.
3. Build a `status` payload: `{ "sha" => commit_victim.sha, "state" => "success", "repository" => { "owner" => { "login" => "org-a" } }, "branches" => [...] }`.
4. Sign the payload with `org-a`'s webhook secret (`OpenSSL::HMAC.hexdigest('sha1', org_a_secret, body)`), set `X-Hub-Signature` and `X-Github-Event: status`.
5. POST to `webhooks#create`.
6. Assert: `assert_response :ok`; `assert_difference 'commit_victim.statuses.count', 1 do ... end`; `assert_equal 'success', commit_victim.reload.status.state` — demonstrating that a payload verified only under `org-a`'s secret mutated a commit belonging to `org-b`'s stack, proving `repository_owner(verified) != commit_victim.stack.repository.owner` yet the write still succeeded.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
