### Title
Cross-tenant webhook forgery via `repository.owner.login` / `repository.full_name` divergence in `CheckSuiteHandler#process` - ([File: app/models/shipit/webhooks/handlers/check_suite_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC secret) to validate a webhook using `params.dig('repository', 'owner', 'login')`, while `Handler#stacks`/`repository_name` (used by `CheckSuiteHandler#process`) resolves the target repository from the independent, attacker-controlled `payload.dig('repository', 'full_name')` field. Because both fields live in the same attacker-supplied JSON body and nothing enforces they refer to the same organization, an attacker who legitimately controls one onboarded GitHub organization in a multi-org Shipit install can sign a payload with their own valid secret while pointing `repository.full_name` at a victim organization's repository, causing `commit.schedule_refresh_check_runs!` to be enqueued against a stack/commit the attacker never authenticated for.

### Finding Description
The broken binding, stated explicitly: **the organization whose `webhook_secret` verified the request bytes (`params.dig('repository','owner','login')`, read in `repository_owner`) must equal the organization that owns the repository/stack/commit the handler subsequently mutates (`payload.dig('repository','full_name')`, read in `Handler#repository_name`)**. No code enforces this equality.

Code path:
- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner)` to pick the `GitHubApp` (and its `webhook_secret`) used to HMAC-verify the raw body. [1](#0-0) [2](#0-1) 
- `Shipit.github` looks up per-organization config in a multi-app deployment (`docs/setup.md` "Using Multiple Github Applications"), and each org has its own `webhook_secret`. [3](#0-2) 
- `GitHubApp#verify_webhook_signature` HMACs the raw body with that org's own secret; if that org's `webhook_secret` is unset it returns `true` unconditionally, an additional bypass. [4](#0-3) 
- Once verified, `WebhooksController#create` dispatches the *entire, unmodified* JSON body to `Shipit::Webhooks.for_event(event)` handlers, including `CheckSuiteHandler`. [5](#0-4) [6](#0-5) 
- `Handler#stacks` and `#repository_name` resolve the target `Repository` purely from `payload.dig('repository', 'full_name')` — a completely different field from the one used for signature verification. [7](#0-6) 
- `CheckSuiteHandler#process` then finds stacks on that resolved repository matching `head_branch` and, for matching `head_sha`, calls `commit.schedule_refresh_check_runs!`. [8](#0-7) 

Exploit flow: an attacker who legitimately administers "attacker-org" (a GitHub org onboarded to this multi-tenant Shipit instance, so they know their own configured `webhook_secret`) crafts a `check_suite` payload where:
- `repository.owner.login` = `"attacker-org"` (so `verify_signature` resolves and validates against the attacker's own known secret — passes)
- `repository.full_name` = `"victim-org/victim-repo"` (a public repository name already onboarded by the victim)
- `check_suite.head_branch` / `check_suite.head_sha` set to a known existing branch/commit of the victim's stack (visible via public GitHub or Shipit's public stack pages)

They sign the raw body with their own `attacker-org` secret and POST it to `/webhooks`. `verify_signature` passes because it validates against `attacker-org`'s legitimate secret, but `CheckSuiteHandler#process` acts on `victim-org/victim-repo`'s stack/commit, none of which the attacker's signature authenticated.

Existing guards that fail to prevent this: `verify_signature` only checks that *some* org's secret matches the body — it never checks that org name against the repository the handlers will act on; `drop_unhandled_event` and the `ExplicitParameters` schema in `CheckSuiteHandler` only validate presence/type of `head_sha`/`head_branch`, not any owner/repository consistency; `force_github_authentication`/`User#authorized?`/`require_permission!` are irrelevant to unauthenticated webhook ingestion.

### Impact Explanation
An attacker who controls one organization onboarded to a multi-tenant Shipit instance can cause the engine to enqueue `RefreshCheckRunsJob`/`schedule_refresh_check_runs!` work against an arbitrary victim stack's commit that they never authenticated for, by simply diverging two independent fields (`repository.owner.login` vs `repository.full_name`) inside one signed payload. This is a payload for one repository (attacker's) mutating state tied to another repository/stack/commit (victim's) — matching the Critical impact category "a payload for one repository mutating another's stack, commit, task or team." It is repeatable indefinitely against any repository/branch/sha combination the attacker can guess or observe (which for public GitHub repos is generally public information), and it can interfere with deploy-gating logic tied to check-suite status for the victim stack. This is scoped to multi-org Shipit deployments where more than one GitHub organization's App/secret is configured; single-org deployments do not expose this specific cross-tenant divergence because there is only one possible `repository_owner`.

### Likelihood Explanation
This requires a Shipit deployment configured with the multi-org GitHub App schema (`github.somegithuborg`, `github.someothergithuborg`, ...) as documented, and requires the attacker to control at least one of those onboarded orgs (or its `webhook_secret`) while a victim org is also onboarded — a realistic scenario for any shared/multi-tenant Shipit installation. Cost to the attacker is a single crafted, self-signed HTTP POST to `/webhooks`; no Shipit session, API token, or victim secrets are needed. It is trivially repeatable against any victim repository name and any observable branch/sha pair.

### Recommendation
In `WebhooksController`, resolve the target repository the same way handlers do (`payload.dig('repository','full_name')`), derive its owning organization from that resolved `Repository`'s stored config/owner (not from the raw, attacker-controlled `owner.login` field) before selecting the `GitHubApp`/secret to verify against; alternatively, after verification, assert that the verifying organization equals the owner of the repository referenced by `full_name` and reject (422) on mismatch. Also treat "no `webhook_secret` configured" as fail-closed rather than fail-open in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`), using the multi-org fixture `test/dummy/config/secrets_double_github_app.yml`:
1. Stub `Shipit.secrets.github` to contain `OrgOne` (attacker-controlled, with a known `webhook_secret`) and `OrgTwo` (victim, with its own distinct `webhook_secret`).
2. Create a victim stack under `Repository` with `full_name` = `"OrgTwo/victim-repo"`, `branch` = `"master"`, with a `Commit` whose `sha` matches a known value.
3. Build a `check_suite` JSON payload: `repository.owner.login` = `"OrgOne"`, `repository.full_name` = `"OrgTwo/victim-repo"`, `check_suite.head_branch` = `"master"`, `check_suite.head_sha` = the victim commit's sha.
4. Compute `X-Hub-Signature` using `OrgOne`'s `webhook_secret` (known/controlled by attacker) over the raw JSON body.
5. POST to `/webhooks` with `X-Github-Event: check_suite` and the computed signature.
6. Assert `response` is `:ok` (signature verification passed using `OrgOne`'s secret) AND `assert_enqueued_with(job: RefreshCheckRunsJob, args: [commit_id: victim_commit.id, ...])` — i.e., the equality `verifying_org ("OrgOne") == owning_org_of_target_repository ("OrgTwo")` is false, yet the job is enqueued anyway, proving the binding is broken.

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

**File:** app/models/shipit/webhooks.rb (L19-22)
```ruby
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
