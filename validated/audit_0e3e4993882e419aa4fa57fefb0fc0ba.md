### Title
Cross-repository commit-status forgery via globally-scoped `Commit.sha` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using the `repository.owner.login` (or `organization.login`) field taken directly from the unverified JSON body [1](#0-0) [2](#0-1) . This only proves the payload was legitimately signed by *that organization's* configured GitHub App/secret — it says nothing about which repository's data may be written. `StatusHandler`, however, does not scope its write by repository/organization at all: it looks up commits purely by SHA across the entire `commits` table and mutates them.

### Finding Description
`Shipit::Webhooks::Handlers::StatusHandler#process` executes: [3](#0-2) 

This ignores the `Handler#stacks`/`repository_name` scoping mechanism that other handlers use (e.g. `CheckSuiteHandler` correctly scopes through `stacks.where(branch: …)` before touching commits, derived from `payload.dig('repository','full_name')` [4](#0-3) [5](#0-4) ). `StatusHandler` instead calls `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no join or filter on `repository`/`stack`.

The binding that should hold is:
`organization whose secret verified the signature == organization owning the repository/commit that gets written`

In this deployment model, Shipit supports multiple GitHub organizations each with its own `app_id`/`installation_id`/`webhook_secret` [6](#0-5) [7](#0-6) . `verify_signature` only checks that the payload was legitimately signed for the organization named inside that same payload — it never checks that the SHA being acted upon in `StatusHandler` actually belongs to a commit/repository tracked under that organization. An attacker who legitimately controls (or is a collaborator on) any repository in Organization A — and can therefore trigger a genuinely-signed `status` webhook for that org (e.g. by setting a commit status via the GitHub API on their own repo, or through any GitHub-native action that emits a `status` event) — can pick/influence the `sha` value going into that event. If that SHA also identifies a commit tracked by a *different* organization's stack (identical commit objects shared across mirrored/forked repositories onboarded into the same Shipit instance under different orgs — a supported multi-org configuration), the handler will happily update that other organization's commit/status record.

### Impact Explanation
`Commit#create_status_from_github!` persists a `Status` used by Shipit's deploy-gating logic (`deployable?`/release status checks). Forging a passing status on a commit in a stack the attacker does not own can unblock or otherwise manipulate deploy eligibility for that unrelated stack/repository — this is a cross-repository write and can lead to an unauthorized deploy, both explicitly listed as Critical impacts.

### Likelihood Explanation
Exploitability requires: (1) a Shipit instance configured with multiple GitHub organizations (a documented, supported configuration [7](#0-6) ), and (2) a SHA collision/overlap between a commit the attacker can legitimately generate a signed webhook for and a commit tracked in a different org's stack (e.g., mirrored/forked repositories, shared library commits, or vendored history present in multiple onboarded repos). This is not a cryptographic hash collision requirement — it only requires the *same git commit object* to exist in Shipit-tracked history under two different organizations, which is a realistic scenario for mirrored/forked codebases. No possession of `webhook_secret`, `api_clients_secret`, or a Shipit session/API token is required — only ordinary GitHub access sufficient to produce a genuinely-signed webhook for the attacker's own organization.

### Recommendation
Scope `StatusHandler#process` through the same repository-derived `stacks` mechanism used by `CheckSuiteHandler`/`PushHandler` (i.e. resolve commits only within `stacks.joins(...).where(sha: params.sha)` derived from `payload.dig('repository','full_name')`), so that a webhook verified for organization X can never mutate commit/status data belonging to a repository not owned by X.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`).
2. Onboard `OrgA/repo` and `OrgB/repo` (a mirror/fork sharing history) as Shipit stacks, both containing commit `abc123...`.
3. As a collaborator with push/status rights on `OrgA/repo`, set a commit status (`success`) on commit `abc123...` via the GitHub API — GitHub emits a `status` webhook signed with `OrgA`'s webhook secret and `repository.owner.login = "OrgA"`.
4. `WebhooksController#verify_signature` validates the signature using `OrgA`'s secret and passes.
5. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, which matches the commit row belonging to `OrgB/repo`'s stack, and writes a forged `success` status onto it — despite the request never being signed for `OrgB`.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
