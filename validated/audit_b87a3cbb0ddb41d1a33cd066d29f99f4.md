### Title
Webhook signature verification selects the signing organization from an unverified payload field, allowing cross-organization commit-status/event forgery on multi-org Shipit instances - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and therefore which `webhook_secret`) to validate a webhook against using `repository_owner`, a value read straight out of the untrusted, not-yet-verified JSON body. The rest of the pipeline (`Shipit::Webhooks::Handlers::Handler#repository_name`) locates the target `Stack`/`Repository` using a *different* field of the same untrusted body, `repository.full_name`, without ever checking it is consistent with the organization whose secret produced a valid signature.

### Finding Description
On a multi-org Shipit deployment (`secrets.github` keyed by organization, e.g. `OrgOne`/`OrgTwo` as in `test/dummy/config/secrets_double_github_app.yml`), each configured GitHub organization has its own independent `webhook_secret` [1](#0-0) .

`verify_signature` derives the signing key purely from the payload's claimed owner, before the signature has been checked: [2](#0-1) [3](#0-2) 

`Shipit.github(organization:)` looks up the app config for that claimed organization and, if found, uses its dedicated `webhook_secret` to validate `X-Hub-Signature`: [4](#0-3) [5](#0-4) 

Once the signature check passes, event handlers ignore `repository_owner` entirely and instead trust `repository.full_name` (a sibling field of the same JSON body) to resolve the actual `Repository`/`Stack` that gets acted upon: [6](#0-5) [7](#0-6) 

There is no code anywhere that asserts `repository.owner.login == repository.full_name.split('/').first`. This breaks the binding **organization-authenticated == repository-written**: the signature only proves the request was HMAC-signed with *some* configured organization's secret, not that the events inside the payload actually pertain to that organization's repositories.

### Impact Explanation
Any principal who legitimately controls (or can read the webhook configuration of) one onboarded GitHub organization on a shared, multi-org Shipit instance knows that organization's `webhook_secret` (it is set at GitHub App/organization-installation configuration time, independent per org, per `github_app_config`) [8](#0-7) . Using that secret, they can sign an arbitrary payload whose `repository.owner.login`/`organization.login` names their own org (so `verify_signature` picks their org's secret and accepts it) while `repository.full_name` names a repository belonging to a *different, unrelated* organization also hosted on the same Shipit instance. Because handlers resolve the target purely from `repository.full_name`, the forged event is applied to that unrelated org's stack.

Concretely reachable handlers:
- `StatusHandler#process` creates a commit status (`create_status_from_github!`) on any commit by `sha`, without any repository/organization ownership check on the `Commit` itself [9](#0-8) , letting the attacker mark commits of a stack they do not own as `success`, which Shipit's UI/merge/deploy-gating logic relies on as CI status.
- `CheckSuiteHandler#process` and `PushHandler#process` likewise operate on `stacks` resolved solely from the forged `repository.full_name`, forcing check-run refreshes or GitHub syncs against a stack outside the attacker's own organization [10](#0-9) [11](#0-10) .

This is a cross-repository/cross-organization write achieved by an attacker who is only trusted for one organization on the shared instance, matching the required "cross-repository writes" / gate for "unauthorized deploy" impact class, since forged green commit statuses can unlock deploy actions that are otherwise gated on CI status.

### Likelihood Explanation
This requires the Shipit instance to be configured with more than one GitHub organization (the multi-org config schema `secrets.github: { OrgOne: {...}, OrgTwo: {...} }` documented and tested in this repo), and the attacker to be someone entrusted with configuring/administering one of those organizations' GitHub App (hence knowing its `webhook_secret`) but not others. This is a realistic scenario for shared/multi-tenant Shipit deployments, though it does not apply to single-organization deployments (the common case, where `github_default_organization` is `nil` and there is only one secret to know) [12](#0-11) .

### Recommendation
After `verify_signature` succeeds, re-derive the organization from the same trusted field the handlers use (`repository.full_name` / `repository.owner.login`) and assert they match the organization whose secret validated the signature, rejecting the webhook (422) on mismatch. Alternatively, bind `Handler#repository_name`/`stacks` resolution to the already-verified `repository_owner` instead of re-reading an independent, uncorrelated field of the payload.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgOne` and `OrgTwo`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker administers `OrgOne`'s GitHub App and thus knows `OrgOne`'s `webhook_secret`.
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim-commit-sha-in-OrgTwo-repo>",
  "state": "success",
  "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgOne_webhook_secret, body)` and POSTs to `/github/webhooks`.
5. `verify_signature` calls `Shipit.github(organization: "OrgOne")`, uses `OrgOne`'s secret, and the signature validates successfully.
6. `StatusHandler#process` looks up `Commit.where(sha: ...)` — a commit belonging to `OrgTwo/victim-repo` — and calls `create_status_from_github!`, marking it green, despite the attacker never having been authenticated for `OrgTwo`.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** lib/shipit.rb (L170-181)
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
```

**File:** lib/shipit.rb (L183-188)
```ruby
  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
