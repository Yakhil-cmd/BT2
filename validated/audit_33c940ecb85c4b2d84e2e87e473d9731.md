### Title
Cross-repository commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController` verifies the HMAC signature of a GitHub `status` webhook against the `webhook_secret` belonging to the organization named in the payload, then hands the *raw, unscoped* JSON body to `StatusHandler`. Unlike `PushHandler`, which resolves the target `Stack` through `Repository.from_github_repo_name(repository_name)` before acting, `StatusHandler#process` looks up commits solely by `sha` across the *entire* database, with no check that the commit's repository matches the repository/organization whose signature was actually verified.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret used to authenticate the request) using `repository_owner`, taken from the payload itself [1](#0-0) , and dispatches to handlers only after that signature check passes [2](#0-1) .

The base `Handler` class provides a `stacks` helper that correctly scopes lookups to the repository named in the payload via `Repository.from_github_repo_name(repository_name)` [3](#0-2) , and `PushHandler` uses exactly that scoping before touching any stack [4](#0-3) .

`StatusHandler`, however, never calls `stacks` / `repository_name` at all. It queries `Commit.where(sha: params.sha)` globally and mutates every matching commit's status regardless of which repository (and therefore which signing organization) it belongs to [5](#0-4) .

This is the same class of bug as the reported `BytesLib.concat` issue: a value that is nominally covered by the "trust boundary" (here, the verified webhook signature that is supposed to authorize actions only for the *sending organization's* repository) is not actually cross-checked against the field being acted on (the commit's owning repository). The binding that should hold —
`organization authenticated by signature == organization owning the repository whose commit is mutated`
— is never enforced.

### Impact Explanation
In the documented multi-tenant configuration (`docs/setup.md`, "Using Multiple Github Applications", and `config/secrets.development.shopify.yml` / `test/dummy/config/secrets_double_github_app.yml`) a single Shipit instance can host stacks for multiple independent GitHub organizations, each with its own `webhook_secret` [6](#0-5) . An organization that legitimately owns its own webhook secret can sign a `status` event referencing a commit `sha` that also exists in another tenant's repository/stack (identical SHA-1 commit hashes routinely occur across forks, cherry-picks, or shared history). `StatusHandler` will apply the forged status to that commit in the *other* tenant's stack, because it never re-checks the repository, even though `Commit#create_status_from_github!` feeds into deploy/merge gating logic. This allows one authenticated-but-unprivileged tenant to write/forge commit status data belonging to a repository it does not control, and to influence that repository's deployability/merge gating — a cross-repository write.

### Likelihood Explanation
Requires only a legitimately configured GitHub App/webhook secret for *any one* organization hosted on the same multi-tenant Shipit instance (no privileged Shipit account, GitHub token, or repository write access to the victim repo is needed). The only added requirement is a commit `sha` collision across repositories, which is common in practice (shared upstream history, cherry-picks, forks, vendored/mirrored branches, monorepo split-outs).

### Recommendation
Scope `StatusHandler#process` (and any other handler mutating cross-repository state) the same way `PushHandler` does: resolve the target repository via `Repository.from_github_repo_name(repository_name)` / the `stacks` helper from `Handler`, and restrict the `Commit.where(sha:)` lookup to commits belonging to stacks of that repository, rather than a global, repository-unscoped query.

### Proof of Concept
1. Configure Shipit with two tenants, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. `OrgB` has a `Stack` tracking a commit whose sha is `SHA_X` (e.g., because it shares history/a cherry-picked commit with `OrgA`'s repo).
3. Attacker, who legitimately controls `OrgA`'s GitHub App/webhook secret, sends a `status` webhook to `/webhooks` for `OrgA`'s repository, signed correctly with `OrgA`'s `webhook_secret`, with body:
```json
{ "sha": "SHA_X", "state": "success", "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/repo" } }
```
4. `WebhooksController#verify_signature` verifies the signature against `OrgA`'s secret and passes [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: 'SHA_X')`, which matches the commit belonging to `OrgB`'s stack, and calls `create_status_from_github!` on it, forging a status on a commit `OrgA` never has access to [5](#0-4) .

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
