### Title
Webhook signature verified for one organization but `status` event writes are applied globally by commit SHA with no repository/organization binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook based on the organization derived from the payload (`repository.owner.login`, falling back to `organization.login`), then looks up a per-organization `GitHubApp`/`webhook_secret` to validate the HMAC signature. Once verified, `StatusHandler#process` performs its write purely against `params.sha`, with no re-check that the commit being updated actually belongs to the organization/repository whose secret authenticated the request. This mirrors the FTN-3 bug class: the "existence/ownership check" (signature verified against organization X) and the "action performed" (status write on any commit matching a SHA) are decoupled, so the verified identity never constrains the object mutated.

### Finding Description
The webhook signature check selects the app/secret using the payload's own organization field: [1](#0-0) [2](#0-1) 

After signature verification succeeds for organization X, the raw JSON payload is dispatched unchanged to handlers: [3](#0-2) 

`StatusHandler`, which handles `status` events, never consults `repository`/`organization` at all — it looks up commits purely by `sha` across the whole database and writes a status to every match: [4](#0-3) 

Compare this to the base `Handler` class, which *does* provide a `repository_name`/`stacks` scoping helper derived from `payload.dig('repository', 'full_name')` that other handlers (`PushHandler`, `CheckSuiteHandler`) use to scope their side effects to the correct repository: [5](#0-4) [6](#0-5) 

`StatusHandler` does not use `stacks`/`repository_name` at all — its write path (`Commit.where(sha: params.sha)`) is completely independent of the organization that signed the request. Because Shipit explicitly supports hosting multiple, independently-managed GitHub Apps/organizations from one instance (each with its own `webhook_secret`, as documented and tested): [7](#0-6) [8](#0-7) 

an attacker who legitimately administers their own organization's GitHub App (and therefore legitimately knows that organization's `webhook_secret`) can produce a validly-signed `status` webhook for their own org, but set `sha` to a commit SHA that belongs to a *different* tracked organization/repository. `verify_signature` will pass (it only checks the HMAC against the attacker's own org's secret), yet `StatusHandler#process` will apply the status update to the matching `Commit` regardless of which org/repo it belongs to.

### Impact Explanation
Commit statuses gate Shipit's merge queue and deploy safety logic (blocking statuses, CI gating) per project changelog. Being able to inject an arbitrary `success`/`failure` status onto a commit belonging to an org/repo the attacker doesn't administer allows bypassing required CI checks for that unrelated stack, potentially enabling an unauthorized merge or deploy to proceed — matching the "unauthorized deploy, rollback, or merge" Critical impact criterion, since the write happens through a signature the attacker does control but for a repository binding they do not.

### Likelihood Explanation
Requires the attacker to run their own legitimately-configured GitHub organization/App under the same Shipit deployment (a supported, documented multi-org configuration) and to know a target commit SHA in the victim's tracked repository (commit SHAs are frequently public/guessable, e.g., visible via GitHub's public API/UI for any repo the attacker can view). No access to the victim org's secret, session, or ApiClient token is needed — only the attacker's own valid webhook signature.

### Recommendation
`StatusHandler` (and any other handler that does not currently scope by repository) should resolve the target commit through the same repository-scoping helper (`Repository.from_github_repo_name(repository_name)` / `stacks`) used elsewhere, and reject or ignore matches whose owning stack's repository does not correspond to the organization that authenticated the webhook (`repository_owner` used in `verify_signature`). This ties the verified organization to the object being mutated, closing the gap between "who signed" and "what gets written."

### Proof of Concept
1. Deploy Shipit configured with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` multi-app configuration), each with tracked stacks/commits.
2. As the administrator of `OrgA` (an "unprivileged" party with respect to `OrgB`), obtain `OrgA`'s `webhook_secret` (legitimately, since you administer that org's App).
3. Craft a `status` event payload: `{"sha": "<commit-sha-belonging-to-OrgB-repo>", "state": "success", ...}` together with `"repository": {"owner": {"login": "OrgA"}}` (or `"organization": {"login": "OrgA"}` if no repository key) so `repository_owner` resolves to `OrgA`.
4. Sign the raw body with `OrgA`'s `webhook_secret` using HMAC-SHA1 and set `X-Hub-Signature`.
5. POST to `/webhooks` with `X-Github-Event: status`. `WebhooksController#verify_signature` succeeds (verified against `OrgA`'s secret).
6. `StatusHandler#process` executes `Commit.where(sha: params.sha)` and creates/updates a status on the `OrgB` commit, even though the request was never authenticated as `OrgB`, achieving a cross-organization commit-status write.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
