### Title
`StatusHandler` writes commit statuses without validating that the commit belongs to the organization whose webhook secret authenticated the request - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by SHA globally, across every `Stack`/`Repository` known to the whole Shipit instance, with no check that the commit belongs to the repository/organization whose webhook secret was used to authenticate the incoming request.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the webhook secret to validate against) using `repository_owner`, itself taken from the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or the `organization` sub-object): [1](#0-0) [2](#0-1) 

Shipit explicitly supports multiple GitHub organizations configured with independent `webhook_secret` values in the same instance: [3](#0-2) [4](#0-3) 

Once the HMAC signature is valid for the organization named in the payload, the raw body is dispatched to every registered handler for the event: [5](#0-4) 

Most handlers (`push`, `check_suite`, pull-request handlers) correctly scope their side effects to the repository named in `payload['repository']['full_name']`, via `Handler#stacks`/`Repository.from_github_repo_name`: [6](#0-5) [7](#0-6) 

`StatusHandler`, however, does not scope by repository at all — it queries `Commit.where(sha: params.sha)` across the entire database and writes a GitHub-style status onto every matching commit, regardless of which repository/organization it belongs to: [8](#0-7) 

This breaks the binding "organization that authenticated versus the repository that is written": the signature check only proves the sender knows OrgA's `webhook_secret`, but the `status` handler's write target (an arbitrary commit belonging to OrgB, OrgC, etc.) is never checked against OrgA at all.

### Impact Explanation
Anyone who legitimately administers webhooks for one organization onboarded into a multi-org Shipit deployment (i.e., knows/controls that organization's `webhook_secret`, which is routine to configure a GitHub webhook) can send a directly-crafted, correctly-signed `status` webhook naming any commit SHA belonging to a different organization's repository tracked by the same Shipit instance. This lets the attacker inject forged CI status entries (`state: success`, arbitrary `context`/`description`/`target_url`) onto another organization's commits. Because commit statuses feed into Shipit's "deployable" checks and merge-queue/continuous-deployment gating logic (`Status`/`Status::Group`, `Stack` deployable status), this can be used to satisfy status checks required for continuous delivery or merging on a repository the attacker has no legitimate access to — an unauthorized-deploy-adjacent cross-repository write. This matches the report's "High" bar (escalation of write/authorization beyond the credential's intended scope) at minimum, and can enable an unauthorized deploy if the target stack's `shipit.yml` gates deploys purely on status checks satisfied this way.

### Likelihood Explanation
Requires the attacker to control (or know) the webhook secret of at least one organization already integrated with the target Shipit instance — a low bar in any Shipit deployment onboarding several orgs, since each org's own admins configure and therefore know their org's webhook secret. No Shipit login, `ApiClient` token, or GitHub App private key is needed; only a raw HTTP POST to the public webhooks endpoint with a valid HMAC for the attacker's own org.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository named in the webhook payload (e.g., via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and its stacks/commits), mirroring the pattern already used by `PushHandler`/`CheckSuiteHandler`/`Handler#stacks`, and additionally verify that the resolved repository's owner matches the organization that authenticated the webhook (`repository_owner` used in `verify_signature`).

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with distinct `webhook_secret`s (supported per `docs/setup.md`/`lib/shipit.rb#github_app_config`).
2. As an admin of `OrgA` (who legitimately knows `OrgA`'s webhook secret), find or guess a commit SHA belonging to a stack under `OrgB` (e.g., visible in a public deploy log/URL).
3. POST to `/webhooks` with header `X-Github-Event: status`, `X-Hub-Signature` computed with `OrgA`'s secret over a body such as:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/anything" },
  "sha": "<OrgB commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged",
  "target_url": "https://example.com"
}
```
4. `verify_signature` validates against `OrgA`'s secret and succeeds. `StatusHandler#process` finds the commit by SHA (belonging to `OrgB`) and calls `commit.create_status_from_github!(params)`, injecting a forged status unrelated to `OrgA`.

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
