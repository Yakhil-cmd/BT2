### Title
Cross-organization webhook forgery — the org whose secret authenticates a webhook is not bound to the repository the payload acts on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/HMAC secret to verify a webhook against using an attacker-influenced field of the very payload it is about to validate, while the downstream `Webhooks::Handlers::Handler#repository_name` (used to locate the `Stack`/`Repository` that gets written to) reads a *different, independently-controlled* field of the same payload. In Shipit's supported multi-tenant configuration (multiple GitHub organizations behind one Shipit instance), these two fields are never checked for consistency, breaking the equality "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` computes the verifying secret from `repository_owner`: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` picks the app config (and therefore the `webhook_secret`) keyed by that same organization name, case-insensitively: [3](#0-2) 

Meanwhile, every event handler resolves the *acted-upon* repository from an entirely separate JSON key, `repository.full_name`, with no cross-check against `repository.owner.login`: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`Repository.from_github_repo_name` simply splits `"owner/name"` and does a DB lookup, with no relation to which secret verified the request: [5](#0-4) 

Because Shipit explicitly supports hosting multiple GitHub organizations from a single instance with one shared webhook endpoint, each with its own `webhook_secret` (`Shipit.github_app_config`, documented in "Using Multiple Github Applications"): [6](#0-5) [7](#0-6) 

an attacker who is merely an admin of *any one* of the configured organizations (OrgB) — an unprivileged actor with respect to a victim org (OrgA) also configured on the same Shipit instance — knows OrgB's `webhook_secret` (they can set it themselves when registering a webhook on their own org/repo). They can craft an arbitrary JSON body where:
- `repository.owner.login` = `"OrgB"` (used only to pick which secret verifies the signature)
- `repository.full_name` = `"OrgA/victim-repo"` (used to resolve the `Stack`/`Repository` actually acted on)

then sign the whole raw body with OrgB's known secret. `verify_signature` succeeds (it only checks the HMAC against OrgB's secret, over whatever bytes the attacker supplied), and the handler proceeds to act on OrgA's repository because `repository_name` is read independently from `repository.full_name`.

This equality is broken: **organization whose credential authenticated the request ≠ repository the handler writes to**.

### Impact Explanation
Depending on the event type forged, this allows an attacker who only controls a separate, unrelated GitHub organization on the same Shipit deployment to:
- Forge a `push` event naming a victim stack, causing `PushHandler` to call `stack.sync_github(expected_head_sha:)` with an attacker-chosen SHA for a repository the attacker does not own [8](#0-7) .
- Forge `status` events to inject fabricated CI/commit statuses against a victim stack's commits via `Commit#create_status_from_github!`, potentially satisfying merge-queue/deploy CI requirements gated on status checks [9](#0-8) .
- Forge `check_suite` events to trigger `schedule_refresh_check_runs!` on a victim stack's commits [10](#0-9) .
- Forge `pull_request` events (`opened`/`labeled`/`reopened`) to archive/unarchive or auto-provision review stacks belonging to a repository the attacker does not control, since these handlers also key off `params.repository.full_name` independently of the signing organization [11](#0-10) .

This is a cross-repository write achieved purely by controlling an unrelated org's webhook secret — matching the "cross-repository writes" / "unauthorized deploy" impact bucket.

### Likelihood Explanation
Likelihood is Medium: it requires (a) the Shipit deployment to be configured for multiple GitHub organizations sharing one instance (an explicitly documented and supported configuration), and (b) the attacker to be a legitimate admin/owner of at least one of those organizations — an "unprivileged attacker" relative to the victim org, but not relative to Shipit as a whole. Single-organization deployments (the common case, using the top-level `github:` schema) are not affected because there is only one secret to verify against, matching the single owner.

### Recommendation
Do not let the payload dictate which secret verifies it independent of what the payload asserts to act on. Concretely:
- After identifying the verifying organization from `repository_owner`, require that the `owner` prefix of `repository.full_name` match `repository_owner` exactly, rejecting the webhook otherwise.
- Alternatively, encode the expected organization into the webhook URL path (e.g. `/github/organization/:org/webhooks`) so the verifying secret is chosen by a value never taken from the request body, and validate `repository.full_name`'s owner segment matches the path parameter.

### Proof of Concept
Given a Shipit instance configured with multiple GitHub orgs (`OrgA`, `OrgB`) as in `docs/setup.md`'s multi-app section, and attacker controls `OrgB` (knows `OrgB`'s `webhook_secret`):

```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(OrgB_webhook_secret, body)>

body = {
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgB" },        // used only to pick verifying secret
    "full_name": "OrgA/victim-repo"       // used by handlers to find the Stack
  }
}
```

`verify_signature` calls `Shipit.github(organization: "OrgB")` and validates the HMAC against `OrgB`'s secret — which the attacker legitimately knows — so it passes. `PushHandler#process` then resolves `stacks` via `Repository.from_github_repo_name("OrgA/victim-repo")`, entirely unrelated to `OrgB`, and triggers `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` for a stack the attacker does not own. [12](#0-11) [13](#0-12) [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
