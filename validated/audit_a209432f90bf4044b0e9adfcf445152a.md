This confirms the exploitable mismatch. I have enough evidence to write the finding.

### Title
Webhook signature verified against the organization derived from `repository.owner.login`, while the event is applied to the stack matched by `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to verify a payload against using `repository.owner.login` (falling back to `organization.login`). All downstream event handlers, however, resolve which `Stack`/`Repository` to act on using `repository.full_name`, a completely separate field in the same JSON body that is never covered by the signature-selection logic in a binding way. In a multi-organization Shipit deployment (a documented, supported configuration), these two fields can be made to disagree: an attacker who knows (or controls) the webhook secret for **one** configured GitHub organization can forge a payload whose `repository.owner.login`/`organization.login` names that organization (so signature verification passes with a secret the attacker legitimately possesses) while `repository.full_name` names a repository belonging to a **different** configured organization/stack.

### Finding Description
`Shipit::WebhooksController#verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` looks up a distinct `GitHubApp` instance (with its own `webhook_secret`, keyed per-organization) for multi-org installs, as documented and configured in `docs/setup.md` ("Using Multiple Github Applications") and `config/secrets.development.shopify.yml`. [2](#0-1) [3](#0-2) 

`GitHubApp#verify_webhook_signature` only proves the HMAC was computed with the secret configured for **that particular organization key** — it says nothing about which repository the payload actually describes: [4](#0-3) 

Once signature verification passes, `WebhooksController#create` dispatches the raw parsed JSON to handlers unchanged:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [5](#0-4) 

Every handler resolves the target repository/stack from `repository.full_name`, not from `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

`PushHandler` then syncs commits for that stack using `full_name`-resolved stacks: [7](#0-6) 

**The broken equality**: the code implicitly assumes
`organization used to select the verifying webhook_secret (repository.owner.login) == organization owning the repository acted upon (derived from repository.full_name)`.
Nothing enforces this. An attacker with legitimate access to organization `OrgA`'s webhook secret (e.g. an admin of their own GitHub org that they registered as a second Shipit GitHub App, a fully supported multi-tenant scenario) can send:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
signed with `OrgA`'s `webhook_secret`. `repository_owner` resolves to `OrgA`, verification succeeds against `OrgA`'s secret, but `PushHandler`/other handlers act on the `OrgB/victim-repo` stack because they only look at `full_name`.

### Impact Explanation
This breaks a credential/repository trust boundary: possession of one organization's webhook secret becomes sufficient to inject GitHub events (push, status, check_suite, membership, pull_request, etc.) for repositories/stacks belonging to a different, unrelated organization configured on the same Shipit instance. Concretely reachable high-impact consequences:
- Forged `push` events can call `stack.sync_github(expected_head_sha:)` for a victim-org stack, feeding an attacker-chosen `after` SHA into `GithubSyncJob`, which is subsequently used by `Stack#trigger_continuous_delivery` for stacks with `continuous_deployment: true` — i.e. attacker-influenced input can drive an unauthorized deploy pipeline. [8](#0-7) [9](#0-8) 
- Forged `status`/`check_suite` events can create fabricated CI statuses/check runs against a victim-org's commits, which feed directly into `deployable_commits`/CI-gating logic used before deploys, undermining CI-based deploy gating for a repository the attacker does not control.

This satisfies the "unauthorized deploy" / cross-organization-write class of High/Critical impact defined in scope, since the trust boundary crossed is exactly "organization that authenticated the webhook" vs "repository that gets written to."

### Likelihood Explanation
Requires only: (1) the target Shipit instance is configured with multiple GitHub organizations (a documented, supported configuration), and (2) the attacker controls/administers a GitHub App installed on any one of those configured organizations (their own org), which is an unprivileged-attacker capability relative to the victim organization's stacks. No access to the victim's webhook secret, `ApiClient` token, or repository write access is needed — only the attacker's own org's webhook secret, which they legitimately hold.

### Recommendation
After signature verification, validate that the organization key used to select the verifying `GitHubApp`/secret matches the `owner.login` of the repository named in `repository.full_name` (i.e., re-derive the organization from `full_name` and compare it to `repository_owner`, or better, resolve the target `Stack`/`Repository` first and verify the signature using that repository's actual owning organization's secret rather than a value taken from the unauthenticated JSON body). Reject the webhook if they diverge.

### Proof of Concept
1. Configure Shipit with two GitHub Apps/organizations, `OrgA` (attacker-controlled, e.g. attacker registers their own GitHub App per `docs/setup.md`) and `OrgB` (victim, has a Stack for `OrgB/victim-repo` with `continuous_deployment: true`).
2. Attacker crafts a `push` webhook payload:
   ```json
   {"ref":"refs/heads/main","after":"<attacker_sha>","repository":{"owner":{"login":"OrgA"},"full_name":"OrgB/victim-repo"}}
   ```
3. Attacker signs the raw body with `OrgA`'s known `webhook_secret` and sends it to `POST /webhooks` with header `X-Github-Event: push` and the computed `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: 'OrgA')` and successfully verifies the signature using `OrgA`'s secret.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name('OrgB/victim-repo')` and calls `stack.sync_github(expected_head_sha: '<attacker_sha>')`, injecting attacker-influenced sync state into `OrgB`'s stack despite the attacker never possessing `OrgB`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```
