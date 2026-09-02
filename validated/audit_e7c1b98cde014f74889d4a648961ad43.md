### Title
Webhook signature verified against the payload's `repository.owner.login`/`organization.login` while all handlers act on the unverified `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read straight out of the still-unverified JSON body. Every webhook handler, however, resolves the target `Repository`/`Stack` using a *different* field from that same unverified body: `repository.full_name` [1](#0-0) . Because the field that is checked against the cryptographic signature (`repository.owner.login`) is not the field that determines which repository is mutated (`repository.full_name`), the two can be set independently by an attacker who only needs to know (or brute force via delivery of many pushes) a single organization's `webhook_secret` in a multi-org Shipit deployment.

### Finding Description
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
with
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

In a multi-organization configuration (`Shipit.github(organization:)` looks up per-organization secrets via `github_app_config`) [3](#0-2) , each configured GitHub organization has its own `webhook_secret`. The signature check only proves the request was HMAC-signed with the secret belonging to whatever organization name appears in the *unverified* `repository.owner.login`/`organization.login` field of the payload.

Once the signature passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3)  dispatches to handlers such as `PushHandler`, which resolve the affected stacks purely from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [1](#0-0) 

`PushHandler#process` then triggers `stack.sync_github(expected_head_sha: params.after)` for every matching stack [5](#0-4) , which schedules `GithubSyncJob` and ultimately drives continuous-delivery sync/deploy behaviour for that stack — using an attacker-supplied `after` SHA and `ref`.

The binding that should hold is:
```
organization whose secret signed the request == organization owning the repository that gets mutated
```
Because `repository.owner.login` (used to pick the secret) and `repository.full_name` (used to pick the mutated repository/stack) are two independent, attacker-controlled JSON fields inside the same unverified body, an attacker can set them inconsistently: sign the outer envelope so it validates against Org A's secret while pointing `repository.full_name` at a stack belonging to Org B that is registered in the same Shipit instance.

### Impact Explanation
If Shipit is configured with multiple GitHub organizations (the documented multi-org secrets schema) [6](#0-5) , and an attacker has legitimate push access to one repository under Organization A (and thus can trigger genuine, correctly-signed webhooks from Org A), they can craft their own POST to `/webhooks` (or reuse Org A's HMAC secret if it ever leaks/duplicated) that is valid per `verify_webhook_signature` for Org A but whose `repository.full_name` names a stack under Organization B. Handlers like `PushHandler`/`StatusHandler`/`CheckSuiteHandler` will then act on Org B's stack (queue sync jobs, update commit statuses, enqueue check-run refreshes) even though the request was never authenticated as coming from Org B. This crosses a repository-trust boundary that the signature mechanism is supposed to enforce, matching the "Cross-repository writes / unauthorized deploy trigger" impact category (deploy triggers stem from `sync_github` → continuous delivery).

### Likelihood Explanation
Exploitability strictly requires: (1) a Shipit deployment configured with the multi-organization `github:` secrets schema, and (2) the attacker controlling (or being able to sign with) at least one configured organization's `webhook_secret` — e.g., by having legitimate webhook delivery rights on a repo under that org, or the secret being reused/leaked across orgs. Single-organization deployments (the common/default case, where `github_default_organization` is `nil`) are not affected because there is only one secret to verify against regardless of the payload content. This limits likelihood to specific multi-tenant setups, but no additional privilege beyond "push access to one onboarded org/repo" is required to attack a different org's stacks in that configuration.

### Recommendation
Bind signature verification and repository resolution to the same trusted value: after verifying the signature with the organization implied by `repository_owner`, re-validate that `repository.full_name`'s owner segment matches that same `repository_owner` (case-insensitively) before dispatching to handlers, or resolve the `Repository`/webhook secret from Shipit's own stored `Repository`/`Hook` record (keyed by an already-known repository) rather than trusting any organization name taken from the unverified payload.

### Proof of Concept
1. Configure Shipit with two organizations, `orga` and `orgb`, each with a distinct `webhook_secret`, and onboard a repository `orgb/target-repo` (with a `Stack`) under `orgb`.
2. As an attacker with legitimate push access to a repo under `orga` (and therefore knowledge of `orga`'s `webhook_secret`, since GitHub delivers signed webhooks to any registered receiver for that org), build a payload:
```json
{
  "repository": {
    "owner": { "login": "orga" },
    "full_name": "orgb/target-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
3. Sign the raw body with `orga`'s `webhook_secret` using `sha1=HMAC-SHA1(secret, body)` and send it as `X-Hub-Signature`, with `X-Github-Event: push`, to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: 'orga')`, which succeeds against `orga`'s secret [7](#0-6) .
5. `PushHandler` then resolves stacks via `repository.full_name` = `orgb/target-repo` [1](#0-0)  and calls `stack.sync_github(expected_head_sha: <attacker sha>)`, even though the request was never signed by `orgb`.

Note: I was not able to fully trace `Repository.from_github_repo_name` and `Shipit::Webhooks::DEFAULT_HANDLERS` registration in this pass to enumerate every affected event type beyond `push`/`status`/`check_suite`, and I could not confirm in-repo test coverage proving/disproving this exact cross-org scenario — these would benefit from further review in a full Devin session given index size limits on the codebase.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
