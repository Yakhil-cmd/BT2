### Title
Webhook signature is bound to the payload's claimed organization, but `StatusHandler` mutates commits in *any* organization's repository by `sha` alone - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's GitHub App secret to HMAC-verify against using a field taken straight out of the unverified JSON body, then hands the *entire* body to event handlers. `StatusHandler`, unlike `PushHandler`/`CheckSuiteHandler`, never re-checks that the acted-upon object (a `Commit`, looked up globally by `sha`) actually belongs to the organization that produced the valid signature. This breaks the binding: "organization that authenticated" == "repository that is written."

### Finding Description
`verify_signature` picks the secret to validate against like this: [1](#0-0) 

where `repository_owner` is read directly from the still-unauthenticated body: [2](#0-1) 

In a multi-org Shipit deployment each organization has its own independently configured `webhook_secret`, resolved via `Shipit.github_app_config` / `Shipit.github`: [3](#0-2) [4](#0-3) 

So the HMAC check only proves "the sender knows the secret belonging to the organization named in `repository.owner.login`/`organization.login`" - it says nothing about the rest of the payload's contents.

Once verification passes, `WebhooksController#create` dispatches the raw, fully attacker-controlled body to the handler: [5](#0-4) 

`Handler` normally re-derives scope from `repository.full_name` via `stacks`: [6](#0-5) 

`PushHandler` and `CheckSuiteHandler` use that `stacks` scope, but `StatusHandler` does not - it searches `Commit` globally by `sha` across every stack/repository/organization in the whole Shipit instance: [7](#0-6) 

The equality that must hold for this trust boundary is:
`organization whose secret validated the HMAC == organization that owns the repository/commit being mutated`

`StatusHandler` never enforces the right-hand side. An organization admin who legitimately possesses their *own* org's `webhook_secret` (e.g. a self-service/delegated multi-tenant Shipit setup, as documented in "Using Multiple Github Applications") can:
1. Set `repository.owner.login` (or `organization.login`) to their own organization, so `verify_signature` fetches and checks against a secret they already know → signature passes.
2. Set `sha` to a commit SHA belonging to a target stack in a *different, unrelated* organization.
3. Set `state`, `context`, `description`, `target_url` to whatever they want (e.g. `state: "success"`).

`StatusHandler#process` will locate the victim's `Commit` purely by `sha` (regardless of which repository it actually belongs to) and call `commit.create_status_from_github!(params)`, writing a forged status onto a commit in an organization the attacker never authenticated for.

### Impact Explanation
Commit statuses (`commit_status` / `deployable_status` are first-class webhook/notification events in this engine, see `Hook::EVENTS`) are used by stacks to gate deploy readiness. Forging a `success` status on an arbitrary commit in a different organization's repository can make that commit appear deployable/mergeable, contributing to an unauthorized deploy on a repository the attacker has no legitimate access to - this is a cross-organization write achieved purely from knowledge of one's own (legitimately obtained) org secret, i.e. a privilege boundary that should isolate tenants from each other is not enforced. This matches the "cross-repository writes / unauthorized deploy" Critical impact category. [8](#0-7) 

### Likelihood Explanation
This requires only a valid webhook secret for *some* organization configured in the same multi-tenant Shipit instance - not for the victim organization. Any multi-org Shipit deployment where different organizations are only meant to control their own data (the documented "Using Multiple Github Applications" setup) is affected as soon as more than one tenant's secret exists. No GitHub write access, `ApiClient` token, or session is needed - only the ability to send an HTTP POST to `/webhooks` with a body signed with one's own org's key.

### Recommendation
In `StatusHandler` (and any other handler that doesn't already scope through `Handler#stacks`), require and cross-check `repository.full_name`/`repository.owner.login` against the `Commit`'s associated `Stack`/`Repository`, rejecting or ignoring status updates whose commit does not belong to the repository named in the same payload that was used to select the signing organization.

### Proof of Concept
1. Multi-org Shipit config with `orgA` (attacker-controlled, attacker knows `webhook_secret_A`) and `orgB` (victim, stack `orgB/target-repo`, commit `deadbeef` pending deploy).
2. Attacker crafts JSON body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/some-repo" },
  "sha": "deadbeef",
  "state": "success",
  "context": "ci/forced"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_A, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner => "orgA"`, fetches `orgA`'s app, and verifies successfully (attacker knows this secret).
5. `StatusHandler#process` runs `Commit.where(sha: "deadbeef")` — finds the commit belonging to `orgB/target-repo` (unrelated to `orgA`) and applies the forged `success` status to it, despite the signature only proving knowledge of `orgA`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/hook.rb (L70-82)
```ruby
    EVENTS = %w[
      stack
      review_stack
      task
      deploy
      rollback
      lock
      commit_status
      deployable_status
      merge_status
      merge
      pull_request
    ].freeze
```
