### Title
Webhook signature verification uses attacker-controlled `repository.owner.login` to select the GitHub App/secret, while handlers act on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to validate an incoming webhook against using `repository_owner`, a value taken directly from the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `organization.login`). All downstream event handlers, however, resolve the target `Repository`/`Stack` using a *different* payload field, `repository.full_name`. These two fields are never checked for consistency, so the "organization that authenticated" and "the repository that is written" are not bound to the same value.

### Finding Description
`verify_signature` computes the verification organization purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a `GitHubApp` instance per-organization only when Shipit is configured for multiple GitHub Apps (see the documented "Using Multiple Github Applications" feature): [3](#0-2) 

`GitHubApp#verify_webhook_signature` treats a missing/blank `webhook_secret` as automatic success, i.e. it returns `true` unconditionally when no secret is configured for that organization: [4](#0-3) 

The `webhook_secret` is explicitly documented as optional per organization: [5](#0-4) [6](#0-5) 

Once the request passes `verify_signature`, `WebhooksController#create` dispatches the raw JSON body to the registered handlers without any re-validation: [7](#0-6) 

Every handler resolves the repository/stack to act on using a **different** field of the same payload, `repository.full_name`, completely independent from the `repository.owner.login`/`organization.login` value that was used to pick the verification secret: [8](#0-7) [9](#0-8) [10](#0-9) 

Equality that should hold but does not: `organization_used_for_signature_verification == owner(repository_acted_on)`. Before the check, the attacker fully controls both `repository.owner.login` (verification key selection) and `repository.full_name` (actual target); after the check, only the former was validated (and even then, only if that organization has a secret configured), while the latter drives all subsequent side effects.

### Impact Explanation
In a multi-GitHub-App Shipit installation (a documented, supported configuration), if **any** configured organization has no `webhook_secret` set (the docs explicitly call this field "optional"), an unauthenticated attacker can:
1. Send a POST to `/webhooks` with `repository.owner.login` set to that secret-less organization (or omit a `repository` key and just set `organization.login`) so that `verify_webhook_signature` short-circuits to `true` regardless of the (missing/garbage) `X-Hub-Signature` header.
2. Set `repository.full_name` to any other tracked repository (belonging to a *different*, properly secured organization) and craft the rest of the event body (e.g. `push` event's `ref`/`after`).
3. `Shipit::Webhooks::Handlers::PushHandler` resolves the real `Repository`/`Stack` via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and calls `stack.sync_github(expected_head_sha:)`, which schedules `GithubSyncJob` to fetch commits and, when continuous deployment is enabled for that stack, ultimately trigger `ContinuousDeliveryJob#perform` → `stack.trigger_continuous_delivery`.

This lets an unprivileged, unauthenticated attacker who never held any secret cause an unauthorized deploy/sync for a stack belonging to a completely different, secured GitHub organization, purely by exploiting the mismatch between the field used for authentication and the field used to select the write target. This satisfies the Critical impact criterion "an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Exploitability depends on the deployment having at least two configured GitHub Apps (multi-org mode) where at least one organization is left without a `webhook_secret` — an explicitly documented, foreseeable, and "optional" configuration choice, not a misuse of the engine. No credentials, sessions, or secrets are required by the attacker. Likelihood is therefore moderate-to-high specifically for multi-org installs that rely on this optional field for some org while trusting the shared `/webhooks` endpoint for all orgs.

### Recommendation
Require the `repository`/`organization` field used to select the verification secret to be re-validated against (or bound to) the field actually used by handlers to resolve the target stack (`repository.full_name`), and refuse to treat "no secret configured" as an automatic pass for organizations that host live stacks — e.g., require a `webhook_secret` to be configured for every organization with active stacks, or verify that the resolved `Repository#owner` matches the organization that was used to authorize the webhook before invoking any handler.

### Proof of Concept
Given a Shipit instance configured with two GitHub organizations, `SecretlessOrg` (no `webhook_secret`) and `SecureOrg` (with `webhook_secret` set, hosting a tracked stack for `SecureOrg/target-repo` with continuous deployment enabled):

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=deadbeef   (arbitrary/garbage)
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha-that-exists-on-github>",
  "repository": {
    "owner": { "login": "SecretlessOrg" },
    "full_name": "SecureOrg/target-repo"
  }
}
```

`repository_owner` resolves to `SecretlessOrg`, whose `GitHubApp#webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the bogus signature. `PushHandler` then resolves `Repository.from_github_repo_name("SecureOrg/target-repo")` and, if that branch matches, calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, enqueuing `GithubSyncJob` for `SecureOrg`'s real stack — an unauthorized trigger of that stack's deploy pipeline.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
