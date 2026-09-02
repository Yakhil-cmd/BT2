### Title
Webhook signature verification keys on `repository.owner.login`/`organization.login` while every event handler acts on the independent `repository.full_name` field, letting any org with a valid Shipit GitHub App forge events against a victim org's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which HMAC `webhook_secret`) to validate a webhook against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. Once the HMAC check passes for that org, `create` dispatches the *entire, unfiltered* JSON body to the registered handlers. Every handler (`PushHandler`, `PullRequest::*Handler`, etc.) independently derives the target repository from a **different** payload field, `payload.dig('repository', 'full_name')` (see `Handler#repository_name`), via `Repository.from_github_repo_name`. Nothing ties `repository.owner.login` (the field the signature check trusted) to `repository.full_name` (the field the handler acts on) — they are never cross-validated against each other.

### Finding Description
- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb` picks the GitHub App/secret via `repository_owner`: [1](#0-0) [2](#0-1) 
- The signature is verified against that specific org's `webhook_secret`, held in `Shipit::GitHubApp#verify_webhook_signature`: [3](#0-2) 
- Once verified, the raw parsed payload is forwarded unmodified to all handlers for the event: [4](#0-3) 
- Every handler resolves the acted-upon repository from an independent field, `repository.full_name`, not `repository.owner.login`: [5](#0-4) [6](#0-5) 
- `Repository.from_github_repo_name` does a straight DB lookup by `owner/name` parsed out of `full_name`, with no relation back to which GitHub App validated the request: [7](#0-6) 
- Shipit explicitly supports multiple, independently configured GitHub Apps/orgs sharing one installation, each with its own `webhook_secret`: [8](#0-7) [9](#0-8) 

**The broken binding**: the engine authenticates the webhook against "the organization that owns app config X" but then executes handler logic against "whatever repository the payload's `full_name` field names" — these are supposed to be the same repository/org, but the code never enforces that equality. An attacker who legitimately controls their own Shipit-registered GitHub organization/App (a completely unprivileged, self-service action — installing a GitHub App on your own org and adding it to a multi-org `secrets.yml`, which the docs treat as a normal supported configuration) knows their own `webhook_secret`. They can:
1. Compute a valid HMAC signature using their own org's secret.
2. Set `repository.owner.login` (or `organization.login`) to their own org so `verify_signature` picks the org whose secret they know and the check passes.
3. Set `repository.full_name` in the same JSON body to `victim-org/victim-repo` — any repository/stack that exists in this shared Shipit instance, regardless of which GitHub org "owns" that Shipit deployment slot.

Because handlers only look at `full_name` afterward, this crosses the binding "organization that authenticated versus the repository that is written."

### Impact Explanation
This allows cross-repository state changes triggered by a party who has no write access, no `ApiClient` token, and no Shipit session — only knowledge of their own legitimate webhook secret in a multi-org Shipit deployment:
- `push` events invoke `stack.sync_github(expected_head_sha: params.after)` on victim stacks (via `PushHandler#process`), letting the attacker force sync/refresh actions against a stack they don't own. [6](#0-5) 
- `pull_request` events can archive/unarchive review stacks or capture PR labels for arbitrary repositories via `ReviewStackAdapter`, again scoped only by the untrusted `full_name` field: [10](#0-9) 

This meets the "cross-repository writes" bar because handler-driven state transitions (archive/unarchive, forced sync jobs) execute against a repository that was never validated by the signature that authorized the request.

### Likelihood Explanation
Requires the deployment to use the documented multi-organization GitHub App configuration (explicitly supported and documented) and requires the attacker to control at least one of the configured orgs/Apps — a normal, unprivileged, self-service GitHub action, not an insider/admin capability. Single-org Shipit deployments (the common case) are not exploitable this way, since `repository_owner` and the only configured org are effectively the same value — but any deployment following the documented multi-org setup is affected.

### Recommendation
After signature verification, re-validate that the org used to select the webhook secret (`repository_owner`) matches the owner encoded in every payload field the handlers subsequently trust (e.g., `repository.full_name`, `organization.login`). Reject the request (422) on mismatch before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two GitHub Apps (`attacker-org`, `victim-org`) per the documented multi-org `secrets.yml` schema.
2. As the attacker, who legitimately owns `attacker-org`'s webhook secret, craft a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Compute `X-Hub-Signature` using `attacker-org`'s known `webhook_secret`.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `repository_owner` to `attacker-org`, verifies successfully against the attacker's own secret.
5. `PushHandler#process` uses `payload.dig('repository','full_name')` = `victim-org/victim-repo`, looks up the real `Repository`/`Stack`, and calls `stack.sync_github`, acting on a repository the attacker never authenticated for.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
