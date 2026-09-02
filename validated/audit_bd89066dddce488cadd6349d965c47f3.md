Confirmed core finding: `WebhooksController#verify_signature` selects the GitHub App (and thus which `webhook_secret` HMAC to validate against) using `repository_owner`, which is read directly from the unverified payload — `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. Every event handler, however, resolves the target `Stack`/`Repository` using a *different* field from the same payload: `payload.dig('repository', 'full_name')` in `Handler#repository_name` (used by `PushHandler`, etc.) or `params.repository.full_name` in the `PullRequest` handlers/`ReviewStackAdapter`. Since the HMAC only proves "this payload was signed with organization X's webhook secret," not "the `repository.full_name` inside belongs to organization X," an attacker who legitimately controls a repository/webhook secret for one organization/app installation can forge a payload whose `repository.owner.login` matches their own org (so it passes `verify_signature` with their own valid secret) while `repository.full_name` names a different, unrelated tracked repository, causing the handler to act on that other repository (e.g., trigger `stack.sync_github`, create `ReviewStack`s, close/merge PRs, etc.) — a cross-repository/cross-organization write despite passing signature verification for a different repo's key. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

This matches one of the allowed binding classes in scope ("an organization that authenticated versus the repository that is written"), and only requires the attacker to control any single GitHub App installation/webhook secret already registered with the Shipit instance (multi-org deployments are explicitly documented and supported), not a privileged Shipit account or `webhook_secret` leak beyond their own org's.

### Title
Webhook signature is verified against `repository.owner.login` while handlers act on the unrelated `repository.full_name` field, allowing cross-repository writes - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` picks which GitHub App/`webhook_secret` to use for HMAC validation based on `repository.owner.login` (or `organization.login`) taken straight from the untrusted JSON body. Once the signature check passes, `WebhooksController#create` dispatches the full, attacker-controlled payload to event handlers, which identify the target `Stack`/`Repository` using the independent `repository.full_name` field. The HMAC binds "this JSON blob came from someone holding org A's webhook secret" — it does not bind "the repository referenced by `full_name` inside the JSON belongs to org A." An operator of one org's GitHub App installation (i.e., anyone who can trigger/craft that org's webhooks) can therefore produce a validly-signed payload whose `owner.login` is their own org, but whose `repository.full_name` names a repository tracked under a different organization's stack.

### Finding Description
`Shipit.github(organization: repository_owner)` resolves the `GitHubApp` (and its `webhook_secret`) using `repository_owner`, defined as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [6](#0-5) [7](#0-6) 

`verify_webhook_signature` only checks that the raw body's HMAC matches the secret configured for that organization: it never inspects or constrains which repository the payload describes. [4](#0-3) 

After verification succeeds, `create` parses the same raw body and fans it out to handlers without re-checking that `repository.full_name` belongs to `repository_owner`: [8](#0-7) 

Handlers then resolve their target purely from `repository.full_name`: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` to scope `stacks`, used by e.g. `PushHandler#process`, which triggers `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack/branch. [2](#0-1) [9](#0-8) 

The `PullRequest` handlers follow the identical pattern — `OpenedHandler#repository` looks up `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and, via `ReviewStackAdapter`, creates/archives/unarchives `ReviewStack`s and merges pull request state based solely on this field. [10](#0-9) [11](#0-10) 

Shipit's own documentation confirms multi-organization installs are a supported, first-class configuration, each with its own `webhook_secret`, so this is not a "misconfiguration" edge case: [12](#0-11)  and `Shipit.github_app_config`/`Shipit.github` resolve independent secrets per org key. [5](#0-4) 

Equality that should hold but doesn't: `organization_that_authenticated(payload) == owner_of(repository_the_handler_writes_to(payload))`. In reality, the controller enforces only `verify_webhook_signature(secret_for(repository.owner.login), raw_post) == true`, while the handler acts on `repository.full_name`, an unrelated, unverified-against-owner field within the same signed blob.

### Impact Explanation
An attacker who controls (or can trigger) webhook delivery for one organization's GitHub App installation registered on this Shipit instance can forge push/pull_request/status/check_suite events that are validly signed for their own org, but whose `repository.full_name` designates a repository/stack belonging to a different tracked organization. This can drive `GithubSyncJob`/`sync_github` calls, create or archive `ReviewStack`s, and manipulate `PullRequest` records for repositories the attacker does not control — a cross-repository/cross-organization write, matching the Critical impact bucket ("cross-repository writes").

### Likelihood Explanation
Requires only that the Shipit instance is configured with more than one GitHub organization/app (a documented, supported setup) and that the attacker controls delivery of at least one organization's legitimate webhooks (e.g., they administer that GitHub App/repo, or can otherwise produce a signable payload for it). No Shipit session, `ApiClient` token, or the victim organization's `webhook_secret` is needed.

### Recommendation
After `verify_signature` resolves `repository_owner`, additionally verify that every repository referenced inside the payload (`repository.full_name`, `repository.owner.login`) is actually owned by / consistent with `repository_owner`/the authenticating organization before dispatching to handlers, e.g. compare `repository.owner.login == repository_owner` and reject mismatches, or resolve the target `Repository`/`Stack` and confirm it is registered under the same organization that produced a valid signature.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` and `orgB`, each with a distinct `webhook_secret` (per `docs/setup.md`'s multi-org example).
2. As the holder of `orgA`'s webhook secret, craft a `push` payload: `{"repository": {"owner": {"login": "orgA"}, "full_name": "orgB/victim-repo"}, "ref": "refs/heads/main", "after": "<attacker-controlled sha>"}`.
3. Sign the raw body with `orgA`'s `webhook_secret` (`X-Hub-Signature: sha1=...`) and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "orgA")` and successfully validates the signature. `create` then dispatches to `PushHandler`, whose `stacks` lookup uses `repository.full_name` = `"orgB/victim-repo"`, causing `sync_github` to run against `orgB`'s stack — despite the request only being authenticated as `orgA`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-85)
```ruby
          def repo_name
            params.repository["full_name"]
          end

          def pr_number
            params.number
          end

          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
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
