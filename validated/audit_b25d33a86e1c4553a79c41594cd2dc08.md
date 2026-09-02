Confirmed: Shipit supports multi-organization GitHub App configuration, each with its own `webhook_secret`, resolved via `Shipit.github(organization:)` / `github_app_config` [1](#0-0) . This is the multi-tenant boundary that the webhook signature is supposed to enforce per organization.

### Title
Webhook signature is bound to `repository.owner.login`, but stack/repository resolution is bound to the unrelated `repository.full_name` field — cross-organization writes - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`), but every event handler that actually performs writes (`Repository`/`Stack` lookup, `sync_github`, review-stack provisioning/archival) resolves its target using the sibling field `repository.full_name`. These two fields are never checked for consistency, so a payload that authenticates as organization A can direct writes at a stack belonging to an entirely different organization B managed by the same Shipit instance.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and fetches the corresponding `GitHubApp`/secret to validate `X-Hub-Signature`: [2](#0-1) [3](#0-2) 

Once the signature check passes, `Shipit::Webhooks.for_event(event)` dispatches the raw parsed `params` hash to handlers [4](#0-3) . Handlers resolve the target `Repository`/`Stack` from a *different* key in the same `repository` object — `full_name` — completely independent of `owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

`Shipit.github(organization:)` proves multiple organizations, each with an independently configured `webhook_secret`, can be hosted by one Shipit deployment: [1](#0-0) 

This is exactly the "organization that authenticated versus the repository that is written" binding break: the equality that should hold is `organization_authenticated_by_signature == organization_owning_the_written_repository`, but the code only enforces `organization_named_in(repository.owner.login) == organization_whose_secret_signed_the_raw_body`, and separately trusts `repository.full_name` — from the same JSON body but a semantically unrelated field — for the actual database mutation target. Anyone in possession of a valid webhook secret for *any one* organization configured in the instance (e.g., a legitimate Shipit customer/org admin, or anyone who can get GitHub to deliver a signed event for a repo they administer) can hand-craft the JSON payload so `repository.owner.login`/`organization.login` names their own org (passes signature check) while `repository.full_name` names a stack under a completely different, unrelated organization's repository also tracked by the same Shipit install.

### Impact Explanation
With a mismatched but validly-signed payload, an attacker owning only organization A's webhook secret can:
- Trigger `PushHandler#process` → `stack.sync_github(expected_head_sha: ...)` against organization B's stacks [6](#0-5) , forcing sync state changes and, combined with continuous deployment, influencing when/what gets auto-deployed for a repository the attacker has no authorization over.
- Trigger PR handlers to `archive!`/`unarchive!`/deprovision or create Review Stacks for organization B's repositories (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler`) [7](#0-6) [9](#0-8) , causing cross-repository writes and unauthorized state changes (deprovisioning/archiving another org's deployed environment, or spinning up new review-stack infrastructure) without ever having been granted access to that organization or repository.

This satisfies the required Critical/High bar of "cross-repository writes" / "unauthorized deploy" through a credential (webhook secret) that was only ever meant to authorize actions on its own organization's repositories.

### Likelihood Explanation
Exploitation requires possession of one organization's `webhook_secret` configured in the Shipit instance — a credential routinely held by that organization's admins who legitimately set up the GitHub webhook, or obtainable through the normal webhook-configuration workflow of a single tenant in a multi-org Shipit deployment. No access to organization B, its repository, or its GitHub App credentials is needed; only the mismatch between the field used for authentication (`repository.owner.login`) and the field used for authorization/target resolution (`repository.full_name`) needs to be exploited.

### Recommendation
After `verify_signature` succeeds, re-derive the organization from `repository.full_name` (or `repository.owner.login` used for both purposes, keeping them equal) and assert it matches the organization whose secret validated the signature before dispatching to handlers; alternatively, have `Webhooks::Handlers::Handler#repository_name`/`#stacks` cross-check that the resolved `Repository`'s owner matches the authenticated `repository_owner` from `WebhooksController`, rejecting (422) any payload where they diverge.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, `orgA` (secret `S_A`) and `orgB` (secret `S_B`), each with at least one tracked `Stack`/`Repository`.
2. As an attacker who only knows/controls `S_A` (e.g., a GitHub org admin of `orgA` who can register/inspect webhooks there), build a `push` event JSON body where:
   - `repository.owner.login = "orgA"`
   - `repository.full_name = "orgB/victim-repo"`
   - `ref = "refs/heads/<orgB-stack-branch>"`, `after = "<attacker-chosen sha>"`
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, raw_body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches `orgA`'s `GitHubApp`, and validates successfully against `S_A` [2](#0-1) .
5. `PushHandler` resolves `stacks` via `Repository.from_github_repo_name("orgB/victim-repo")` [5](#0-4)  and calls `sync_github` on `orgB`'s stack, despite the request only being authenticated for `orgA`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
