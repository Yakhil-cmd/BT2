### Title
Webhook signature is validated against the payload's `repository.owner.login` while every handler acts on the payload's `repository.full_name` — cross-tenant confused-deputy allowing forged deploy-affecting webhooks for repos the attacker does not own - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate a request against based on `params.dig('repository','owner','login')` (or `organization.login`), but every downstream handler resolves the actual repository/stack to act on via `payload.dig('repository','full_name')`. These are two independent, attacker-controlled fields inside the very body whose signature is being checked. Nothing enforces that the owner used to pick the signing secret matches the owner encoded in `full_name`. In Shipit's documented multi-organization mode (`docs/setup.md`, "Using Multiple Github Applications"), each organization has its own `webhook_secret`. An attacker who legitimately knows (or controls) the `webhook_secret` for *one* configured organization can craft an arbitrary JSON body, set `repository.owner.login` to their own org (so `verify_webhook_signature` picks and matches their own secret) while setting `repository.full_name` to a different organization/repo's stack, and sign the whole body with their own key. The signature check passes, and the handler pipeline then mutates state belonging to a repository/org the attacker never proved control over.

### Finding Description
- Signature verification: `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 
picks the app via `repository_owner`: [2](#0-1) 
This value comes straight out of the JSON body (`params.dig('repository','owner','login')`), and `Shipit.github(organization: repository_owner)` returns the `GitHubApp` instance holding that specific organization's `webhook_secret`: [3](#0-2) 
The HMAC comparison itself is otherwise correctly implemented (`SecureCompare.secure_compare`) over `request.raw_post`: [4](#0-3) 

- Handler dispatch/resolution: `Handler#stacks`/`#repository_name` (and every concrete handler) resolve the target repository from a *different* field of the same body, `repository.full_name`: [5](#0-4) 
For example `PushHandler#process` immediately calls `stack.sync_github` on stacks found via that repository: [6](#0-5) 
`PullRequest::OpenedHandler` provisions/creates review stacks (real deploy pipelines) keyed off the same `full_name`: [7](#0-6) 
`ClosedHandler`/`LabeledHandler` archive/unarchive review stacks the same way: [8](#0-7) [9](#0-8) 
`StatusHandler` writes GitHub commit statuses onto arbitrary `Commit` rows matched purely by `sha` (no repository binding is even checked here beyond the sha lookup), which is used by Shipit's deploy pipeline to gate whether a commit is deployable: [10](#0-9) 
`MembershipHandler` creates `Team`/`User` records tied to whatever `organization.login`/`team` values are in the body: [11](#0-10) 

The binding that should hold as an equality and does not:
`organization_that_authenticated (repository.owner.login used to pick webhook_secret)` **==** `organization/repository_that_is_written (repository.full_name used by every handler)`.

Because the attacker fully controls the raw JSON body they submit (this is a direct HTTP POST to `/webhooks`, not something GitHub itself relays), and HMAC-SHA1 signs whatever bytes are sent, an attacker who knows *any one* configured organization's `webhook_secret` can produce a validly-signed body whose `repository.owner.login` matches that known secret while `repository.full_name` names an entirely different tenant's repository/stack.

### Impact Explanation
This breaks the intended trust boundary between tenants (organizations) that Shipit's own documentation describes as isolated ("A Github application can only authenticate to the Github organization it's installed in..."). A holder of one organization's webhook secret can:
- Trigger `GithubSyncJob`/`sync_github` and drive commit ingestion for another organization's stack (`PushHandler`).
- Provision, archive, or unarchive another organization's review-stack deploy pipelines (`PullRequest` handlers), which can enqueue real deploy/deprovision actions.
- Inject fabricated commit statuses (`StatusHandler`) on arbitrary commits looked up only by `sha` — commit statuses are a standard Shipit deploy-gating mechanism, so this can be used to force a commit into (or keep it out of) a deployable state, enabling an unauthorized deploy on a stack the attacker does not own.
- Create/modify `Team`/`Membership` records for arbitrary organizations (`MembershipHandler`), affecting `Shipit.github_teams` authorization state used elsewhere in the app.

This matches the Critical/High impact classes: cross-repository writes and unauthorized deploy/rollback triggering, achieved purely by crossing an authentication boundary meant to isolate one organization's webhook credential from another organization's data.

### Likelihood Explanation
This requires the deployment to use Shipit's supported multi-organization configuration (multiple orgs, each with its own `webhook_secret`), and requires the attacker to possess one organization's legitimate webhook secret (e.g., they are a GitHub App admin for that org, or the secret otherwise leaked/was rotated by them) while targeting a different organization hosted on the same Shipit instance. In a single-org deployment (the common/default config) this specific cross-tenant angle does not apply, since there is only one secret. Given multi-tenant Shipit deployments are an explicitly documented, supported configuration, and the exploit requires no additional secret material beyond what one legitimate but lower-privileged tenant already has, likelihood is moderate-to-high in any environment that actually hosts multiple organizations.

### Recommendation
Bind the identity used for signature verification to the identity that handlers act on:
- Derive `repository_owner` (used to select the verifying `webhook_secret`) and the repository ultimately processed by handlers from the same authoritative source, and explicitly assert they match before dispatch — e.g., re-derive the owner from `repository.full_name` and compare it against `repository.owner.login`/`organization.login`, rejecting mismatches with 422.
- Alternatively/additionally, after selecting the `GithubApp` by `repository_owner`, verify inside `WebhooksController#create` (before invoking handlers) that every repository referenced in the payload (`repository.full_name`) actually belongs to that same authenticated organization (e.g., checked against `Shipit::Repository`/`Shipit::Stack` ownership), rejecting cross-organization payloads.
- Consider also validating that the `X-Github-Event`-declared org key used for GitHub App selection is the sole basis for authorization, and that this same key is echoed and validated inside each handler rather than trusting `full_name` in isolation.

### Proof of Concept
Preconditions: Shipit configured for two organizations, `OrgA` and `OrgB`, each with distinct `webhook_secret`s (per `docs/setup.md`'s multi-org example and `test/dummy/config/secrets_double_github_app.yml`). Attacker is a legitimate admin/knows `OrgA`'s `webhook_secret`, but has no access to `OrgB`'s private stack `OrgB/victim-repo`.

1. Craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
2. Compute `sha1=HMAC_SHA1(OrgA_webhook_secret, body)` and set it as `X-Hub-Signature`; set `X-Github-Event: push`.
3. POST to `/webhooks`.
4. `WebhooksController#repository_owner` returns `"OrgA"` → `Shipit.github(organization: "OrgA")` is used → `verify_webhook_signature` succeeds because the attacker signed with `OrgA`'s real secret.
5. `Shipit::Webhooks::Handlers::PushHandler` resolves `repository_name` as `"OrgB/victim-repo"` (via `Handler#repository_name`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `OrgB`'s stack — a stack the attacker never authenticated for.

(Note: I was not able to fully trace `Stack#sync_github`/`GithubSyncJob` and `Commit#create_status_from_github!` implementation details to their end effect within the available iterations; the analysis above is based on confirmed reads of the handler entry points, `Handler#stacks`/`#repository_name`, and the webhook signature-selection code, which is sufficient to establish the authentication/authorization boundary break.)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-68)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
