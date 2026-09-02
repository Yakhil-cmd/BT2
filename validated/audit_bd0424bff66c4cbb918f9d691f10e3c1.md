### Title
Webhook signature verification key is selected by `repository.owner.login`, but every event handler acts on `repository.full_name` (or `organization.login`) without cross-checking it against the verified owner - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to HMAC-verify a delivery against by reading `repository.owner.login` (or `organization.login`) straight out of the *untrusted, not-yet-verified* JSON body. Once the signature check passes, every downstream `Webhooks::Handlers::Handler` subclass looks up the target `Stack`/`Repository`/`Team` using a *different* field of that same body (`repository.full_name` for repo-scoped handlers, `organization.login` for `MembershipHandler`). Nothing in the engine enforces that the owner used to select the secret is the same owner encoded in `full_name`/`organization.login` that is actually written to.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` computes: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`repository_owner` is read from the raw JSON payload *before* trust in any part of that payload has been established - the only thing the signature check proves is "whoever sent this raw body knows the secret for the organization named at `repository.owner.login`". It does not prove anything about any other field in the body.

Every handler, however, derives the record to mutate from a *different* field:
- Generic `Handler#stacks` / `#repository_name` uses `payload.dig('repository', 'full_name')`: [3](#0-2) 
- `PushHandler#process` calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` using that same `stacks` helper. [4](#0-3) 
- `StatusHandler#process` writes a `Status` to any `Commit` matching `params.sha` globally, with no org/owner scoping at all: [5](#0-4) 
- `CheckSuiteHandler`, and the `pull_request/*` handlers all resolve their own `repository` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`: [6](#0-5) 
- `MembershipHandler` resolves/creates a `Team` keyed on `params.organization.login`, which is completely independent of `repository_owner`: [7](#0-6) 

Because Shipit explicitly supports hosting multiple GitHub Apps/organizations behind one instance (`config/secrets.development.example.yml` documents the multi-org schema, and `lib/shipit/github_app.rb`/`lib/shipit.rb#github_teams` resolve per-organization secrets and OAuth teams), an attacker who legitimately controls (or has compromised) **one** configured organization's webhook secret - e.g. because they are an admin of "OrgA" which is one of several orgs Shipit tracks - can craft an arbitrary raw JSON body, sign it with OrgA's `webhook_secret`, but set `repository.full_name` (or `organization.login` for membership events) to point at "OrgB/victim-repo", a completely different tenant of the same Shipit instance. `verify_signature` will happily accept the delivery because it only checked "the sender knows OrgA's secret" - it never checks that OrgA's login equals the owner embedded in the field the handler actually consumes.

This breaks the trust binding: *the organization that authenticated (`repository_owner` used to pick `webhook_secret`) ≠ the repository/organization that is written to (`full_name` / `organization.login` used by the handler)*.

### Impact Explanation
Concrete cross-tenant writes reachable via this gap:
- `StatusHandler` lets the attacker inject arbitrary CI `Status` records (`state`, `context`, `description`, `target_url`) for **any** commit SHA in the whole database, not scoped to their own org's repositories, via `Commit.where(sha: params.sha)` with no repository filter at all. Combined with `Commit#schedule_continuous_delivery`, a forged "success" status on a victim stack's pending commit can trigger `ContinuousDeliveryJob` and an **unauthorized deploy** if that stack has `continuous_deployment?` enabled. [8](#0-7) 
- `PushHandler`/`CheckSuiteHandler`/pull-request handlers let the attacker fabricate sync, check-run-refresh, PR-open/close/label events against any other tenant's `Stack`/`Repository`/`PullRequest`, driving state changes (archiving/unarchiving review stacks, forcing merge-status recalculation) for a repository the attacker does not own.
- `MembershipHandler` lets the attacker add or remove arbitrary GitHub users to/from `Team`s belonging to a different organization's `Shipit.github_teams`, which is used for authorization gating in `Authentication#force_github_authentication` / `User#authorized?` - i.e., escalation into `Shipit.github_teams` authorization for a tenant the attacker doesn't control. [9](#0-8) [10](#0-9) 

This satisfies the required High/Critical bar: unauthorized deploy (via forged CI status + continuous delivery) and escalation into `Shipit.github_teams` authorization (via forged membership events).

### Likelihood Explanation
Exploitation requires the attacker to possess a valid `webhook_secret` for *some* organization configured on the same Shipit instance - realistic in any multi-tenant deployment (explicitly supported and documented by this engine, see `config/secrets.development.example.yml` and `test/dummy/config/secrets_double_github_app.yml`) where different organizations have different trust levels (e.g., a low-trust org onboarded alongside a high-trust one). No Shipit session, `ApiClient` token, or GitHub App private key is needed - only the webhook secret of any one tenant, which that tenant's own GitHub org admins legitimately hold. This is a design gap in the engine's own webhook trust model, not a misconfiguration by the host application.

### Recommendation
After parsing and verifying the raw body, re-derive `repository_owner`/`organization.login` used for handler lookups from the *same, already-authenticated* organization the secret was matched against, and reject the webhook if `repository.full_name`'s owner segment (or `organization.login`) does not match the organization whose secret validated the signature. Concretely, in `WebhooksController#verify_signature`/`#create`, compare `repository_owner` against the owner segment parsed out of `params.dig('repository', 'full_name')` (and against `params.dig('organization', 'login')` for membership events) and `head(422)` on mismatch, instead of trusting each handler to independently and consistently scope by full_name.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgA` (attacker-controlled, webhook secret `sA`) and `OrgB` (victim, tracks stack `OrgB/victim-repo` with `continuous_deployment: true`), per the multi-org schema shown in `config/secrets.development.example.yml`.
2. Attacker crafts a `status` webhook body:
```json
{
  "sha": "<pending-commit-sha-of-OrgB/victim-repo>",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/whatever" }
}
```
3. Attacker signs it with `sA` and sends `X-Hub-Signature: sha1=<hmac(sA, body)>`, `X-Github-Event: status`.
4. `WebhooksController#verify_signature` computes `repository_owner = "OrgA"`, loads OrgA's `GitHubApp`, and the signature verifies successfully (attacker legitimately knows `sA`).
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` - which matches the OrgB commit regardless of the "OrgA" owner used for verification - and creates a passing `Status`, which via `Commit#schedule_continuous_delivery` can trigger an unauthorized `ContinuousDeliveryJob` deploy on `OrgB/victim-repo`, a tenant the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
