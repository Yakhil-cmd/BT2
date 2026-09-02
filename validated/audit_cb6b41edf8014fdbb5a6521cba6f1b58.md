This confirms the vulnerability. The `MembershipHandler` (app/models/shipit/webhooks/handlers/membership_handler.rb:38-42) uses `params.organization.login` — an attacker-controlled JSON field — as the `Team#organization` when creating a team, and then calls `team.add_member(member)`, which directly feeds `Shipit.github_teams` authorization (lib/shipit.rb:256-258), since `Team.find_or_create_by_handle` is looked up by `organization:`/`slug:` matching the `oauth.teams` handles that gate login access.

### Title
Webhook organization used for signature verification differs from the organization written to `Team`/`Repository` records, enabling cross-organization forgery in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-organization Shipit deployment, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to check the HMAC signature against using a field taken directly from the untrusted JSON body (`repository.owner.login` / `organization.login`), while the handlers that actually mutate state (`MembershipHandler`, `PushHandler`, pull-request handlers) read *different* attacker-controlled fields from the same body (`organization.login`, `repository.full_name`) to decide what `Team`, `Repository`, or `Stack` to act on. Because the signing key is chosen by one field and the mutated entity is chosen by another, independently-controlled field in the same signed payload, the two are never cross-checked against each other.

### Finding Description
`WebhooksController#verify_signature` computes: [1](#0-0) 
picking the app config via `Shipit.github(organization: repository_owner)`, where: [2](#0-1) 
`repository_owner` is read straight from the JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), which is entirely attacker-controlled content of the signed payload, not metadata independent of it.

`Shipit.github` resolves per-organization secrets from `secrets.github`, supporting the documented multi-org configuration: [3](#0-2) [4](#0-3) 

Once the signature check passes (which it will, if the attacker knows *any one* configured org's `webhook_secret`, e.g. their own org's), the handler for the event is invoked with the full raw JSON body, and handlers derive the *target* entity from separate fields of that same body:

- `MembershipHandler` sets `team.organization = params.organization.login` when creating a `Team`, and adds/removes members on it: [5](#0-4) 
- `Team.find_or_create_by_handle`/`Shipit.github_teams` uses that `organization` value to gate authentication into the whole Shipit app: [6](#0-5) [7](#0-6) 
- `Handler#stacks`/`#repository_name` resolves the target `Repository`/`Stack` from `payload.dig('repository','full_name')`: [8](#0-7) 
- `PushHandler` and pull-request handlers (`ClosedHandler#process` → `review_stack.archive!`, `LabeledHandler`/`UnlabeledHandler#process` → `stack.archive!`/`unarchive!`) all key off this same `repository.full_name` field: [9](#0-8) [10](#0-9) [11](#0-10) 

**Equality that should hold but doesn't:** `organization used to select/verify the webhook_secret` == `organization/repository the handler actually mutates`. Nothing in `WebhooksController` or `Handler` enforces that `params.dig('repository','owner','login')` (or `organization.login`) matches `payload.dig('repository','full_name')`'s owner. Both are independent, attacker-supplied strings inside the same HMAC-signed body — signing the body doesn't bind them to each other, it only proves the body came from someone possessing the secret picked by one of those fields.

### Impact Explanation
An administrator/holder of a legitimate `webhook_secret` for **Organization A** (configured in `secrets.github.orgA`) can forge a webhook whose `repository.owner.login`/`organization.login` is `"orgA"` (so `verify_signature` selects and validates against Org A's real secret) but whose `repository.full_name` / `organization` payload fields point at **Organization B**'s repository or team. This is accepted as a fully verified webhook and dispatched to handlers that act on Org B's data:
- `MembershipHandler` can add/remove arbitrary GitHub users to a `Team` object matching Org B's `oauth.teams` handle, directly manipulating `Shipit.github_teams` membership used to gate application login — an authorization-escalation vector into a completely different tenant's app instance.
- `PushHandler`/pull-request handlers can trigger `sync_github`, `archive!`/`unarchive!` on Org B's stacks — cross-organization/cross-repository writes performed without ever having Org B's `webhook_secret`, `ApiClient` token, or repository access.

This satisfies the Critical "cross-repository writes" / High "escalation into `Shipit.github_teams` authorization" categories, since the attacker never needed any credential belonging to the victim organization.

### Likelihood Explanation
Requires only that Shipit be configured with multiple GitHub organizations sharing one instance (an explicitly documented and supported configuration) and that the attacker control one organization's own legitimate GitHub App webhook secret — a capability normal for any org admin who installed the Shipit GitHub App for their own org, but which grants them no expected privilege over other orgs on the same Shipit instance. No repository write access, `ApiClient`, or session is needed against the victim org.

### Recommendation
Bind the two fields together: after selecting the GitHub App via `repository_owner`, verify that this same value equals the owner segment parsed from `repository.full_name` (and from `organization.login` for membership events) before dispatching to handlers, rejecting mismatches with a 422. Alternatively, derive the signing organization solely from a value that handlers subsequently reuse verbatim (not merely a same-named-but-independently-controlled field).

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `test/dummy/config/secrets_double_github_app.yml`).
2. As the legitimate owner/admin of `OrgA`'s GitHub App, obtain `OrgA`'s `webhook_secret`.
3. Craft a `membership` event JSON body:
   ```json
   {
     "action": "added",
     "team": { "id": 999, "name": "developers", "slug": "developers", "url": "https://example.com" },
     "organization": { "login": "OrgB" },
     "member": { "login": "attacker" },
     "repository": { "owner": { "login": "OrgA" } }
   }
   ```
4. Compute `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)` and POST to `/webhooks` with `X-Github-Event: membership`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"` → verifies successfully against `OrgA`'s secret.
6. `MembershipHandler#process` reads `params.organization.login` = `"OrgB"` and creates/updates a `Team` with `organization: "OrgB"`, adding `attacker` as a member — potentially matching one of `OrgB`'s `oauth.teams` handles and granting the attacker login access to a Shipit instance scoped to `OrgB`, despite never possessing any `OrgB` credential.

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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

**File:** app/models/shipit/team.rb (L17-21)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-63)
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
```
