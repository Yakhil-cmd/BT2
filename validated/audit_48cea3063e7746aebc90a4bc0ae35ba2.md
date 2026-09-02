### Title
Multi-organization webhook signature verification does not bind the authenticated organization to the repository/team actually written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit.github(organization:)` supports a multi-tenant config where each GitHub organization has its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's secret to use for HMAC verification purely from attacker-controlled payload fields (`repository.owner.login`, falling back to `organization.login`), then hands the *entire* raw payload to the event handler without re-checking that the field(s) the handler actually acts on (`repository.full_name` for stack lookup, or `organization.login` for team creation) match the organization whose secret verified the request.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and asks `Shipit.github(organization: repository_owner)` for that organization's `GitHubApp`, then verifies the signature with that org's `webhook_secret`: [2](#0-1) [3](#0-2) 

Once verification succeeds, the raw payload is dispatched unmodified to all registered handlers for the event: [4](#0-3) 

Handlers resolve the target `Stack`/`Repository` from a *different* field of the same payload, `repository.full_name`, with no cross-check against `repository.owner.login` (the field that was actually used to select the verifying secret): [5](#0-4) 

Similarly, `MembershipHandler` trusts `organization.login` from the payload to create/attribute a `Team` and add members to it — again a field that is only used for *secret selection*, not verified to be the actual owner of the signed content: [6](#0-5) 

Because HMAC verification only proves "whoever holds Organization X's `webhook_secret` produced this payload," and the code picks X from `repository.owner.login`/`organization.login`, an attacker who legitimately controls a GitHub App/organization configured in Shipit (and therefore knows that organization's `webhook_secret`, e.g. by configuring a webhook on their own org's repo) can forge a payload where:
- `repository.owner.login` = `"OrgA"` (their own org, used to pick and pass the HMAC check with `OrgA`'s `webhook_secret`), while
- `repository.full_name` = `"OrgB/some-other-shipit-repo"`, or `organization.login` = `"OrgB"` for the `membership` event,

This breaks the intended equality **`verified_organization == organization_whose_resources_are_mutated`**: before the attack, only a party who could produce a signature verified against `OrgB`'s secret could act on `OrgB`'s stacks/teams; after the attack, anyone who knows `OrgA`'s secret (a different, disjoint credential) can drive writes against `OrgB`'s `Stack`, `Repository`, or `Team` records, as long as Shipit is configured with a multi-organization `github` section (`secrets.github` keyed by org, per `github_app_config`) [7](#0-6) .

For the `membership` webhook specifically, this lets the attacker fabricate `params.team.id`/`organization.login` pairs to make `find_or_create_team!` attach an arbitrary GitHub team id to an arbitrary `organization` string and add an arbitrary `member.login` to it via `team.add_member(member)` [8](#0-7) . Since `Shipit.github_teams` (the set of teams gating access to the whole application via `User#authorized?`) is built from configured team handles resolved to `Team` records [9](#0-8) , and `User#authorized?` checks membership against `Shipit.github_teams.map(&:id)` [10](#0-9) , an attacker who can forge a `membership` webhook that is accepted because it was signed with a *different, weaker* organization's secret can insert a chosen GitHub user login as a member of a `Team` record that happens to collide with (or later becomes) a gating team — escalating into the `Shipit.github_teams` authorization boundary.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository/team that is written" trust boundary explicitly called out in scope: knowledge of one tenant organization's `webhook_secret` is leveraged to mutate another tenant's `Stack`/`Repository` data (cross-tenant writes) or, via `MembershipHandler`, to add arbitrary GitHub logins into `Team` records that gate authorization through `Shipit.github_teams`/`User#authorized?`. The membership path maps to the in-scope "High" impact of escalation into `Shipit.github_teams` authorization.

### Likelihood Explanation
Exploitation requires the instance to be configured with the multi-organization `github` schema (multiple orgs, each with a `webhook_secret`, as exercised by `secrets_double_github_app.yml` test fixture referenced in `Shipit.github(organization:)` tests) [1](#0-0)  and requires the attacker to legitimately control one such organization/repository's webhook configuration (a normal, expected way to obtain a `webhook_secret` without any Shipit credential). No Shipit session, `ApiClient`, or GitHub App private key is required — only a webhook secret for one of the configured orgs, which is a much weaker credential than access to the target org.

### Recommendation
After signature verification, re-derive the organization that must own every payload field the handler consumes, and reject the request if `repository.owner.login`/`organization.login` used to pick the verifying secret does not match the owner embedded in `repository.full_name` (or the `organization.login` used by `MembershipHandler`). Alternatively, verify the signature against the webhook secret tied to the specific `GithubHook`/`Repository` record matching `repository.full_name`, rather than a top-level organization guess, so a single verified secret cannot be replayed to affect a different organization's resources.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `OrgA` and `OrgB`, each with a distinct `webhook_secret` (multi-org schema per `lib/shipit.rb#github_app_config`).
2. As a legitimate admin of `OrgA`, obtain `OrgA`'s `webhook_secret` (e.g., set it while configuring a webhook on an `OrgA` repository you control).
3. Craft a `push` (or `membership`) webhook payload where `repository.owner.login` = `"OrgA"` but `repository.full_name` = `"OrgB/target-repo"` (a repository tracked by Shipit under `OrgB`).
4. Sign the raw payload body with `OrgA`'s `webhook_secret` using HMAC-SHA1 and send it to `/github/webhooks` with `X-Hub-Signature` set accordingly and `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `OrgA`'s `GitHubApp`, and the signature verifies successfully.
6. `PushHandler#stacks` looks up `Repository.from_github_repo_name("OrgB/target-repo")` and triggers `stack.sync_github` for a stack the attacker does not control, despite never possessing `OrgB`'s webhook secret.

### Citations

**File:** lib/shipit.rb (L170-181)
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
```

**File:** lib/shipit.rb (L196-200)
```ruby
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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L15-43)
```ruby
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
