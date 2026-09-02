### Title
Cross-organization `Team` write via global `github_id` lookup in `find_or_create_team!` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` resolves the target `Shipit::Team` solely by GitHub's globally-unique `github_id`, without verifying that the record's `organization` matches the organization whose webhook secret authenticated the current request. On a multi-organization Shipit deployment (a configuration this engine explicitly documents and supports), a webhook that is validly signed by Organization A's secret can mutate a `Team` row that actually belongs to Organization B, including adding an arbitrary member to a team that gates `Shipit.github_teams` authorization.

### Finding Description
The broken binding, stated as an equality that should hold but does not:
`Team#organization` (the org that owns/created the team row) **must equal** the `organization.login` that was cryptographically verified for the current webhook (i.e., `repository_owner` used in `verify_signature`).

Trace:
1. `WebhooksController#verify_signature` picks the GitHub App/secret to check with `Shipit.github(organization: repository_owner)`, where for `membership` events `repository_owner` is `params.dig('organization', 'login')` [1](#0-0) . This only proves the payload was signed by *some* organization's registered secret (the one named in the payload itself) — it does not bind the `team.id` inside the same payload to that organization.
2. `MembershipHandler#find_or_create_team!` looks the team up **exclusively** by `github_id`:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [2](#0-1) 
The block that sets `team.organization` only runs on **creation**. If a `Team` row with that `github_id` already exists (created earlier from Organization B's own legitimate membership webhook), the block is skipped and the found row's `organization` is never checked against the payload's `organization.login`.
3. `process` then calls `team.add_member(member)` for `action: 'added'`, mutating that pre-existing (Organization B) `Team` row using a request only proven to originate from Organization A [3](#0-2) .
4. `Team#add_member` appends the member with no organization check either [4](#0-3) .
5. `User#authorized?` grants app access when the user belongs to any team in `Shipit.github_teams` [5](#0-4) , and `force_github_authentication` uses that same check to gate all Shipit UI/API access [6](#0-5) .

GitHub team IDs (`params.team.id`) are global integers assigned by GitHub across all organizations, and are discoverable from public org/team pages or the GitHub API for any team the attacker can view. No existing guard (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) checks that the resolved `Team#organization` matches the verified `organization.login` for existing records — the schema only validates payload *shape*, not cross-record consistency.

Exploit flow: An attacker who owns/administers their own GitHub organization (Org A) that is legitimately registered on the same multi-tenant Shipit instance (a configuration explicitly documented in `docs/setup.md` "Using Multiple Github Applications") sends a `membership` webhook, signed with Org A's own valid `webhook_secret`, but sets:
- `organization.login = "org-a"` (so `verify_signature` passes using Org A's secret)
- `team.id = <victim's Shipit.github_teams-authorizing team's public GitHub team id>` (belonging to Org B)
- `member.login = <attacker's own GitHub login>`
- `action = "added"`

Because the `Team` row for that `github_id` already exists (created previously from Org B's legitimate onboarding), `find_or_create_by!` finds it and `add_member` inserts the attacker's user into Org B's privileged team, with the request having only been authenticated as belonging to Org A.

### Impact Explanation
The attacker gains membership in a `Shipit::Team` used by `Shipit.github_teams` to gate authorization (`User#authorized?`), thereby escalating an account they control into a privileged team without ever being invited to it on GitHub. This is a direct escalation into `Shipit.github_teams` authorization (High severity category), granting the attacker full authenticated access to the Shipit UI/API for stacks gated by that team-based authorization — repeatable for any known team `github_id` as long as the corresponding `Team` row pre-exists in Shipit's database. Blast radius spans across tenant organizations sharing one multi-org Shipit deployment.

### Likelihood Explanation
Requires: (a) the Shipit instance configured for multiple GitHub organizations (documented, supported configuration), (b) attacker controls/administers their own onboarded organization with a legitimate `membership` webhook and secret, (c) the victim's target team already exists as a `Team` row in Shipit (naturally true once that org has done any prior membership sync), and (d) the attacker knows the target's numeric GitHub team `github_id` (obtainable from public team/org pages or API for visible teams). All of these are plausible operational conditions for a genuine multi-tenant deployment and require no Shipit or victim-org secrets — only the attacker's own valid webhook secret for their own org.

### Recommendation
Scope the team lookup by both `github_id` and the verified `organization.login`, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and reject/raise if an existing `Team` with that `github_id` has a different `organization` than the one that signed the current webhook, rather than silently reusing the row.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb
test "membership webhook cannot mutate a team belonging to a different organization" do
  # Team already exists, created earlier by org "victim-org"
  victim_team = Team.create!(github_id: 999, organization: 'victim-org', name: 'Admins', slug: 'admins', api_url: 'https://x')

  # Attacker's own org "attacker-org" has a valid registered webhook secret (fixture github_hooks: attacker_org_membership)
  payload = {
    action: 'added',
    team: { id: 999, name: 'Admins', slug: 'admins', url: 'https://x' }, # victim's github_id, publicly known
    organization: { login: 'attacker-org' },   # attacker's own org, verified by attacker's own secret
    member: { login: 'attacker-gh-login' }
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', 'attacker-org-secret', payload)}"

  post :create, body: payload, as: :json,
       headers: { 'X-Github-Event' => 'membership', 'X-Hub-Signature' => signature }

  assert_response :ok
  victim_team.reload
  # Broken binding: attacker's user landed on victim-org's team despite the request
  # only being verified as belonging to attacker-org.
  assert_equal 'victim-org', victim_team.organization
  refute victim_team.members.where(login: 'attacker-gh-login').empty?
end
```

### Citations

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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
