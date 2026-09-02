### Title
Global `github_id` matching in `find_or_create_team!` lets an attacker-controlled org's membership webhook add users to a team belonging to a different organization - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` looks up a `Team` solely by the numeric `github_id`, which is global across all GitHub organizations, and only sets `organization`/`slug`/`name` inside the `find_or_create_by!` block that runs exclusively on record creation. Once a `Team` row for org A already exists, any org B whose webhook signature validates (i.e., any org that has the Shipit GitHub App installed) can send a `membership` webhook naming the same numeric `team.id`, causing `team.add_member` to mutate org A's `Team` row with a user who was never vetted by org A.

### Finding Description
The binding that should hold is: `params.organization.login` (the org whose HMAC secret verified the webhook in `WebhooksController#verify_signature`, using `Shipit.github(organization: repository_owner)`) `==` `team.organization` (the organization field on the `Team` row that `add_member` mutates).

`WebhooksController#verify_signature` only proves that the request was signed by *some* organization's `webhook_secret` (looked up via `repository_owner`, i.e., `params.organization.login` for membership events): [1](#0-0) [2](#0-1) . It does not verify that this organization is the owner of `team.id`.

`MembershipHandler#find_or_create_team!` resolves the team purely by the GitHub-global `github_id`: [3](#0-2) 
The `do |team| ... end` block passed to `find_or_create_by!` in ActiveRecord only executes when a **new** record is being built; if a `Team` with that `github_id` already exists (because it was created earlier from a legitimate webhook from org A, e.g. `shipit_teams(:shopify_developers)`), the block is skipped and the existing row's `organization` column is left untouched. `MembershipHandler#process` then unconditionally calls `team.add_member(User.find_or_create_by_login!(params.member.login))`: [4](#0-3) , and `Team#add_member` simply appends the member: [5](#0-4) .

Exploit flow:
1. Attacker registers/administers `attacker-org`, on which they install the Shipit GitHub App (a normal, self-service, unprivileged action any GitHub org admin can do — it does not require any Shipit secret).
2. Attacker sends a `membership` webhook (`action: 'added'`) to `POST /webhooks`, signed with `attacker-org`'s own `webhook_secret`, containing `organization.login = 'attacker-org'` and `team.id` equal to the already-persisted `github_id` of a `Team` belonging to a different, legitimate org (e.g. `shopify`), and `member.login` set to the attacker's own GitHub login.
3. `verify_signature` succeeds because it only checks that `attacker-org`'s secret matches — it never checks that `team.id` belongs to `attacker-org`.
4. `find_or_create_team!` finds the pre-existing `Team` row (organization = `shopify`) by `github_id` alone, skips the creation block, and returns it unchanged.
5. `team.add_member` inserts a `Membership` row linking the attacker's user to the `shopify` team.

Existing guards do not catch this: `drop_unhandled_event` only checks the event type is handled; `ExplicitParameters` only validates payload shape/types, not ownership of `team.id`; there is no code path anywhere that cross-checks `params.organization.login` against `team.organization` after the team is looked up.

### Impact Explanation
A successful request inserts a `Membership` for an attacker-controlled `User` into a `Team` that determines authorization via `User#authorized?` (`Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?`) and `force_github_authentication`: [6](#0-5) [7](#0-6) . If the targeted `Team` is one of the teams configured in `Shipit.github_teams`, this grants the attacker full authenticated access to the Shipit instance (deploys, rollbacks, stack management) despite never having been added to that team on GitHub by its legitimate owners. This matches the "High - escalation into `Shipit.github_teams` authorization" category, and arguably crosses into unauthorized deploy/rollback capability (Critical) once logged in as an "authorized" user.

### Likelihood Explanation
Preconditions: the attacker must control any GitHub organization on which the target Shipit installation's GitHub App has been installed (self-service, requires no Shipit secret), and must know/guess the numeric `github_id` of the target team — team `github_id`s are visible via GitHub's org/team APIs and UI to anyone with read access to that org's teams, and in many setups team ids are low, sequential, and easily enumerated. No Shipit credentials, session, or API token are required. The attack is a single unauthenticated HTTP POST and is fully repeatable against any team ID the attacker can enumerate.

### Recommendation
Scope the team lookup by both `github_id` and `organization`, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and additionally verify inside `MembershipHandler#process` that an existing team's `organization` matches `params.organization.login` before calling `add_member`/`members.delete`, rejecting (or logging and no-op'ing) the webhook otherwise.

### Proof of Concept
```ruby
test "membership webhook cannot add a member to a team owned by a different organization" do
  team = shipit_teams(:shopify_developers) # organization == 'shopify', github_id == team.github_id
  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  post :create, body: {
    action: 'added',
    organization: { login: 'attacker-org' },
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    member: { login: 'attacker' }
  }.to_json, params: {}, headers: { 'X-Github-Event' => 'membership', 'X-Hub-Signature' => 'sha1=fake' }

  team.reload
  assert_equal 'shopify', team.organization # binding still holds only if this passes
  refute team.members.exists?(login: 'attacker'), "attacker should not have been added to shopify's team"
end
```
This test demonstrates that `team.organization` (`'shopify'`) does not equal `params.organization.login` (`'attacker-org'`) at the point `add_member` is invoked, and that the current code fails the `refute` assertion, confirming the vulnerability.

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
