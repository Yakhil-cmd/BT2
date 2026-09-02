### Title
Membership webhook `team.id` collision lets an attacker with a valid webhook signature for their own org inject themselves into another org's `Team` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` resolves the target `Team` solely by the attacker-controlled `params.team.id`, and only sets/validates `organization` when the row doesn't already exist. `WebhooksController#verify_signature` only proves the request body was HMAC-signed by *some* configured org's `webhook_secret`, it never checks that the `team.id` embedded in that body actually belongs to that verified org. The two checks are disjoint, so a legitimate tenant (an attacker who owns/administers one Shipit-configured GitHub organization and therefore genuinely knows its `webhook_secret`) can forge a `membership` payload naming their own org while pointing `team.id` at a `Team` row that belongs to a different organization.

### Finding Description
The broken binding is:
`Shipit.github(organization: params.organization.login).webhook_secret used to verify signature` ≠ `Team.find_or_create_by!(github_id: params.team.id).organization`

Trace:
1. `WebhooksController#create` parses raw JSON and dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature` passes. [1](#0-0) 
2. `verify_signature` selects the `GitHubApp` using `repository_owner`, which for a `membership` event (no `repository` key) falls back to `params.dig('organization', 'login')` — an attacker-controlled field — and verifies the HMAC of the *entire raw body* against that org's `webhook_secret`. [2](#0-1) [3](#0-2) 
   This only proves the sender knows the `webhook_secret` for the org named in the body — it says nothing about whether `team.id` in that same body actually belongs to that org.
3. `MembershipHandler#find_or_create_team!` looks the `Team` up (or creates it) purely by `github_id: params.team.id`: [4](#0-3) 
   The `organization`-setting block only runs on creation (`find_or_create_by!`'s block semantics) — if a `Team` with that `github_id` already exists (e.g., belonging to a different, real organization), it is returned as-is, with its true `organization` untouched and unchecked against `params.organization.login`.
4. `#process` then unconditionally calls `team.add_member(member)` for `action == 'added'`, using `member = User.find_or_create_by_login!(params.member.login)` — also fully attacker-controlled. [5](#0-4) 
5. `Team#add_member` appends the member to `members` (backed by `Membership`) with no additional authorization check. [6](#0-5) 

Exploit flow: the attacker administers `AttackerOrg`, one of possibly several organizations configured in Shipit's multi-tenant `github:` secrets block (as documented for multi-org setups), and thus genuinely possesses `AttackerOrg`'s `webhook_secret`. They craft a `membership` payload:
```json
{"action":"added","team":{"id":<target_team_github_id>,"name":"x","slug":"x","url":"http://x"},
 "organization":{"login":"AttackerOrg"},"member":{"login":"attacker-login"}}
```
sign it with `AttackerOrg`'s real `webhook_secret`, and POST to `/webhooks` with `X-Github-Event: membership`. `verify_signature` passes (it only checks against `AttackerOrg`), `find_or_create_team!` matches the pre-existing `Team` row for the *target* organization by `github_id`, and `team.add_member(attacker)` inserts a `Membership` for the attacker into the target org's team.

No existing guard prevents this: `verify_signature` never cross-references `params.team.id` against the resolved org; the `ExplicitParameters` schema only validates types/presence, not ownership; `find_or_create_by!`'s block is skipped on the find path, so no re-validation of `organization` occurs.

### Impact Explanation
A successful request writes a `Membership` row binding the attacker's `User` to a `Team` belonging to an organization the attacker never authenticated as. If that `Team.id` is listed in `Shipit.github_teams`, `User#authorized?` becomes true for the attacker via `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, granting them full Shipit access (deploys, rollbacks, stack management) as if they were a legitimate member of the victim organization's authorized team. [7](#0-6) 
This is repeatable against any `Team` row whose numeric `github_id` the attacker can learn or guess, and constitutes cross-tenant privilege escalation — matching the "escalation into `Shipit.github_teams` authorization" High/Critical impact category.

### Likelihood Explanation
Requires: (a) Shipit configured for multiple GitHub organizations (documented, supported setup) with the attacker legitimately controlling one of them and thus knowing its real `webhook_secret`; (b) a `Team` row for the victim org already existing in Shipit's DB (created earlier via a legitimate membership sync); (c) the attacker learning/guessing that `Team`'s `github_id` (GitHub team IDs are not secret — visible via GitHub API/UI to anyone who can view the team, or via `Shipit::Team#api_url`). Given these, the attack costs a single signed HTTP POST and is fully repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, after finding an existing `Team` by `github_id`, verify that `team.organization == params.organization.login` before proceeding (raise/drop the event on mismatch), or better, scope the lookup itself: `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`. Additionally, `WebhooksController#verify_signature` should ensure the verified organization matches every organization-identifying field referenced deeper in the payload for handlers that don't carry a `repository`.

### Proof of Concept
Minitest (`test/controllers/webhooks_controller_test.rb`-style) plan:
```ruby
test ":membership signed by AttackerOrg cannot mutate a Team belonging to another org" do
  target_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: known
  attacker_org = 'attacker-org'
  # Assume Shipit.github(organization: attacker_org) configured with a known secret in test fixtures
  payload = {
    action: 'added',
    team: { id: target_team.github_id, name: 'x', slug: 'x', url: 'http://x' },
    organization: { login: attacker_org },
    member: { login: 'attacker-login' }
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', attacker_org_webhook_secret, payload)
  @request.headers['X-Github-Event'] = 'membership'
  @request.headers['X-Hub-Signature'] = signature

  assert_no_difference -> { target_team.reload.members.count } do
    post :create, body: payload, as: :json
  end
  # Currently FAILS: a Membership is created and target_team.members includes 'attacker-login'
  # despite the request having been signed only as attacker_org, never as 'shopify'.
end
```
Assertion binding to validate: `params.organization.login` (verified org, "attacker-org") must equal `Team.find_by(github_id: params.team.id).organization` ("shopify") before `add_member` runs; currently the code never checks this equality.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-33)
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
