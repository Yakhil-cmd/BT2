### Title
Membership webhook `find_or_create_team!` matches teams by `github_id` alone, letting an attacker's own signed webhook mutate another organization's `Team` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` looks up a `Team` solely by `github_id` with `Team.find_or_create_by!(github_id: params.team.id)`, never checking that the matched record's `organization` equals the webhook's `params.organization.login`. Because `verify_signature` only authenticates that the payload came from *some* organization Shipit trusts (the one named in `params.organization.login`), an attacker who legitimately controls their own Shipit-registered org can forge a `membership` event naming a victim org's real (globally unique, GitHub-wide) team `github_id`, and Shipit will silently attach the attacker-chosen member to the victim's existing `Team` row.

### Finding Description
The binding the code should enforce is: `matched_team.organization == params.organization.login` for every membership event, i.e. a webhook signed for org A must only ever mutate teams belonging to org A. That binding is broken.

Trace:
1. `Shipit::WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) resolves `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` falls back to `params.dig('organization', 'login')` (line 61) for organization-scoped events like `membership`. It then checks the HMAC signature against that org's own `webhook_secret` [1](#0-0) [2](#0-1) . This only proves the request was signed by *the org named in the payload's own `organization.login`* - it proves nothing about which `github_id` is inside `params.team`.
2. `GitHubApp#verify_webhook_signature` uses a per-organization `webhook_secret` pulled from that org's own config entry [3](#0-2) [4](#0-3) . An attacker who legitimately administers their own org that is registered with Shipit (a real, if unprivileged-in-Shipit, tenant) knows that org's own webhook secret and can sign arbitrary JSON bodies for it.
3. `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.github_team = ...; team.organization = params.organization.login }` (app/models/shipit/webhooks/handlers/membership_handler.rb:38-43). `find_or_create_by!` performs a `find_by(github_id: ...)` first; if a `Team` with that `github_id` already exists (created earlier from the victim org's own genuine membership webhook), that existing record is returned **without running the block**, so its `organization` column is left as the victim's org, untouched.
4. Back in `process`, `team.add_member(member)` (or `team.members.delete(member)`) then mutates that victim `Team`'s membership list using a `User` resolved purely from `params.member.login`, an attacker-controlled string [5](#0-4) [6](#0-5) .

Attacker request: a POST to `/webhooks` with header `X-Github-Event: membership`, signed with the attacker's own org's webhook secret, and JSON body:
```json
{
  "action": "added",
  "team": { "id": <victim_team_github_id>, "name": "x", "slug": "x", "url": "x" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-controlled-username" }
}
```
GitHub team ids are global integers assigned across all of GitHub (not per-org namespaced), and an org's team list (and thus its ids) is visible via `GET /orgs/{org}/teams` to members of that org, so the attacker can obtain or brute-force the victim's real team `github_id` without any Shipit credential.

None of the existing guards stop this: `verify_signature` validates provenance of the *organization named in the payload*, not of the *team id embedded in the payload*; `ExplicitParameters` only checks types (`Integer`, `String`), not ownership; `Team#add_member` performs no cross-check against `organization`; and `force_github_authentication`/`User#authorized?` are session-based controller-level guards that don't apply to the unauthenticated `WebhooksController`.

### Impact Explanation
A successful request adds an attacker-controlled `User` (or removes a legitimate member) to/from a `Team` row that belongs to a different, victim organization, without ever touching the victim org's real webhook secret or GitHub account. If that victim `Team` is referenced in `Shipit.github_teams` (the set of teams whose membership grants access via `User#authorized?`, see app/controllers/concerns/shipit/authentication.rb:26-30), this is a direct escalation into Shipit's authorization system - the attacker's chosen `User` becomes an authorized Shipit user with access to stacks, deploys, and rollbacks gated by that team, matching the "escalation into `Shipit.github_teams` authorization" High-severity category. The attack is repeatable against any `github_id` the attacker can enumerate/observe and works cross-tenant in any multi-org Shipit deployment.

### Likelihood Explanation
Requires: (a) a multi-org Shipit deployment where the attacker administers/controls at least one legitimately-registered organization (and thus knows that org's own `webhook_secret`), and (b) a pre-existing `Team` record for the victim's team id (created from a prior genuine webhook), and (c) knowledge of the victim's team's `github_id`, obtainable via GitHub's own team-listing API for any org whose team list is visible to the attacker. No Shipit session, API token, or victim secret is needed. Cost is a single crafted HTTP POST; the primary friction is operating in a deployment with more than one configured org and guessing/observing the right numeric id, both realistic in Shopify-style shared Shipit installs.

### Recommendation
`find_or_create_team!` must scope the lookup by both `github_id` and `organization`, and must reject (or re-parent only via an authenticated org-management flow) any payload where an existing `Team` record's `organization` differs from `params.organization.login`, e.g. `Team.find_by(github_id: params.team.id)` then explicitly `raise` or drop the event if `team.organization != params.organization.login`, only creating a new record when no conflicting `github_id` exists for a different org.

### Proof of Concept
minitest plan (`test/models/webhooks/membership_handler_test.rb`, illustrative, no live GitHub call needed since `find_or_create_team!` and `add_member` are pure ActiveRecord calls):
```ruby
test "membership webhook cannot attach attacker member to a team owned by a different organization" do
  victim_team = shipit_teams(:testing) # existing Team fixture, organization: "shopify", github_id: 1234
  assert_equal "shopify", victim_team.organization # binding LHS

  payload = {
    "action" => "added",
    "team" => { "id" => victim_team.github_id, "name" => "x", "slug" => "x", "url" => "x" },
    "organization" => { "login" => "attacker-org" }, # binding RHS, differs from victim_team.organization
    "member" => { "login" => "attacker_controlled_user" }
  }

  assert_no_difference -> { Shipit::Team.count } do
    Shipit::Webhooks::Handlers::MembershipHandler.new.call(payload)
  end

  victim_team.reload
  # Fails today: attacker-controlled user is added to the victim's team despite
  # payload["organization"]["login"] != victim_team.organization
  refute_includes victim_team.members.map(&:login), "attacker_controlled_user"
end
```
This asserts the equality `matched_team.organization == payload["organization"]["login"]` must hold (or the write must be rejected); the current implementation violates it and adds the member anyway.

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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
