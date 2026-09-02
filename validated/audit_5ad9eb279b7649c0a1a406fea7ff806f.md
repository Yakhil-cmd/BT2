### Title
Cross-organization team membership mutation via unscoped `Team.find_or_create_by!(github_id:)` in `MembershipHandler` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` resolves the target `Team` solely by the GitHub-global `team.id` field, with no check that the organization whose `webhook_secret` validated the request matches the `organization` column already persisted on that `Team` row. Any org onboarded into Shipit's multi-org config can therefore add or remove members on a `Team` that legitimately belongs to a different onboarded org, including a team referenced by `Shipit.github_teams` for authorization.

### Finding Description
The broken binding, stated explicitly: `verify_signature`'s selected org (`repository_owner`, used to pick the `GithubHook`/webhook secret) must equal `Team#organization` for the team being mutated by the same request. In `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) [2](#0-1) 

`repository_owner` is derived from the attacker-controlled JSON body (`repository.owner.login` if present, else `organization.login`). For membership events (no `repository` key), it equals `params['organization']['login']` — a value the attacker fully controls in the payload they sign. The signature is checked against `Shipit.github(organization: repository_owner)`'s `webhook_secret` (`lib/shipit/github_app.rb#verify_webhook_signature`), which is only "valid" for that specific org's secret.

In `MembershipHandler`: [3](#0-2) 

`find_or_create_team!` looks up `Team` purely by `github_id`. The block that sets `team.organization = params.organization.login` only runs on **creation**. When `params.team.id` already matches an existing `Team` row (as stipulated in the question), that block never executes, so the existing team's `organization` column is left untouched and is never compared to `params.organization.login` or to `repository_owner`. `Team#add_member` then unconditionally appends the attacker-named `member` (`app/models/shipit/team.rb:41-43`) with no further authorization check.

Exploit flow: the attacker administers two GitHub orgs (Org B and Org C) both onboarded into Shipit via the documented multi-org `github:` config (`docs/setup.md`, "Using Multiple Github Applications"). Because they configured the GitHub App / webhook for Org B themselves, they know Org B's `webhook_secret`. They craft a JSON body: `{"action":"added","team":{"id":<victim_team_github_id>,...},"organization":{"login":"orgb"},"member":{"login":"attacker"}}`, compute `sha1=HMAC(orgb_secret, body)`, and POST it to `/webhooks` with `X-Github-Event: membership`. `verify_signature` resolves `repository_owner = "orgb"`, fetches Org B's app, and the signature checks out — genuinely, no forgery of the HMAC is needed since the attacker legitimately owns that secret. `MembershipHandler` then finds the pre-existing `Team` row (belonging to, e.g., `organization: "victimorg"`) by `github_id` and appends the attacker as a member, entirely bypassing any binding to Org B.

Existing guards do not catch this: `verify_signature` only proves "this request came from whichever org is named in the payload," not "this request may only mutate resources tagged with that org." `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape, not tenant scoping. `find_or_create_by!`'s creation block is a no-op cross-check for pre-existing records.

### Impact Explanation
An attacker who controls even a single unprivileged, Shipit-onboarded GitHub organization can write membership records (`Shipit::Membership`) into any other onboarded organization's `Team`, as long as they know or can guess/enumerate the target `team`'s numeric GitHub `github_id`. If that `Team` is one referenced by `Shipit.github_teams` (`lib/shipit.rb:256-258`, `oauth.teams` config), this directly escalates the attacker's own user account into `User#authorized?` (`app/models/shipit/user.rb:80-82`), i.e., authenticated/authorized access to the whole Shipit instance — matching the "High: escalation into `Shipit.github_teams` authorization" category. The write is repeatable against any team ID and any onboarded org combination, and blast radius spans all tenants sharing one Shipit deployment under the multi-org config.

### Likelihood Explanation
Requires: (1) Shipit configured for multi-org GitHub Apps (`docs/setup.md`, "Using Multiple Github Applications"), a documented and supported deployment mode; (2) attacker administers/onboards at least one org into that config and thus knows its `webhook_secret` (a realistic precondition in self-service/multi-tenant onboarding flows where each org's admin generates its own App and secret); (3) knowledge of the victim team's numeric `github_id`, which is not secret (visible in prior webhook deliveries, GitHub API team listings, or simply brute-forced since GitHub team IDs are sequential integers). No Shipit session, API token, or the victim org's own secret is ever needed. Cost is a single signed HTTP POST.

### Recommendation
Bind the `Team` lookup/mutation to the verified organization: in `MembershipHandler#find_or_create_team!`, require `params.organization.login.downcase == team.organization.downcase` for existing records (raise/drop the event otherwise), and additionally have `WebhooksController#verify_signature` pass the verified organization into the handler context so `process` can assert equality rather than trusting `params.organization.login` picked from the same attacker-controlled body used for routing.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test ":membership from org B cannot add a member to org A's existing team" do
  team = shipit_teams(:shopify_developers) # organization == "shopify"
  org_b_secret = 'org-b-secret'
  GithubHook::Organization.create!(organization: 'orgb', event: 'membership', secret: org_b_secret)
  Shipit.stubs(:github).with(organization: 'orgb').returns(
    Shipit::GitHubApp.new('orgb', webhook_secret: org_b_secret)
  )

  payload = {
    action: 'added',
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    organization: { login: 'orgb' },
    member: { login: 'attacker' }
  }.to_json
  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', org_b_secret, payload)}"

  @request.headers['X-Github-Event'] = 'membership'
  @request.headers['X-Hub-Signature'] = signature

  # Binding under test: verified org ("orgb") must equal team.organization ("shopify")
  assert_not_equal 'orgb', team.organization

  assert_no_difference -> { Membership.where(team_id: team.id).count } do
    post :create, body: payload, as: :json
  end
  # Currently FAILS: Membership.count increases by 1, proving the missing binding check.
end
```

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
