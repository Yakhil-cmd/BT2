Confirmed: `User#authorized?` gates access based on membership in `Shipit.github_teams`, so `Team` membership is a real authorization boundary [1](#0-0) .

### Title
Cross-organization Team membership escalation via `MembershipHandler#find_or_create_team!` keying only on `github_id` - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#process` resolves the target `Team` solely by `params.team.id` (`github_id`), never checking that the organization whose secret verified the webhook signature actually owns that team. An attacker with a legitimate `GithubApp`/`webhook_secret` for their own small organization can forge a `membership` webhook whose `team.id` points at a team belonging to an unrelated, more privileged organization already known to Shipit, and add an arbitrary GitHub login (their own) to it.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:

`Team#organization` (the org that actually owns the GitHub team with `github_id == params.team.id`) == the organization whose `webhook_secret` was used to pass `verify_signature` for this request.

Trace:
- `WebhooksController#verify_signature` picks the `GithubApp` to check the signature against using `repository_owner`, which is read directly from the attacker-controlled JSON body: `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) [3](#0-2) . Since the whole request body (including this field) is authored by the attacker, they can set it to their own org login and sign the body with their own org's genuine `webhook_secret`, so `verify_signature` passes legitimately.
- `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) do |team| team.github_team = params.team; team.organization = params.organization.login end` [4](#0-3) . The `organization`/`github_team` assignment only executes inside the `do...end` block, which `find_or_create_by!` runs **only when a new record is created**. If a `Team` row with that `github_id` already exists (e.g. a real team from a victim organization that Shipit previously synced), the lookup returns the existing record untouched — its `organization` is never compared against `params.organization.login` or against the verified `repository_owner`.
- `process` then does `team.add_member(member)` where `member = User.find_or_create_by_login!(params.member.login)` — also fully attacker-controlled [5](#0-4) , letting the attacker name their own GitHub login as the member being added.

None of the existing guards close this gap: `verify_signature` only proves the request was signed by *some* org whose login the attacker chose to put in the payload, not that that org owns `params.team.id`; the `ExplicitParameters` schema on `MembershipHandler` only checks types/presence, not cross-org ownership [6](#0-5) ; and `drop_unhandled_event` is irrelevant since `membership` is a handled event [7](#0-6) .

Attacker's exact request: a legitimately-signed `POST /webhooks` (header `X-Github-Event: membership`) whose JSON body sets `repository.owner.login` (or `organization.login`, used as fallback) to the attacker's own org, is HMAC-signed with the attacker's own real `webhook_secret`, but sets `team.id` to the numeric GitHub team ID of a team belonging to a different, victim organization that Shipit already has a `Team` row for, and `member.login` to the attacker's own GitHub username with `action: "added"`.

### Impact Explanation
The attacker gains membership (`Shipit::Membership`) in a `Team` belonging to an organization they don't control, by only ever using their own legitimate webhook credentials — this is a genuine escalation into `Shipit.github_teams` authorization, since `User#authorized?` treats membership in any team listed in `Shipit.github_teams` as sufficient for access [1](#0-0) . This is repeatable against any `Team` row already present in Shipit's database (any org Shipit tracks that has previously received a `membership` webhook), and the blast radius spans every tenant organization hosted on the same Shipit instance, matching the High severity "escalation into `Shipit.github_teams` authorization" category.

### Likelihood Explanation
Preconditions: the attacker needs (a) a real GitHub organization with its own valid `GithubApp`/`webhook_secret` configured in Shipit (attacker-controlled, low cost — they only need to own a small org Shipit is configured to accept webhooks from), and (b) the numeric GitHub `team.id` of the victim's privileged team, which per the question is obtainable from a public source (e.g., GitHub's public team API) and requires the victim's `Team` to already exist in Shipit's DB (satisfied once any `membership` event has ever fired for it). No Shipit session, API token, or victim secret is required. This is highly feasible and fully repeatable per request.

### Recommendation
In `find_or_create_team!`, always validate/assign `team.organization` against the organization derived from the verified webhook signature (or reject when `params.organization.login` doesn't match the existing `Team#organization`), and derive `repository_owner` for signature verification from a source the attacker cannot spoof independently of the event's actual organization/team ownership, rather than trusting attacker-supplied `repository.owner.login`/`organization.login` fields uncritically.

### Proof of Concept
Minitest plan (integration test on `WebhooksController`):
1. Create two `GithubApp`/webhook secret configs: `attacker_org` (secret `S1`) and `victim_org` (secret `S2`).
2. Seed a `Shipit::Team` fixture with `organization: 'victim_org'`, `github_id: 999`.
3. Build a `membership` payload: `{action: 'added', team: {id: 999, name:'X', slug:'x', url:'...'}, organization: {login: 'attacker_org'}, member: {login: 'attacker_login'}, repository: {owner: {login: 'attacker_org'}}}`.
4. Sign the payload body with `S1` (attacker's own real secret) and set `X-Hub-Signature`/`X-Github-Event: membership` headers.
5. `POST :create` with this body; assert `response :ok`.
6. Assert equality check: `Team.find_by(github_id: 999).organization == 'victim_org'` (unchanged, since block doesn't run on existing record) while a new `Shipit::Membership` was created linking `User.find_by(login: 'attacker_login')` to that same victim `Team` — i.e. `Shipit::Team.find(999).members.pluck(:login)` now includes `'attacker_login'`, proving the verified-org (`attacker_org`) diverges from the mutated team's actual org (`victim_org`).

### Citations

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
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

**File:** app/models/shipit/webhooks.rb (L19-21)
```ruby
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
```
