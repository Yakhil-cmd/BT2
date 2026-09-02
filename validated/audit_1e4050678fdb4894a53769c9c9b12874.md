### Title
Cross-organization webhook signature/payload divergence lets a legitimate org owner write `Team`/`Membership` rows for a different organization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify against using `repository_owner`, which reads `params['repository']['owner']['login']`, falling back to `params['organization']['login']` only if `repository` is absent. `MembershipHandler#find_or_create_team!`, however, unconditionally reads `params.organization.login` to scope the `Team` record it creates or updates. Because the controller does not require these two values to match, an attacker who is a legitimate admin of one Shipit-configured organization (orgA, whose `webhook_secret` they know because they configured it) can sign an arbitrary raw JSON body with orgA's secret while setting `organization.login` to a different, victim organization (orgB), causing a `Team` write scoped to orgB despite orgB's secret never being used.

### Finding Description
The broken binding is:

`Shipit.github(organization: repository_owner).verify_webhook_signature(...)` where `repository_owner == params.dig('repository','owner','login') || params.dig('organization','login')` (`app/controllers/shipit/webhooks_controller.rb:25,59-62`)

vs.

`team.organization = params.organization.login` in `MembershipHandler#find_or_create_team!` (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-42`)

These are two independent reads of the same attacker-controlled raw JSON body, and nothing in the request pipeline (`create`, `drop_unhandled_event`, `verify_signature`, or the handler's `ExplicitParameters` schema) enforces `params.dig('repository','owner','login') == params.organization.login`. The `membership` handler's schema only `requires` the `organization` and `team` sub-hashes; it does not forbid or validate an extraneous top-level `repository` key, and the controller's `repository_owner` helper is evaluated entirely independently of the handler.

Because `POST /webhooks` accepts a raw, attacker-supplied JSON body (`request.raw_post`) with only an HMAC-SHA1 signature check against it, an attacker who legitimately administers orgA (and therefore knows its `webhook_secret`, since they configured it when onboarding orgA into Shipit per "Using Multiple Github Applications") can construct a body such as:

```json
{
  "action": "added",
  "team": {"id": 1, "name": "T", "slug": "t", "url": "https://api.github.com/teams/1"},
  "organization": {"login": "orgB"},
  "member": {"login": "attacker"},
  "repository": {"owner": {"login": "orgA"}}
}
```

sign it with orgA's `webhook_secret`, and POST it with `X-Github-Event: membership`. `verify_signature` computes `repository_owner` as `orgA` (from the injected `repository.owner.login`), fetches `Shipit.github(organization: 'orgA')`, and the signature verifies successfully. `MembershipHandler#process` then runs unmodified, calling `find_or_create_team!` which reads `params.organization.login == 'orgB'` and creates/updates a `Team` row scoped to orgB, then adds the attacker's GitHub login as a member of that team via `team.add_member(member)` — all without ever presenting a valid signature for orgB.

### Impact Explanation
This is a cross-organization state mutation: a request authenticated only against orgA's secret writes and mutates a `Team`/`Membership` record belonging to orgB. If orgB's team slug/id is guessed or known (team ids/slugs are often public via GitHub's API) and that team is referenced in `Shipit.github_teams` for authorization purposes, the attacker can add themselves as a member of a `Team` object representing an org they do not administer, which can feed into Shipit's team-based authorization checks (`User#authorized?` in `app/models/shipit/user.rb`). This matches the "Critical" category of a payload for one repository/org mutating another's team, and is repeatable against any victim organization for which the attacker can guess/know a `team.id`.

### Likelihood Explanation
Preconditions: Shipit must be configured with multiple GitHub organizations/apps (per `docs/setup.md`), and the attacker must legitimately administer at least one of them (orgA) — a realistic scenario for a Shipit instance shared across many teams/orgs, where each org owner configures their own app/secret. The attack costs the attacker nothing beyond crafting one JSON payload and computing an HMAC with a secret they already possess. No GitHub session, Shipit session, or orgB secret is required. It is fully repeatable for any `membership` (or similarly-shaped) event against any team whose numeric `github_id` is known or guessable.

### Recommendation
In `MembershipHandler` (and any other handler that trusts `params.organization.login` or similar org-scoped fields), require and cross-check the value against the same organization value used in `WebhooksController#verify_signature` (i.e., ensure `params.dig('repository','owner','login')`/`repository_owner` equals `params.organization.login`) before processing, rejecting the event (422) if they diverge. More robustly, pass the verified `repository_owner` value down to handlers instead of letting handlers re-derive organization identity from unrelated payload fields.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Configure `Shipit.github_apps`/`Shipit.github(organization:)` stubs for both `orgA` and `orgB`, each with a distinct `webhook_secret`.
2. Build a JSON body: `{"action"=>"added","team"=>{"id"=>1,"name"=>"T","slug"=>"t","url"=>"..."},"organization"=>{"login"=>"orgB"},"member"=>{"login"=>"attacker"},"repository"=>{"owner"=>{"login"=>"orgA"}}}`.
3. Compute `X-Hub-Signature` using orgA's `webhook_secret` over the raw JSON.
4. `post :create, body: raw_json, headers: {'X-Github-Event' => 'membership', 'X-Hub-Signature' => sig_with_orgA_secret}`.
5. Assert response is `200 OK` (signature accepted using orgA's secret).
6. Assert `Shipit::Team.find_by(github_id: 1).organization == 'orgB'` — demonstrating a team record scoped to orgB was created/mutated despite orgB's secret never being used, confirming the divergent binding `repository_owner (orgA) != params.organization.login (orgB)` is not enforced anywhere in the path. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-43)
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
