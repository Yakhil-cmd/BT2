### Title
Forged `membership` Webhook Grants Unauthorized Access to `Shipit.github_teams` via Signature-less Organization Confusion - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to validate a webhook against using an attacker-supplied field (`repository_owner`), and silently treats an organization with no `webhook_secret` configured as "verified" unconditionally. `MembershipHandler` then mutates a `Team` record looked up purely by the attacker-supplied numeric `github_id`, with no binding back to the organization that was actually authenticated. This lets an unauthenticated caller add an arbitrary (real) GitHub account as a member of any pre-existing `Team` — including one listed in `Shipit.github_teams` — thereby escalating that account into Shipit's authorization system.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/organization config to validate against from attacker-controlled JSON, not from anything cryptographically bound yet: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` fully bypasses HMAC validation whenever the resolved organization has no `webhook_secret` configured, which the docs explicitly describe as *optional*: [3](#0-2) [4](#0-3) 

So any request whose `organization.login` (or `repository.owner.login`) names an org configured without a secret is accepted as "verified" regardless of the `X-Hub-Signature` header — the request body is entirely attacker-controlled.

`MembershipHandler` then processes the (unverified/forged) body and mutates authorization state keyed only by the attacker-supplied numeric `team.id`, with no check that this id/org actually corresponds to the organization that was used to "authenticate" the request: [5](#0-4) 

`Team.find_or_create_by!(github_id: params.team.id)` will match an *existing* `Team` row if the attacker supplies the `github_id` of a team already present in the DB (team IDs are public GitHub metadata, discoverable via the GitHub API), and `team.add_member(member)` then appends the attacker-chosen (but real, GitHub-API-verified-to-exist) user to that team: [6](#0-5) 

Authorization is granted purely based on team membership by `id`, independent of organization: [7](#0-6) [8](#0-7) 

The broken binding is: **the organization whose webhook secret "authenticated" the request ≠ the team/authorization record that is actually written.** The verification step trusts a field describing *which org sent this*, while the mutation trusts an unrelated attacker-chosen numeric id describing *which team to modify*, and the two are never checked for consistency. This is the direct analog of the audit report's root cause — a value used for one check (`get_dy` estimate direction) diverging from the value actually used to authorize the action (`get_dy` reverse estimate) — here, the value used to pick "is this authentic" (org name) diverges from the value used to decide "what gets mutated" (team github_id), with no organization ownership check tying them together.

### Impact Explanation
An attacker who registers/knows a GitHub login (their own account is sufficient) and knows the numeric `github_id` of a `Team` already recorded in Shipit's database as part of `Shipit.github_teams` can add themselves to that team via a forged `membership` webhook, then complete a normal OAuth login flow to become `authorized?`. This is a direct escalation into `Shipit.github_teams` authorization, explicitly listed as a High-severity impact category — granting the attacker full access to trigger deploys, rollbacks, and tasks across every stack gated by that team.

### Likelihood Explanation
Exploitation requires: (1) an organization in the multi-org config with no `webhook_secret` set — a state the setup docs describe as normal/optional and thus plausible in real deployments — and (2) knowledge of a target team's numeric GitHub `id`, which is public information retrievable from the GitHub API for any team the attacker can see (e.g., via `GET /orgs/{org}/teams`). No privileged Shipit credentials, session, or API token are required, matching the "unprivileged attacker" threat model. Likelihood is moderate-to-high in deployments that use the documented optional-secret configuration.

### Recommendation
- Do not treat an unset `webhook_secret` as "verified"; require an explicit signature check or reject the request if no secret is configured for a resolvable organization.
- In `MembershipHandler#find_or_create_team!`, scope the `Team` lookup by both `github_id` and `organization` (matching the organization actually verified by the webhook signature), and reject processing if the payload's `organization.login` does not match the `repository_owner`/verified org used to select the webhook secret.
- Consider re-validating team membership changes against a live GitHub API call before granting/persisting authorization-affecting state.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs, e.g. `trusted-org` (has `webhook_secret`) and `staging-org` (no `webhook_secret`, per docs this is optional).
2. Look up (via public GitHub API) the numeric `id` of a GitHub team already mirrored in Shipit as a `Team` row referenced by `Shipit.github_teams` (e.g., `trusted-org/deployers`, `github_id = 12345`).
3. Send an unauthenticated `POST /webhooks` with header `X-Github-Event: membership` and a body:
```json
{
  "action": "added",
  "team": {"id": 12345, "name": "Deployers", "slug": "deployers", "url": "https://example.com"},
  "organization": {"login": "staging-org"},
  "member": {"login": "attacker-github-login"}
}
```
No valid `X-Hub-Signature` is required because `staging-org` has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally [9](#0-8) .
4. `MembershipHandler` finds the existing `Team` with `github_id: 12345` and calls `team.add_member(User.find_or_create_by_login!('attacker-github-login'))` [10](#0-9) .
5. The attacker completes GitHub OAuth login as `attacker-github-login`; `current_user.authorized?` now returns true because the user is a member of a team whose `id` is in `Shipit.github_teams` [7](#0-6) , granting full access to trigger deploys/tasks.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
