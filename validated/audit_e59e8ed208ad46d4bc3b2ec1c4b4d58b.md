### Title
Webhook signature verification is bypassed entirely when `webhook_secret` is unset, allowing unauthenticated forgery of GitHub events including team-membership grants - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb])

### Summary
The external report's bug class is: a service signs/validates an authentication artifact derived from attacker-influenced data without validating its structure or provenance, letting the attacker forge an artifact the server treats as trusted. The closest reachable analog in shipit-engine is `Shipit::WebhooksController#verify_signature`, which delegates HMAC verification to `GitHubApp#verify_webhook_signature`. That method unconditionally treats *any* payload as authentic when no `webhook_secret` is configured for the resolved organization, and the organization used to pick the secret is itself taken from the unauthenticated request body.

### Finding Description
`WebhooksController#verify_signature` resolves which GitHub App configuration (and therefore which HMAC secret) to use from the request body itself, before the body has been authenticated: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the resolved app's `webhook_secret` is blank: [3](#0-2) 

This is a documented, supported configuration state — the example secrets file explicitly shows `webhook_secret:` left blank/nil as a valid setup: [4](#0-3) 

Because the trust decision ("is this request really from GitHub?") collapses to "always true" whenever the operator has not (or cannot, e.g. for a not-yet-recognized org) configured a webhook secret, any unauthenticated caller who knows a target `repository.owner.login` (or `organization.login` for events without a `repository` key) can submit an arbitrary, unsigned JSON body to `POST /webhooks` and have it dispatched exactly as a genuine GitHub webhook, with no structural or provenance validation beyond `verify_signature`'s no-op check.

One of the dispatchable event handlers is `MembershipHandler`, which creates/updates `Team` records and adds/removes `User` records from a `Team` purely from body fields (`team.id`, `organization.login`, `member.login`), with no cross-check that the event actually originated from GitHub: [5](#0-4) 

`Shipit.github_teams` (built from configured OAuth team handles) is exactly the authorization gate used by `Shipit::Authentication#force_github_authentication` to decide whether a logged-in GitHub user may use the app at all: [6](#0-5) [7](#0-6) 

So, stated as an equality that the engine relies on but fails to enforce when `webhook_secret` is unset:

`organization that cryptographically authenticated the webhook` **should equal** `organization whose Team/membership/commit-status/stack state is mutated by the handler`

When `webhook_secret` is blank, the left side of this equality is vacuously true for every request, decoupling it entirely from the right side.

### Impact Explanation
An attacker who already has (or creates) a GitHub login and knows the organization/team id used by an installation can send a forged `membership` webhook adding their own GitHub login to a `Team` that is part of `Shipit.github_teams`. On their next OAuth login, `User#authorized?` will find them a member of that team and `force_github_authentication` will grant them full access to the Shipit instance — an authentication-bypass/escalation into `Shipit.github_teams` authorization, matching the "High" impact tier (escalation into `Shipit.github_teams` authorization). The same missing verification also lets an unauthenticated actor forge `push`, `status`, `check_suite`, `pull_request`, and `merge` events, corrupting deploy/commit/merge-queue state for any stack whose org has no configured `webhook_secret`.

### Likelihood Explanation
Likelihood is conditioned on deployment configuration: the vulnerability is only live for organizations/installations where `webhook_secret` is left blank — a state the project's own example configuration explicitly presents as acceptable, and which is easy for an operator to overlook since Shipit functions normally without it. For such deployments, no credentials, tokens, or secrets are required by the attacker at all, only network access to the `/webhooks` endpoint and knowledge of public GitHub identifiers (org login, team id, login names), which are often discoverable via GitHub's public API.

### Recommendation
- Short term: Make `webhook_secret` mandatory for every configured GitHub App/organization; reject (422) any webhook request for an organization that has no configured secret rather than treating it as automatically verified in `GitHubApp#verify_webhook_signature`.
- Long term: Verify the HMAC signature using the raw body **before** trusting any field from that body (including the field used to select which secret to check against), and have `MembershipHandler` (and other identity-sensitive handlers) cross-validate that the claimed `organization`/`team` in the payload matches the organization the signature was actually verified against, not simply trust body content once `verify_signature` "passes."

### Proof of Concept
1. Identify a Shipit-integrated GitHub organization/installation configured without `webhook_secret` (or an org for which Shipit has no per-org config at all, if `Shipit.github(organization:)` falls back to a secretless default — this fallback path could not be fully confirmed in this pass due to tool budget).
2. Determine the numeric GitHub team id of a team listed in `Shipit.github_teams` (public via GitHub's org teams API) and a GitHub login the attacker controls.
3. `POST /webhooks` with header `X-Github-Event: membership` and no valid `X-Hub-Signature` (or any arbitrary value), body:
```json
{
  "action": "added",
  "team": {"id": <authorized_team_github_id>, "name": "x", "slug": "x", "url": "https://x"},
  "organization": {"login": "<org>"},
  "member": {"login": "<attacker_github_login>"}
}
```
4. `verify_webhook_signature` returns `true` because `webhook_secret` is blank for that org; `MembershipHandler#process` adds the attacker's login to the authorized `Team`.
5. Attacker logs into Shipit via GitHub OAuth; `User#authorized?` now returns true, granting full access to the Shipit deployment.

**Note on completeness**: I was not able to fully inspect the `Shipit.github(organization:)` lookup method (in `lib/shipit.rb`) before running out of tool iterations, so I cannot confirm with certainty whether an *unrecognized* organization name in a multi-org config raises `GithubOrganizationUnknown` (as shown handled in the controller) versus silently returning a default, secretless `GitHubApp`. The core finding — that a configured-but-secretless org fully bypasses signature verification — is confirmed directly from `lib/shipit/github_app.rb` and the example secrets file, independent of that open question.

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
