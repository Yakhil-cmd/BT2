### Title
Webhook signature verification keys off an attacker-controlled organization field, allowing forged `membership` events to add arbitrary GitHub identities to authorized `Shipit.github_teams` teams - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on a field taken directly from the unauthenticated JSON body (`repository.owner.login` or `organization.login`), rather than from any property of the actual, authenticated delivery channel. Because the signature check itself fails open when `webhook_secret` is blank, an attacker can pick an organization name whose Shipit config has no `webhook_secret` set (a state the project's own documentation shows as a valid configuration) and thereby completely bypass signature verification for that request. The verified "organization identity" is then decoupled from the entity the corresponding handler actually mutates, letting `MembershipHandler` create/join teams that are checked against `Shipit.github_teams` for authorization.

### Finding Description
`WebhooksController#verify_signature` computes the org used for verification purely from payload content: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` fails open when no secret is configured for that organization: [3](#0-2) 

Shipit explicitly documents/ships example configurations where `webhook_secret` is left blank per organization, and supports multiple GitHub organizations each with independent app config: [4](#0-3) [5](#0-4) 

If the operator's Shipit instance has any organization entry configured without a `webhook_secret` (the documented default/example state), an attacker can send a POST to the shared `/webhooks` endpoint with `organization.login` (or `repository.owner.login`) set to that organization's name. `verify_signature` will look up that org's `GithubApp`, find `webhook_secret` blank, and `verify_webhook_signature` returns `true` unconditionally — no HMAC check is actually performed.

Once "verified," the event handler processes the attacker-supplied body without re-validating that the organization used for verification matches the entity being written. For the `membership` event: [6](#0-5) 

`find_or_create_team!` finds or creates a `Team` keyed purely by the attacker-supplied `team.id` (an arbitrary integer chosen by the attacker), and `add_member` attaches an arbitrary attacker-chosen `member.login` (created on the fly via `User.find_or_create_by_login!`) to that team.

`User#authorized?` grants full application access based solely on team membership matching `Shipit.github_teams` (a list of team IDs configured by the operator): [7](#0-6) [8](#0-7) 

If an authorized team's numeric GitHub team ID is known (team IDs are low-entropy integers, and in many setups discoverable via the public GitHub API or org page source), the attacker forges a `membership` webhook with that `team.id` and a `member.login` matching a GitHub account the attacker controls. This inserts a `Team`/membership row associating the attacker's GitHub login with an authorized team — entirely bypassing the intended GitHub-team-membership check — because the binding "organization whose secret authenticated the request" == "organization/team the handler actually writes to" was never enforced; the handler trusts payload-supplied identifiers instead.

### Impact Explanation
This breaks the exact trust binding called out for this analog class: the organization that "authenticated" the webhook (by having its, possibly blank, secret selected) is not cryptographically tied to the team/repository object the handler subsequently writes. The result is escalation into `Shipit.github_teams` authorization — an unprivileged external actor can grant their own GitHub identity membership in an authorized team, then complete a normal (unrestricted) OAuth login with that same GitHub login and pass `current_user.authorized?`, achieving full authenticated access to the Shipit instance (viewing/triggering deploys, tasks, stacks) without ever being a real member of the authorized GitHub team. This matches the specified Critical/High impact category "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
The prerequisite — an organization entry configured without `webhook_secret` — is exactly what the project's own example/development secrets files show as acceptable, and is plausible in real deployments (e.g., an operator sets up a second/legacy org config, or initially leaves `webhook_secret` blank while testing). No repository write access, `ApiClient` token, or privileged account is required; the attacker only needs to know or guess a team's numeric GitHub ID and reach the public `/webhooks` endpoint, then complete an ordinary OAuth login with a matching GitHub account they own.

### Recommendation
Do not select the verification secret (or decide to skip verification) based on attacker-supplied payload fields alone; verify the signature against every configured organization's secret (or a global secret) rather than trusting `repository.owner.login`/`organization.login` to choose the key. Additionally, `verify_webhook_signature` should not fail open when `webhook_secret` is blank — either require a `webhook_secret` for every configured organization, or reject/flag unsigned webhooks instead of accepting them unconditionally. `MembershipHandler` (and similar handlers) should cross-check that the organization used to select/verify the webhook matches the `organization.login` embedded in the payload it processes, and team membership changes driven by webhooks should be scoped/validated against the organization that was actually verified.

### Proof of Concept
1. Configure (or find a deployment configured as documented) with two GitHub orgs in `secrets.yml`, one (`OrgA`) with `webhook_secret: nil` and another (`OrgB`, the real, secured org whose team IDs matter for authorization).
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "organization": { "login": "OrgA" },
  "team": { "id": <victim_team_github_id>, "name": "x", "slug": "x", "url": "https://example.com" },
  "member": { "login": "attacker-github-login" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of (or absence of) `X-Hub-Signature`.
4. `MembershipHandler#process` creates/finds `Team` with `github_id == victim_team_github_id` and adds `User` with `login == "attacker-github-login"` as a member.
5. Attacker completes GitHub OAuth login using the real GitHub account `attacker-github-login`; `current_user.authorized?` now returns `true` because that user is a member of a team whose ID is in `Shipit.github_teams`, granting full application access.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
