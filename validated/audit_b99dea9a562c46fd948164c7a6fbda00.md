### Title
Webhook organization used for signature verification can diverge from the organization whose payload is processed, enabling forged `membership` events that escalate into `Shipit.github_teams` authorization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController` picks which GitHub App/organization secret to verify a webhook against using Rails' `params` (which merges query-string and JSON-body values), but then re-parses the raw HTTP body independently in `create` and dispatches that (attacker-fully-controlled) content to the event handlers for whatever `repository`/`organization` value appears in the body. Because the "authenticating organization" binding is decoupled from the "payload actually written" binding, an attacker who can get one configured organization's `webhook_secret` to be unset can forge signature-verified-as-`true` requests carrying a payload that targets a *different*, protected organization — including a `membership` event that adds an arbitrary GitHub login to an existing, `Shipit.github_teams`-authorized `Team` record.

### Finding Description
`verify_signature` derives the org used to pick the webhook secret from `repository_owner`, which reads `params.dig('repository', 'owner', 'login')`: [1](#0-0) [2](#0-1) 

`params` here is the standard Rails `ActionController` parameters hash, which merges `query_parameters` over `request_parameters` (JSON body) for identically-named top-level keys. This means an attacker can send `?repository[owner][login]=<org>` in the query string to control which `GitHubApp`/secret is selected for verification, independently of the JSON body that is actually processed.

`create` independently re-parses the *raw* body (not influenced by the query string) and dispatches it to the real handlers: [3](#0-2) 

`verify_webhook_signature` treats an unset `webhook_secret` as an unconditional pass: [4](#0-3) 

`webhook_secret` is documented as optional and multi-org configurations (each org with its own, independently-optional secret) are an explicitly supported and documented configuration: [5](#0-4) [6](#0-5) 

So if any configured organization has no `webhook_secret` (a documented, supported state), an attacker can:
1. Send a POST to `/webhooks` with query string `repository[owner][login]=<org-without-secret>`.
2. Put an arbitrary JSON body in the raw POST data whose `repository.owner.login`/`organization.login` names the real, protected organization (e.g. the org actually used for the Shipit deployment) and whose event type/content is fully attacker-chosen.
3. `verify_signature` resolves `repository_owner` to the secret-less org (via the query-string override) → `verify_webhook_signature` returns `true` unconditionally → `head(422) unless verified` never fires.
4. `create` re-parses the real raw body (targeting the protected org) and dispatches it to `Shipit::Webhooks.for_event(event)` handlers, with no further authentication.

The most impactful abuse target is the `membership` event handler, which trusts the payload entirely and finds/creates a `Team` purely by the attacker-supplied `team.id` (GitHub team ID, a value that is not secret and is discoverable via the public GitHub API), then adds the attacker-chosen `member.login` to it: [7](#0-6) 

If `team.id` matches the real `github_id` of a `Team` already used for `Shipit.github_teams` authorization, `find_or_create_team!` returns that existing, already-authorized record, and `team.add_member(member)` inserts a `Membership` for the attacker's chosen GitHub login: [8](#0-7) 

`User#authorized?` grants full application access based purely on `teams.where(id: Shipit.github_teams.map(&:id)).exists?`: [9](#0-8) 

After the forged membership is created, the attacker simply signs in through the normal GitHub OAuth flow with the account whose login/GitHub ID they specified; `sign_in_github` creates/finds the `User` by GitHub identity with no additional check: [10](#0-9) 

This crosses the boundary the report's bug-class targets: the organization that "authenticates" the request (selected via a field, `repository_owner`, that is not exclusively covered by the HMAC-verified raw body) is not required to equal the organization/repository whose payload is actually written to the database.

### Impact Explanation
An unauthenticated attacker (no Shipit session, no `ApiClient` token, no GitHub App credentials) can forge a `membership` webhook that adds an arbitrary GitHub account to a `Team` already used for `Shipit.github_teams` authorization, then log in with that GitHub account through the standard OAuth flow to gain full authenticated access to the Shipit instance (deploys, rollbacks, stack configuration, API client management, etc.). This matches the accepted High-impact category: "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Exploitability depends on:
- The deployment using (or having ever used) a multi-organization `github:` configuration, or any configured GitHub App whose `webhook_secret` was left unset — both explicitly documented, supported configurations (`webhook_secret` is described as "optional" in `docs/setup.md`, and the shipped example multi-org config templates leave `webhook_secret` blank).
- Rails' default query/body parameter merge behavior, which is stock framework behavior, not something the engine opts out of.
- Knowledge of the target org's real GitHub team ID, which is discoverable via the public GitHub API (`GET /orgs/{org}/teams`) for any team whose membership is visible, or via the org's team page.

No credentials, tokens, or privileged network position are required, making this practically reachable for any Shipit deployment matching the documented multi-org/optional-secret configuration pattern.

### Recommendation
- In `WebhooksController#repository_owner`, read exclusively from the parsed JSON body (`JSON.parse(request.raw_post)`), never from `ActionController` `params`, so the organization used to select the verifying secret cannot be influenced by query-string parameters.
- Do not allow `verify_webhook_signature` to unconditionally return `true` when `webhook_secret` is blank for any configured organization other than intentionally-unauthenticated single-tenant deployments; at minimum, require an explicit signature-optional grant, and treat a missing secret as "require operator confirmation," not silent bypass.
- In `MembershipHandler#find_or_create_team!`, do not trust a bare `team.id` from the webhook payload to resolve to an already-provisioned, authorization-relevant `Team` without revalidating team membership/identity against the GitHub API for the organization that owns that webhook.

### Proof of Concept
Preconditions: deployment has a secondary GitHub org configured (or misconfigured) with `webhook_secret` unset, e.g. as shown in `test/dummy/config/secrets_double_github_app.yml`, alongside the primary protected org (e.g. `shopify`) that has `Shipit.github_teams` configured and a `Team` record with `github_id = 1000` already authorized.

```
POST /webhooks?repository[owner][login]=OrgTwo HTTP/1.1
Host: shipit.example.com
Content-Type: application/json
X-Github-Event: membership
X-Hub-Signature: sha1=anything-invalid-or-omitted

{
  "action": "added",
  "team": { "id": 1000, "name": "Developers", "slug": "developers", "url": "https://api.github.com/teams/1000" },
  "organization": { "login": "shopify" },
  "member": { "login": "attacker-account" }
}
```

- `repository_owner` resolves to `"OrgTwo"` (from the query string) → `Shipit.github(organization: "OrgTwo").verify_webhook_signature` returns `true` because `OrgTwo` has no `webhook_secret`.
- `create` re-parses the body targeting `shopify`/team `1000` and dispatches the `membership` handler, adding `attacker-account` to the real authorized `Team`.
- Attacker logs into Shipit via `/github/auth/github` as `attacker-account`; `current_user.authorized?` now returns `true`, granting full application access.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-9)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
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

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
    end
```
