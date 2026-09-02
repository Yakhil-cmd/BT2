### Title
Unauthenticated GitHub webhook forgery when `webhook_secret` is unset allows cross-organization writes and authorization escalation - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` delegates the "is this webhook really from GitHub" check to `GitHubApp#verify_webhook_signature`. That method explicitly returns `true` whenever the configured `webhook_secret` for the resolved organization is blank [1](#0-0) . Because `webhook_secret` is an optional configuration field in every documented setup path [2](#0-1) [3](#0-2) , any Shipit instance (or any single organization in a multi-org config) that has not set this optional value accepts **unsigned, unauthenticated** webhook payloads. The binding that is supposed to hold — "the organization whose signature was verified" == "the repository/team the payload is allowed to mutate" — collapses entirely because no signature is required at all in that configuration state.

### Finding Description
`WebhooksController#verify_signature` looks up the GitHub App config for `repository_owner`, itself parsed straight out of the untrusted, unauthenticated JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) [4](#0-3) . It then calls `verify_webhook_signature`, which is meant to enforce that only the real GitHub App produced the request:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [1](#0-0) 

When `webhook_secret` is not configured, this "authentication" step is a no-op — it returns `true` for every request, regardless of the `X-Hub-Signature` header or its absence. Since `webhook_secret` is presented in the documentation and templates as an optional field ("`webhook_secret: # nil`"), it is entirely possible — and by nothing but convention discouraged — to run Shipit with none of the organizations configured with a secret at all, especially in the documented "multiple GitHub applications" setup where every org has its own independent, individually-optional secret [5](#0-4) .

Once signature verification is bypassed, `WebhooksController#create` dispatches the fully attacker-controlled JSON straight into the handler pipeline with no further authentication [6](#0-5) . The handlers use fields from that same untrusted payload to select *which* repository/stack/team to mutate:
- `PushHandler` triggers a `GithubSyncJob`/deploy-eligible sync for any stack matching `repository.full_name` in the forged payload [7](#0-6) .
- `MembershipHandler` creates/updates a `Team` and appends an attacker-chosen GitHub login as a member of that team based purely on the forged `team`/`organization`/`member` payload [8](#0-7) . `Team` records back the `Shipit.github_teams` authorization list that gates access to the entire application via `current_user.authorized?` in `Shipit::Authentication` [9](#0-8) .
- `StatusHandler`/pull-request handlers create commit statuses and manipulate `ReviewStack`/pull request state for any repository named in the payload.

There is no cryptographic binding tying "the organization the request claims to authenticate as" to "the repository/team the payload is permitted to mutate" once the secret check is skipped — this is the exact analog of the audited bug class: a verification step (loop bound / signature) that silently degrades and lets attacker-controlled data downstream act unconstrained.

### Impact Explanation
An unauthenticated network attacker who can reach `/webhooks` on an instance (or a single organization slice of a multi-org instance) with no `webhook_secret` configured can:
- Forge `membership` events to add an arbitrary GitHub login into a `Team` whose handle matches an entry in `Shipit.github_teams`, escalating into the authorization gate that otherwise requires real GitHub org/team membership — this is explicitly listed as a High-impact category ("escalation into `Shipit.github_teams` authorization").
- Forge `push`/`status`/`pull_request` events to make unauthorized cross-repository writes: creating fake commit statuses, unarchiving/archiving review stacks, or influencing merge-queue state for any repository tracked by the instance.

### Likelihood Explanation
The precondition (`webhook_secret` unset) is not an edge case invented for this analysis — it is the literal default shown in every shipped secrets template and documentation example [2](#0-1) [3](#0-2) , and is reachable purely from an unauthenticated HTTP request to the mounted `/webhooks` endpoint — no session, API token, or GitHub credentials are required, satisfying the rules' bar for an "unprivileged attacker."

### Recommendation
Make `webhook_secret` mandatory rather than optional: `verify_webhook_signature` should fail closed (return `false`/raise) when no secret is configured, instead of returning `true`. Additionally, cross-check that the authenticated organization matches the repository/organization actually referenced by the payload fields the handlers act on, so a compromised/misconfigured single-org secret cannot be leveraged to mutate resources belonging to a different org's repositories/teams.

### Proof of Concept
1. Deploy Shipit with `config/secrets.yml` containing a `github` block where `webhook_secret` is left blank (as in the shipped example templates).
2. Without any GitHub-issued signature, `POST /webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 999999, "name": "Fake", "slug": "developers", "url": "https://example.com" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker-github-login" }
}
```
3. `GitHubApp#verify_webhook_signature` returns `true` (no secret configured), `WebhooksController#create` dispatches to `MembershipHandler`, which creates/updates a `Team` and adds `attacker-github-login` as a member [8](#0-7) .
4. If the forged `team.id`/`slug`/`organization.login` collide with a handle configured in `Shipit.github_teams`, the attacker's GitHub login is now recorded as a team member for the authorization check performed by `Shipit::Authentication#force_github_authentication` [9](#0-8) , without ever having a real GitHub App signature or organization membership.

### Citations

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
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
        -----BEGIN RSA PRIVATE KEY-----
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-18)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
