I have enough context to write up the finding now.

### Title
Webhook signature verification key is selected from an unauthenticated payload field, letting an attacker route a spoofed event to any less-strictly-configured GitHub App organization while acting on a different, protected repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and therefore which `webhook_secret`) to verify the request signature against by reading `repository_owner` straight out of the *unverified* JSON body, before any signature has been checked. `Shipit::GitHubApp#verify_webhook_signature` unconditionally returns `true` when that app's `webhook_secret` is blank. In any Shipit installation configured with multiple GitHub organizations (the documented "Using Multiple GitHub Applications" setup), an attacker can name an organization that has no `webhook_secret` configured to bypass signature verification entirely, then supply a `repository.full_name` belonging to a *different*, secret-protected organization/repository inside the same payload so that the event handlers act on that other repository.

### Finding Description
`verify_signature` computes the verification key from attacker-controlled JSON before verifying anything: [1](#0-0) [2](#0-1) 

`repository_owner` is taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`), and this value selects the `GitHubApp` config used to verify the HMAC signature via `Shipit.github(organization: repository_owner)`.

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected app has no `webhook_secret`: [3](#0-2) 

The webhook secret is explicitly documented as optional per organization: [4](#0-3) [5](#0-4) 

Once `verify_signature` passes (because it checked against the secret-less org, not the org that owns the repository actually being acted on), `create` parses the *same* raw body and dispatches it, unmodified, to the registered handlers keyed only by `X-Github-Event`: [6](#0-5) 

Every handler resolves the target `Stack`/`Repository` from a *different* field of the same payload — `repository.full_name` — with no re-validation that this repository belongs to the organization whose secret (or lack thereof) authenticated the request: [7](#0-6) [8](#0-7) 

This is structurally identical to the reported bug class: the field used to establish trust (`repository.owner.login`, used to pick the verification key) is decoupled from the field the code actually acts on (`repository.full_name`), and both live in the same untrusted, attacker-supplied payload. Because the signature-selection key itself comes from unauthenticated payload data, an attacker can force verification onto whichever configured organization is weakest (no `webhook_secret`), then have the handler operate on a repository under a different, secured organization.

The `membership` handler compounds this: it creates/looks up a `Team` and adds an arbitrary `member.login` to it based on payload fields, which is a direct path to `Shipit.github_teams` authorization escalation if the targeted `Team.organization`/`slug` matches an authorization-relevant team: [9](#0-8) [10](#0-9) 

### Impact Explanation
This crosses the required High-impact bar: "escalation into `Shipit.github_teams` authorization" — an attacker can forge a `membership` webhook naming a secret-less organization for verification while specifying `team`/`organization`/`member` values that add themselves (or any GitHub login) to a `Team` backing an authorized `Shipit.github_teams` entry, since `MembershipHandler#process` performs `team.add_member(member)` with no cross-check that the verified organization matches `params.organization.login`. It can also drive unauthorized state changes for repositories under a *different*, secret-protected organization (e.g. forcing `GithubSyncJob`/`stack.sync_github` via `push`, or writing `Status` records via `status`), since the org used to pick the verification key is independent of the org/repository the handler actually mutates.

### Likelihood Explanation
Requires only an unauthenticated HTTP POST to the public `/webhooks` endpoint. It is exploitable as soon as any one organization in a multi-org Shipit deployment is configured without a `webhook_secret` (explicitly supported/documented) or is unknown but attacker-guessable, while at least one other org that owns the targeted repository/team does have a secret. No session, `ApiClient`, GitHub App private key, or repository write access is needed.

### Recommendation
Bind the signature-selection organization to the same value the handler will act on: derive `repository_owner` from `repository.full_name`'s owner (or otherwise ensure the verified organization equals the organization of every repository/team referenced by the payload) before dispatching to handlers, and reject the webhook if they don't match. Additionally, consider making `verify_webhook_signature` fail closed (not return `true`) when `webhook_secret` is unset in a multi-organization configuration, and have `MembershipHandler`/other handlers verify that `params.organization.login` matches the `repository_owner` (or configured organization) used for signature verification.

### Proof of Concept
1. Configure Shipit with two organizations per the documented multi-app schema: `OrgA` (has `webhook_secret` set, owns a protected repo/team used for `Shipit.github_teams` authorization) and `OrgB` (no `webhook_secret` configured).
2. POST to `/webhooks` with header `X-Github-Event: membership` and a JSON body where:
   - `organization.login` / `repository.owner.login` = `"OrgB"` (drives `verify_signature`'s `Shipit.github(organization: repository_owner)` lookup, which returns `true` unconditionally because `OrgB` has no secret — [11](#0-10) )
   - `team` = the `id`/`slug` of a team under `OrgA` that is included in `Shipit.github_teams`
   - `member.login` = attacker's own GitHub login
   - `action` = `"added"`
3. No `X-Hub-Signature` matching `OrgA`'s secret is required; the request passes `verify_signature` and reaches `MembershipHandler#process`, which finds/creates the `Team` from `params.team.id` and calls `team.add_member(member)` — [12](#0-11) 
4. The attacker's user is now a member of an `OrgA` team backing `Shipit.github_teams`, satisfying `User#authorized?` and granting access to `OrgA`-owned stacks — [13](#0-12)

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
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
      end
    end
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
