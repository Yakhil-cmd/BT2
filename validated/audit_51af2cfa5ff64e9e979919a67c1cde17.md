### Title
Webhook signature verification fails open when an organization's `webhook_secret` is unset, allowing forged webhooks to bypass `Shipit.github_teams` authorization and write to any tracked repository - ([File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's secret should authenticate an inbound webhook purely from unverified JSON body fields, then delegates the actual authentication decision to `GitHubApp#verify_webhook_signature`. That method treats a blank/unset `webhook_secret` as automatic success rather than failing closed. Because the handlers that mutate state (`PushHandler`, `StatusHandler`, `MembershipHandler`, etc.) re-derive the target repository/organization/team from the same unverified payload, an unauthenticated attacker can post a JSON body claiming to originate from any organization that has no `webhook_secret` configured, and the engine will accept it as "verified," then write real records (sync a stack, forge commit statuses, or add/remove `Team` memberships) exactly as if it had come from GitHub.

### Finding Description
The binding this breaks is: *the organization whose credential authenticated the webhook* == *the repository/team the webhook handler is permitted to write to*.

1. `WebhooksController#verify_signature` derives the org to authenticate against directly from the untrusted payload: [1](#0-0) [2](#0-1) 

2. `GitHubApp#verify_webhook_signature` fails open when that organization has no configured secret: [3](#0-2) 

3. Shipit explicitly supports hosting multiple GitHub organizations/apps in a single instance, each with its own (optional) `webhook_secret`: [4](#0-3) [5](#0-4) 

4. Once `verify_signature` passes (trivially, because the secret is blank), `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs unconditionally on attacker-controlled JSON: [6](#0-5) 

5. Handlers independently resolve *which* repository/organization/team to mutate from the same untrusted payload, with no re-check against a cryptographically verified identity:
   - `Handler#repository_name` (used by `PushHandler`, `CheckSuiteHandler`, etc.) reads `payload.dig('repository', 'full_name')`: [7](#0-6) 
   - `MembershipHandler` reads `params.organization.login` and `params.team` to find-or-create a `Team`, and can add or remove an arbitrary existing `User` (by login) from that team: [8](#0-7) 
   - `PushHandler` triggers a real sync of any tracked stack matching the forged branch/repo: [9](#0-8) 
   - `StatusHandler` creates a commit status (used for deploy safety checks) on any tracked commit by sha: [10](#0-9) 

6. `Shipit.github_teams` (populated from `Team` records created this way) is the sole gate for application authorization: [11](#0-10) 

The `/webhooks` endpoint requires no session, `ApiClient` token, or any other credential — it is reachable by any unauthenticated network client: [12](#0-11) 

### Impact Explanation
An unprivileged, unauthenticated attacker who knows (or guesses) the login of an organization configured in Shipit without a `webhook_secret` can:
- Forge a `membership` event that adds an already-registered `User` (e.g. an account the attacker controls or has convinced a legitimate member to create) to a `Team` that is included in `Shipit.github_teams`, thereby bypassing GitHub-team-based authorization and gaining full authenticated access to the Shipit UI/API for that instance — this maps directly to the in-scope impact "escalation into `Shipit.github_teams` authorization."
- Forge `push`/`status`/`check_suite` events to trigger `GithubSyncJob` or fabricate CI/commit statuses on tracked stacks, influencing deploy-safety checks and stack state for repositories the attacker does not control — a cross-repository write not gated by any real GitHub credential.

### Likelihood Explanation
Requires only that at least one configured organization in a Shipit deployment has `webhook_secret` unset — a state the code and shipped configuration samples (`secrets_double_github_app.yml`, `secrets.test.json`) treat as ordinary and supported, not a misconfiguration that is rejected or warned about. Any host that installs multiple GitHub Apps/orgs, or simply omits the optional `webhook_secret`, is exposed with no attacker prerequisites beyond network access to `/webhooks`.

### Recommendation
`GitHubApp#verify_webhook_signature` should fail closed (reject the request) when `webhook_secret` is blank rather than returning `true`, or the engine should refuse to boot/mount webhook handling for any organization lacking a configured secret. Additionally, handlers should validate that the organization/repository they act on matches the organization whose credential was cryptographically verified, rather than independently re-reading unverified payload fields.

### Proof of Concept
1. Configure Shipit with two organizations, where `OrgB` has `webhook_secret: nil` (as shown in `test/dummy/config/secrets_double_github_app.yml`).
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Deployers", "slug": "deployers", "url": "https://x" },
  "organization": { "login": "OrgB" },
  "member": { "login": "attacker-controlled-login" }
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgB").verify_webhook_signature(...)`, which returns `true` immediately because `OrgB`'s `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`).
4. `MembershipHandler#process` runs, creating/finding `Team` for `OrgB` and adding `attacker-controlled-login` as a member (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`).
5. If that team is listed in `Shipit.github_teams`, `attacker-controlled-login`'s user account now passes `User#authorized?` (`app/models/shipit/user.rb:80-82`) without ever authenticating through GitHub OAuth or possessing a real GitHub membership.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** config/routes.rb (L14-14)
```ruby
  resources :webhooks, only: :create
```
