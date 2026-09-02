### Title
Webhook signature check is keyed by `repository.owner.login`, while all handlers act on the unrelated `repository.full_name` / `organization.login` fields, letting an attacker use a secret-less org to forge events against a protected org - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate a delivery against using `repository.owner.login` (or, as fallback, `organization.login`) taken directly from the *unverified* JSON body. All the actual side-effecting logic in the webhook handlers, however, keys off a **different** field of the same payload — `repository.full_name` in `Handler#repository_name`, or `organization.login`/`team` in `MembershipHandler` — to decide which `Stack`/`Repository`/`Team` gets mutated. Because Shipit supports multiple organizations in `Shipit.github`, and `GitHubApp#verify_webhook_signature` trivially returns `true` whenever an organization has no `webhook_secret` configured (a documented, valid, optional setting), the "organization whose signature verified" and "repository/organization actually written to" are never the same value and are never cryptographically bound to each other.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`lib/shipit/github_app.rb`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

`config/secrets.development.shopify.yml` and `docs/setup.md` both document a multi-org configuration where `webhook_secret` is explicitly optional/nil per organization: [3](#0-2) 

Meanwhile, the handlers that execute state-changing actions resolve the *target* repository/organization from a completely different field of the same JSON body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`PushHandler` uses that `stacks` scope to force a resync: [5](#0-4) 

`MembershipHandler` uses `params.organization.login`/`params.team` (again, not `repository.owner.login`) to create/update a `Team` and add/remove members, and this `Team` backs `User#authorized?`:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [6](#0-5) 
```ruby
def authorized?
  @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
end
``` [7](#0-6) 

**The broken binding, as an equality:**
`organization whose webhook_secret verified the delivery (repository.owner.login / organization.login as read by verify_signature)` **≠** `repository/organization actually mutated by the handler (repository.full_name / organization.login as read by Handler#repository_name and MembershipHandler#find_or_create_team!)`.

Before the attacker's request: an attacker with no credentials, no repository access, and no knowledge of any `webhook_secret` cannot influence any Shipit-managed `Stack` or `Team`.

After the attacker's request: because at least one organization entry in `Shipit.github` can legitimately have `webhook_secret: nil` (an officially documented configuration), `verify_webhook_signature` unconditionally returns `true` for any payload whose `repository.owner.login` matches that unsecured organization name — regardless of any other field in the body. The attacker then sets `repository.full_name` (for push/check_suite events) or `organization.login`/`team` (for membership events) to point at a *different*, secured organization/repository/team that Shipit tracks, and the handler acts on that target with no further checks, since `stacks`/`find_or_create_team!` never re-validate that the acted-upon organization matches the one whose secret was checked.

### Impact Explanation
Via the `membership` event this reaches the "High" bucket explicitly listed in scope: an unprivileged attacker can escalate into `Shipit.github_teams` authorization. By forging an unauthenticated (secret-less-org) `membership` webhook naming the real, privileged `Team`'s `github_id`/`organization` and adding themselves (`params.member.login`) as a member, `Team.find_or_create_by!`/`team.add_member(member)` creates/updates that `Team` row, causing `User#authorized?` to return `true` for the attacker's Shipit user — bypassing the GitHub-team membership gate enforced by `Shipit::Authentication#force_github_authentication`. Via `push`/`check_suite` events, the same field-mismatch also lets the attacker trigger `stack.sync_github` or `schedule_refresh_check_runs!` against arbitrary tracked stacks belonging to organizations they have no relationship with.

### Likelihood Explanation
Low-to-Medium. It requires the Shipit deployment to be configured for multiple GitHub organizations with at least one of them left without a `webhook_secret` — an explicitly supported and documented configuration (shown as the default/example in `docs/setup.md` and `config/secrets.development.shopify.yml`), so it is a realistic, not purely theoretical, operator choice, but it does not affect single-organization or fully-secreted deployments.

### Recommendation
Bind the field used to select/verify the signing organization to the field used to identify the mutated resource: after signature verification, re-derive the "acting organization" strictly from `repository_owner` (the value actually verified) and reject/short-circuit any handler processing where `repository.full_name`'s owner segment, or `organization.login` in membership events, does not match `repository_owner`. Additionally, stop treating "no `webhook_secret` configured" as an implicit pass (`return true unless webhook_secret`) when the Shipit instance is configured with more than one organization — require an explicit signature (or reject webhooks entirely) for any org lacking a secret in multi-org setups.

### Proof of Concept
1. Shipit is configured with two organizations in `Shipit.github`: `unsecured-org` (`webhook_secret: nil`, no stacks of interest) and `victim-org` (has a real `webhook_secret`, and Shipit tracks `victim-org/app` with `Shipit.github_teams` including `victim-org/admins`).
2. Attacker (no GitHub access to `victim-org`, no knowledge of any webhook secret) sends:
```
POST /webhooks
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "team": { "id": <victim-org/admins github team id>, "name": "admins", "slug": "admins", "url": "https://api.github.com/teams/1" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker-github-login" },
  "repository": { "owner": { "login": "unsecured-org" } }
}
```
3. `WebhooksController#verify_signature` computes `repository_owner == "unsecured-org"`, loads that org's `GitHubApp`, and since its `webhook_secret` is nil, `verify_webhook_signature` returns `true` unconditionally — no `X-Hub-Signature` needed.
4. `Shipit::Webhooks.for_event('membership')` dispatches to `MembershipHandler`, which reads `params.organization.login == "victim-org"` and `params.team.id`, finds/creates the real `victim-org/admins` `Team`, and adds `attacker-github-login` as a member.
5. When the attacker subsequently signs into Shipit via OAuth with `attacker-github-login`, `User#authorized?` finds their membership in the now-poisoned `Team`, and `force_github_authentication` grants them access as if they were a legitimate `victim-org/admins` member.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
