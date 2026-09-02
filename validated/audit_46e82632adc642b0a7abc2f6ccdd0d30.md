### Title
Webhook GitHub App selection is keyed off `repository.owner.login`/`organization.login` while the handler acts on `repository.full_name` (or `organization.login` for membership), letting an attacker satisfy signature verification under one org while writing to another org's repository/teams - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the `webhook_secret` HMAC key) used to authenticate an inbound webhook based solely on `repository.owner.login` (falling back to `organization.login`) taken from the attacker-supplied JSON body. The actual side effects performed by the registered handlers, however, act on a *different* field of the very same body: `repository.full_name` for repository lookup (`Handler#repository_name`) or `organization.login`/`team`/`member` for team membership changes. Because the whole HTTP body is attacker-controlled and only one org's secret needs to validate, an attacker who knows (or who benefits from) any single configured GitHub App whose `webhook_secret` is unset can pick that org purely for the signature check while embedding a different, victim repository/organization in the fields the handlers actually consume.

### Finding Description
`verify_signature` in [1](#0-0)  resolves `repository_owner` via: [2](#0-1) 
and uses it to select the `GitHubApp`: [3](#0-2) 

`GitHubApp#verify_webhook_signature` explicitly bypasses HMAC verification entirely when no secret is configured for that org: [4](#0-3) 

Multi-org setups are a documented, supported configuration where each org has an independent `webhook_secret`, and the documentation/example configs explicitly allow `webhook_secret` to be left `nil`: [5](#0-4) [6](#0-5) 

Once the request passes `verify_signature`, the raw body is re-parsed and dispatched to handlers: [7](#0-6) 

Handlers, however, do not use `repository.owner.login`/`organization.login` (the field used for auth) to decide what to act on — they use `repository.full_name`: [8](#0-7) 
which is consumed e.g. by `PushHandler` to sync/deploy any matching stack: [9](#0-8) 
by `StatusHandler` to write CI statuses for any commit sha, independent of repo/org fields: [10](#0-9) 
and by `MembershipHandler`, which creates/joins teams and users keyed on `organization.login`/`team`/`member` fields that are also just attacker-supplied JSON, unconnected to the org whose (possibly secret-less) app satisfied the signature check: [11](#0-10) 

Because the entire raw POST body is attacker-controlled and JSON is not validated against any canonical GitHub-issued structure, nothing prevents `repository.owner.login` (the "authentication" binding) from being crafted to reference a secret-less/attacker-known org while `repository.full_name`/`organization.login` (the "action" binding) reference an unrelated, victim stack, team, or organization actually configured in the Shipit instance. This is the same class of bug as the referenced Vyper `extcodesize` issue: one evaluation of an attacker-influenced value is used for the safety check, while a second, independently-derived evaluation of the (potentially different) value is what actually executes the side effect.

### Impact Explanation
If any one of several configured GitHub Apps in a multi-org Shipit deployment lacks a `webhook_secret` (an explicitly supported and documented configuration), an attacker can forge arbitrary webhook events — `push` (triggering `stack.sync_github`, which can feed the deploy pipeline for a victim's stack), `status` (writing fake CI results for arbitrary commits, defeating `ci.require` checks and enabling unauthorized deploys), and `membership` (creating arbitrary `Team`/`User` records and adding members to teams) — for repositories/organizations that never validated against that request at all. This can escalate to an unauthorized deploy or manipulation of `Shipit.github_teams`-based authorization, both explicitly listed as in-scope Critical/High impacts.

### Likelihood Explanation
Requires only that the operator run a multi-org Shipit configuration (documented feature) where at least one configured org's `webhook_secret` is left unset — a state the example configs and docs actively show as valid (`webhook_secret: # nil`). No credentials, session, or GitHub write access are needed; the attacker only needs network access to the public webhook endpoint and knowledge that a secret-less org exists in the config (org names are often guessable or discoverable from public docs/DNS/marketing).

### Recommendation
Bind the field used for `GitHubApp`/secret selection to the same field(s) actually consumed by every handler (e.g., always derive the authorizing org from `repository.full_name`'s owner segment, or vice versa), and reject requests where `repository.owner.login`/`organization.login` disagree with `repository.full_name`'s owner. Additionally, do not silently treat a missing `webhook_secret` as "verification passed" in multi-org configurations; require an explicit opt-in per organization, or hard-fail webhook processing when a configured GitHub App has no secret set in production environments.

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (has `webhook_secret` set, hosts the real stacks) and `no-secret-org` (misconfigured with `webhook_secret: nil`), per the supported multi-org format in `docs/setup.md`.
2. Attacker POSTs to `/github_webhooks` (or equivalent mounted webhook path) with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha already known to Shipit>",
  "repository": {
    "owner": { "login": "no-secret-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. `verify_signature` resolves `repository_owner` = `"no-secret-org"`, loads that `GitHubApp`, and `verify_webhook_signature` returns `true` unconditionally because that org has no `webhook_secret` (`lib/shipit/github_app.rb` line 77).
4. `Shipit::Webhooks.for_event('push')` runs `PushHandler`, which uses `repository.full_name` = `"victim-org/victim-repo"` to locate and act on the real, secret-protected victim stack — bypassing that stack's own org's webhook authentication entirely.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L181-209)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
