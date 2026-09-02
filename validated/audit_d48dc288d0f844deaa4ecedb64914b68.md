This confirms the core mechanism. I now have enough to write the finding.

### Title
Webhook signature verification selects the GitHub App/secret from an unverified payload field, decoupled from the repository/team the handler actually writes to - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` chooses which `GitHubApp` (and therefore which `webhook_secret`) to validate the request against using `repository_owner`, a value read directly out of the still‑unauthenticated JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Every webhook handler, however, determines *what to write* (which `Stack`, `Repository`, `Team`, `Commit`, or `PullRequest` gets mutated) from other, independently attacker-controlled fields of the same payload (`repository.full_name`, `organization.login`, `team.id`, etc.). Nothing ties the "org used for signature verification" to the "org/repo actually mutated." In a multi‑organization deployment (`Shipit.github_organizations`, documented under "Using Multiple Github Applications"), if any one configured organization has no `webhook_secret` set (an explicitly supported, documented configuration - see `config/secrets.development.example.yml` and `docs/setup.md`), `GitHubApp#verify_webhook_signature` unconditionally returns `true` for that organization (`return true unless webhook_secret`). An attacker can then send an unauthenticated POST to `/webhooks` claiming `repository.owner.login` (or `organization.login`) equal to that unsecured org to skip signature validation entirely, while setting the actually-acted-upon fields (`repository.full_name`, `organization.login` inside the membership payload, `team.id`, etc.) to reference a different, secured organization/repository tracked by the same Shipit instance.

### Finding Description
`verify_signature` in [1](#0-0)  resolves the app/secret to check against purely from `repository_owner`: [2](#0-1) 

`Shipit#github` supports per-organization apps/secrets as documented, and `GitHubApp#verify_webhook_signature` treats an unset secret as "always verified": [3](#0-2) [4](#0-3) 

Meanwhile, the actual mutation target is derived from a *different* payload path inside each `Handler`, entirely independent of `repository_owner`: [5](#0-4) 

For example `PushHandler` triggers `stack.sync_github` for any stack matching `repository.full_name`/branch: [6](#0-5) , and `MembershipHandler` creates/deletes `Team`/`Membership` records keyed off `params.organization.login` and `params.team.id`, both independently supplied in the same unauthenticated payload: [7](#0-6) .

The equality the code implicitly (and incorrectly) assumes is:
`org verified by signature (payload.repository.owner.login)` == `org/repo actually written (payload.repository.full_name / payload.organization.login / payload.team.id)`.

Because both sides come from the same fully attacker-controlled JSON body, and are read by two completely separate code paths, this equality is never enforced. As documented in `docs/setup.md` ("Using Multiple Github Applications") and exercised by `test/dummy/config/secrets_double_github_app.yml`, real deployments can have several organizations configured, each with its own (optionally blank) `webhook_secret`. Once one organization's secret is left unset — a state the code and docs explicitly tolerate — signature checking becomes a no-op for requests claiming that organization, while the mutating side effects (push-triggered syncs, status updates, check-run refreshes, team membership changes) are keyed off unrelated fields that can point at any other tracked organization/repository/team in the same instance.

### Impact Explanation
This breaks the "organization authenticated vs. repository/team written" binding required by the rules. Concretely, an unauthenticated attacker who only needs to know that Shipit hosts a multi-org install with one org lacking a webhook secret can:
- Force `GithubSyncJob`/`RefreshStatusesJob`/`RefreshCheckRunsJob` on stacks belonging to a different, secured organization (`push`, `status`, `check_suite` handlers), causing spurious/forced deploy-relevant state changes.
- Add arbitrary GitHub logins to a `Team` tracked by Shipit via the `membership` handler (`team.add_member`), which feeds directly into `User#authorized?` and hence `Shipit::Authentication#force_github_authentication`'s `Shipit.github_teams` check — i.e., an attacker can grant an arbitrary user object authorization to use the Shipit UI, matching "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Requires only: (1) the target Shipit instance uses the documented multi-organization GitHub App configuration, and (2) at least one configured organization has no `webhook_secret` set — both are supported, undocumented-as-dangerous configurations shown in the project's own example configs. No credentials, sessions, or API tokens are needed; `/webhooks` is a public unauthenticated endpoint.

### Recommendation
Bind signature verification to the same fields the handler will act on: verify the payload's `repository.full_name` / `organization.login` (whichever the specific event type mutates) matches the organization whose secret validated the signature, and/or require every configured organization to have a non-blank `webhook_secret` before accepting any request. Do not allow `repository.owner.login` (used only for secret selection) to diverge from the identifiers used for the actual database writes.

### Proof of Contest
Given a multi-org `secrets.yml` (as in `test/dummy/config/secrets_double_github_app.yml`) where `OrgOne.webhook_secret` is left blank and `OrgTwo.webhook_secret` is set and protects a private stack, POST to `/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "OrgOne" },
    "full_name": "OrgTwo/private-repo"
  }
}
```
`verify_signature` resolves `repository_owner` = `"OrgOne"`, selects `Shipit.github(organization: "OrgOne")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (absent/invalid) `X-Hub-Signature`. `PushHandler` then looks up stacks via `repository.full_name` = `"OrgTwo/private-repo"` and enqueues `GithubSyncJob` for that stack, entirely bypassing OrgTwo's real webhook secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
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
