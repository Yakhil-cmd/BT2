Confirmed the bug-class analog. This is a legitimate, high-confidence cross-tenant forgery vulnerability in the multi-organization webhook signature verification flow.

### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while handlers act on `repository.full_name` — allows cross-organization forgery of push/status/check-suite/membership events - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-organization Shipit deployment, each tenant organization has its own GitHub App with its own `webhook_secret`, configured under a distinct key in `secrets.github`, as described in `docs/setup.md:181-216`. `Shipit.github(organization:)` looks up the app/secret purely by that key [1](#0-0)  and `verify_webhook_signature` HMACs the raw payload against that secret [2](#0-1) .

### Finding Description
`WebhooksController#verify_signature` selects which organization's secret to verify against using `repository_owner`, which is read straight out of the untrusted, attacker-controlled JSON body: [3](#0-2) 

Critically, `repository_owner` (`payload.dig('repository','owner','login')`) is a *different* field than the one every handler actually uses to resolve which `Repository`/`Stack` the event applies to: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` [4](#0-3) , and `Repository.from_github_repo_name` looks up records by splitting that `full_name` string [5](#0-4) .

Nothing binds `repository.owner.login` (used for **signature verification / authentication**) to `repository.full_name` (used for **which repository/stack is actually mutated**). A legitimate tenant of this Shipit instance — an org admin who owns a GitHub App installed in "org-A" and therefore knows org-A's `webhook_secret` — can craft a webhook body where:
- `repository.owner.login` = `"org-A"` (so `Shipit.github(organization: 'org-A')` is selected and the HMAC computed with org-A's own secret validates), while
- `repository.full_name` = `"org-B/victim-repo"` (a completely different tenant's repository).

The equality that is supposed to hold — *the organization whose credential authenticated the request* == *the repository the request is permitted to write to* — is broken: `Shipit.github(organization: repository_owner).webhook_secret` authenticates org-A, but `Repository.from_github_repo_name(payload['repository']['full_name'])` acts on org-B.

### Impact Explanation
Once signature verification passes, `Webhooks.for_event(event)` dispatches the raw payload to handlers unconditionally [6](#0-5) , all of which trust `full_name`/team data from the body:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for the matched branch/stack of the forged `full_name`, i.e. it can force a `GithubSyncJob` against another org's stack [7](#0-6) .
- `StatusHandler` writes a commit status (`state`, `context`, `target_url`) onto commits by `sha` regardless of repository ownership [8](#0-7) , which can flip a deployability/CI gate that Shipit's deploy pipeline relies on to authorize a ship.
- `MembershipHandler` creates/deletes memberships on `Team`s keyed by GitHub `organization.login`/`team.id` taken directly from the body [9](#0-8) , which can be forged similarly since nothing ties the authenticating org to the `organization`/`team` fields consumed here either.

This crosses the "cross-repository writes" / "unauthorized deploy" bar because a forged, signature-valid push event can drive `GithubSyncJob` and downstream deploy machinery for a stack belonging to an organization the attacker does not control, and a forged status event can manipulate the commit-status gate that decides deployability, both using only a secret the attacker legitimately possesses for their *own*, unrelated tenant organization.

### Likelihood Explanation
This requires an attacker to be an onboarded tenant on a Shipit instance running the **multi-organization** GitHub config (i.e., they legitimately know one org's `webhook_secret`), and for the target repository to also be configured on the same shared Shipit instance. This is exactly the deployment topology `docs/setup.md` documents as supported ("Using Multiple GitHub Applications"), so it isn't a hypothetical misconfiguration — it's the intended multi-tenant use case, and no additional session/API-token/GitHub write access is needed beyond a webhook secret the attacker is entitled to hold for their own org.

### Recommendation
Bind the field used to select/verify the signing secret to the same field used for record resolution: verify the signature using the organization/app derived from `repository.full_name`'s owner segment (not the separate `repository.owner.login`/`organization.login` fields), or, after successful signature verification, re-derive `repository_owner` from `full_name` and assert it matches the org whose secret validated, rejecting the request if they diverge. Apply the same owner/full_name consistency check inside `MembershipHandler`, which trusts `organization.login` independently of anything checked in `verify_signature`.

### Proof of Concept
As an onboarded org-A administrator (knows org-A's `webhook_secret`):
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(org_A_webhook_secret, body)>

body = {
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-A" },      # used only for verify_signature routing
    "full_name": "org-B/victim-repo"    # used by Handler#repository_name / Repository.from_github_repo_name
  }
}
```
`WebhooksController#verify_signature` calls `Shipit.github(organization: 'org-A')` (from `repository.owner.login`), computes the HMAC with org-A's own secret, and it matches — the request passes with `head(422)` never triggered. `PushHandler#process` then resolves `stacks` via `Repository.from_github_repo_name('org-B/victim-repo')` and calls `sync_github(expected_head_sha: params.after)` on org-B's stack, an organization the requester does not own or administer.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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
```
