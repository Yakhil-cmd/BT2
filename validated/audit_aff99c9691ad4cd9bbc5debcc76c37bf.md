This confirms the core trust-binding mismatch. `WebhooksController#verify_signature` selects the HMAC secret using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), and validates the signature only against that organization's `webhook_secret` [1](#0-0) . But the handlers that actually mutate state (`Handler#stacks` / `Handler#repository_name`, used by `PushHandler#process` and reachable by every event handler) resolve the target `Repository`/`Stack` from a completely different, unverified field: `payload.dig('repository', 'full_name')` [2](#0-1) , then `Repository.from_github_repo_name` splits that string on `/` to find `owner`/`name` [3](#0-2) .### Title
Cross-organization webhook forgery — repository written is not bound to the organization whose signature was verified - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to use for HMAC validation based on `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body, then only checks the signature against that one field. The event handlers that actually mutate application state resolve the target `Repository`/`Stack` from an entirely different, still-unverified field (`repository.full_name`). Nothing ties "the organization whose secret produced a valid signature" to "the repository whose stack gets written to."

### Finding Description
`verify_signature` computes:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and verifies the HMAC using `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) .

Shipit explicitly supports multiple GitHub organizations in a single instance, each with its own `webhook_secret`, keyed by organization name in `secrets.github` [4](#0-3) [5](#0-4) .

Once the signature check passes (using OrgA's secret because `repository.owner.login` == OrgA), the request reaches `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [6](#0-5) . Every handler resolves its target stacks via `Handler#stacks`/`#repository_name`, which reads `payload.dig('repository', 'full_name')` — a completely different field, never covered by the signature-selection logic — and looks it up with `Repository.from_github_repo_name` [2](#0-1) [3](#0-2) .

`PushHandler#process` uses this to call `stack.sync_github(expected_head_sha:)` on every matching stack [7](#0-6) , and `StatusHandler#process` uses `params.sha` (also attacker-controlled, unbound to the verified organization) to attach a forged CI status to any commit matching that sha via `commit.create_status_from_github!(params)` [8](#0-7) .

Concretely: if the operator's Shipit instance manages both `OrgA` and `OrgB` (as the multi-org docs describe), an attacker who controls (or is an admin of) the GitHub App/webhook installed on `OrgA` can send a webhook whose `repository.owner.login`/`organization.login` is `OrgA` (so it authenticates with `OrgA`'s `webhook_secret`) but whose `repository.full_name` is set to `OrgB/some-repo`. The signature check passes for `OrgA`; the handler then writes to `OrgB`'s stacks/commits — an organization boundary the attacker was never authenticated for.

The binding broken: **organization that authenticated (`repository.owner.login` used for signature selection) ≠ repository that is written (`repository.full_name` used by handlers)**.

### Impact Explanation
Via the `status` event, an attacker can inject an arbitrary, forged `CommitStatus` (state/context/target_url of their choosing) onto any commit-sha of a stack belonging to an organization they were never authorized for. Shipit's merge-queue/deploy safety logic depends on blocking/required statuses (see CHANGELOG: "Added blocking statuses… will prevent deploy even if they were reported on any of the commits") — forging a passing status for a victim organization's stack can help clear the way for an unauthorized deploy on that stack. Via the `push` event, the attacker can also force `Stack#sync_github` to run against a victim stack. This crosses an organization/repository trust boundary purely from a webhook forged with a different, unrelated organization's own secret — matching the "Critical: cross-repository writes / unauthorized deploy" bar.

### Likelihood Explanation
Exploitability requires the attacker to already control (or have admin rights over) a GitHub App/organization that the Shipit operator has legitimately configured in `secrets.github` for a *different* purpose (e.g., a secondary organization the same instance manages). This is a realistic deployment shape given Shipit's explicit multi-org support and documented config format. No GITHUB_TOKEN, ApiClient token, or session is needed — only the ability to produce a validly-signed webhook for one configured organization, which any admin of that org's own GitHub App can do by design (viewing/regenerating that org's own webhook secret is a normal admin action, not privilege escalation into Shipit itself).

### Recommendation
Bind the signature-verification identity to the same field used for repository/stack resolution. Concretely, require `repository.full_name` (or `repository.owner.login` used by `Handler#repository_name`) to match the organization whose secret validated the signature, and reject the webhook if they differ — i.e., verify the invariant explicitly rather than trusting two independently-read fields to agree, analogous to the recommended pattern in the report of explicitly checking the required invariant instead of assuming it.

### Proof of Concept
1. Shipit instance configured with two organizations in `secrets.github`: `OrgA` (attacker controls the installed GitHub App) and `OrgB` (victim, has a stack tracking `OrgB/victim-repo`).
2. Attacker computes `X-Hub-Signature` using `OrgA`'s `webhook_secret` (which they legitimately possess as `OrgA`'s app owner) over a JSON body:
```json
{
  "organization": {"login": "OrgA"},
  "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo"},
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "required-ci-check"
}
```
3. POST to `/webhooks` with header `X-Github-Event: status` and the computed signature.
4. `verify_signature` resolves `repository_owner` to `OrgA`, verifies successfully against `OrgA`'s secret [9](#0-8) .
5. `StatusHandler#process` looks up commits by `sha` (global across all stacks) and calls `commit.create_status_from_github!(params)`, writing a forged status onto `OrgB`'s commit [8](#0-7) , even though the request was never authenticated for `OrgB`.

### Citations

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
