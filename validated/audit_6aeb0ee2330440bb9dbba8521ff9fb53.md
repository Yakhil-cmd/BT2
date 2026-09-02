## Title
Webhook organization used for signature verification is not bound to the repository the payload writes to, enabling cross-tenant webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
Shipit supports multi-tenant GitHub App configuration, where each GitHub organization has its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's secret to verify the HMAC signature against using `repository_owner`, a field taken from the payload itself, while the actual event handlers select which `Stack`/`Repository` to mutate using a *different* field, `repository.full_name` [2](#0-1) . Because nothing cross-validates that `repository.owner.login` (used for authentication) actually corresponds to the owner encoded in `repository.full_name` (used for authorization/target-selection), an attacker who legitimately controls a GitHub App installation for **their own** organization (Org A, with its own valid `webhook_secret`) can sign an arbitrary payload and set `repository.full_name` to a **victim** organization's tracked repository (Org B), causing Shipit to act on Org B's stack as if it came from a trusted GitHub webhook.

### Finding Description
`verify_signature` computes the organization to check the signature against directly from the untrusted payload:
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
``` [3](#0-2) 

The signature check only proves that *some* configured organization's secret was used to sign the raw body — it does not prove that the `full_name` referenced deeper in the same payload actually belongs to that organization. `Shipit.github(organization:)` resolves a per-organization `GitHubApp` instance keyed by an arbitrary org name supplied in the payload, drawn from `secrets.github`, which is explicitly designed to hold multiple organizations each with their own `webhook_secret` [1](#0-0) .

After signature verification passes, `create` dispatches the full, attacker-controlled JSON body to the relevant handler:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [4](#0-3) 

Every handler resolves the target `Stack`s purely from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

For example `PushHandler` will trigger a `sync_github` against any stack whose repository matches `full_name`, regardless of which organization's secret signed the request:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

The binding that should hold is:
`organization whose secret authenticated the request == organization that owns the repository being acted upon`

But the code only enforces:
`organization whose secret authenticated the request == payload["repository"]["owner"]["login"]` (attacker-controlled)
and separately:
`stack selected == payload["repository"]["full_name"]` (also attacker-controlled, and never checked against the owner field used for authentication)

Since both fields live in the same attacker-crafted JSON body, an attacker with a legitimate GitHub App/webhook for their own org (Org A) can set `repository.owner.login = "org-a"` (so the signature check passes using Org A's own secret) while setting `repository.full_name = "org-b/victim-repo"` (so the handler acts on Org B's stack).

### Impact Explanation
This breaks the authentication boundary of the webhook endpoint in multi-organization Shipit deployments: any organization onboarded to Shipit (with its own legitimately configured GitHub App and `webhook_secret`) can forge `push`, `status`, `pull_request`, `check_suite`, and `membership` events targeting a **different** organization's stacks. Concretely this allows: (a) `PushHandler` to trigger `GithubSyncJob`/`sync_github` for a stack owned by another org, pulling and appending fabricated GitHub commit history via the app's own GitHub credentials, feeding attacker-influenced commit metadata (author/committer) into `User.find_or_create_from_github`; (b) `StatusHandler` to inject fake commit statuses on a victim stack's commits, which downstream can affect CI gating for merges/deploys; (c) `MembershipHandler`/`PullRequest` handlers acting on data scoped to the victim org. This crosses the "organization authenticated vs. repository written" trust boundary called out in scope and can influence unauthorized deploy-adjacent state (commit sync, CI status, merge queue signals) for a repository the attacker does not control, using only their own legitimately obtained per-org webhook secret rather than any privileged Shipit credential.

### Likelihood Explanation
Exploitability requires a Shipit deployment configured with multiple GitHub organizations sharing one instance (a supported and documented configuration, per `Shipit.github_organizations`/`github_app_config` in `lib/shipit.rb`) and requires the attacker to control (or have compromised) a webhook secret for at least one onboarded organization — a normal, non-privileged onboarding a legitimate tenant would have, not an admin/API-token/session credential. Constructing the payload only requires knowledge of the public JSON webhook schema (`repository.owner.login` vs `repository.full_name`), no other secret is needed.

### Recommendation
In `WebhooksController#verify_signature` (or in `Webhooks::Handlers::Handler`), validate that the organization used to authenticate the signature matches the owner portion of `repository.full_name`, rejecting the event (HTTP 422) on mismatch. More robustly, resolve the target `Stack`/`Repository` by the authenticated organization rather than by an unauthenticated payload field, e.g. by scoping `Repository.from_github_repo_name` lookups to repositories owned by `repository_owner`, and reject any payload whose `repository.full_name` owner segment does not equal `repository.owner.login`/`organization.login` used for verification.

### Proof of Concept
Assume a Shipit instance configured with two orgs in `secrets.github`: `org-a` (attacker-controlled GitHub App, webhook secret known to attacker) and `org-b` (victim, with a tracked `Repository` `org-b/victim-repo` and an active `Stack`).

1. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `org-a`'s own legitimately-provisioned `webhook_secret` over the raw JSON body.
3. Attacker POSTs to `/github/webhooks` (`WebhooksController#create`) with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "org-a")` (derived from `repository.owner.login`) and the signature validates successfully because it was signed with `org-a`'s real secret.
5. `create` dispatches the parsed payload to `PushHandler`, whose `repository_name` resolves to `"org-b/victim-repo"` — a repository belonging to the victim org, unrelated to the authenticating org — and enqueues `sync_github`/`GithubSyncJob` against the victim's `Stack`, as confirmed by `PushHandler#process` and `Handler#stacks`/`#repository_name` [5](#0-4) [2](#0-1) .

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
