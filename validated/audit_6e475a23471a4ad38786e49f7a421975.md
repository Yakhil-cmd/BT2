### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but handlers act on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports multi-tenant GitHub App configuration where each organization has its own `webhook_secret` [1](#0-0) . The webhook controller selects *which* organization's secret to verify the HMAC signature with by reading `repository.owner.login` out of the still-untrusted JSON body [2](#0-1) [3](#0-2) . Once the HMAC check passes, every event handler instead resolves the target repository/stack from a *different, independently-controlled* field of the same body: `repository.full_name` [4](#0-3) . Nothing binds these two fields together, so an attacker who legitimately administers one onboarded organization (and therefore knows/controls that organization's webhook secret) can forge a signed request that authenticates as "their" organization while directing the payload's `repository.full_name` at a completely different, victim organization's stack.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/organization config to check the signature against using attacker-supplied payload data:
```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

`Shipit.github(organization:)` looks up a per-organization `webhook_secret` from `secrets.github` when multiple GitHub orgs are configured (`github_organizations`) [1](#0-0) .

Once `verify_signature` passes, `WebhooksController#create` dispatches the *same raw JSON body* to the event handler [6](#0-5) . Every handler resolves the affected repository/stack purely from `repository.full_name`:
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`repository.owner.login` (used to choose the verifying secret) and `repository.full_name` (used to choose the acted-upon repository) are two unrelated leaf strings inside the same JSON object. The HMAC only proves "whoever computed this signature knows the secret associated with organization X" — it says nothing about which repository the rest of the JSON body should reference. Because Shipit lets `repository_owner` steer which secret is used for verification, an attacker who is an authenticated admin of their own onboarded organization ("attacker-org", with a known `webhook_secret`) can craft a payload like:
```json
{
  "repository": {
    "owner": {"login": "attacker-org"},
    "full_name": "victim-org/private-repo"
  },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
sign it with `attacker-org`'s own secret, and POST it directly to `/github/webhooks`. `verify_signature` resolves `repository_owner == "attacker-org"`, fetches `attacker-org`'s legitimately-known secret, and the HMAC check passes. `PushHandler#process` then looks up stacks for `victim-org/private-repo` and invokes `stack.sync_github(expected_head_sha: params.after)` [7](#0-6)  for a repository the attacker never had credentials for.

This breaks exactly the binding the rules call out: "an organization that authenticated versus the repository that is written."

### Impact Explanation
An attacker who legitimately controls only one onboarded, low-trust organization can forge webhook events that are processed as if they came from a completely different, higher-privilege organization's repository — without ever knowing that victim organization's `webhook_secret`, GitHub App private key, or possessing any Shipit account/API token. Depending on the handler reached (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.), this can force `GithubSyncJob` to re-sync a victim stack against an attacker-chosen `expected_head_sha`, inject forged commit statuses/check-runs that gate the victim's merge queue and continuous-deployment logic, or manipulate `Membership`/`Team` records tied to authorization (`Shipit.github_teams`). Any of these can cascade into an unauthorized deploy/merge on a repository the attacker does not control, satisfying the "cross-repository writes" / "unauthorized deploy" criteria.

### Likelihood Explanation
Exploitability only requires that Shipit be configured for more than one GitHub organization (multi-tenant `secrets.github` keyed by org, i.e., `github_default_organization` present and `github_organizations` returning more than one org) and that the attacker be a legitimate, unprivileged admin of one of those onboarded organizations — a realistic multi-tenant deployment scenario, and not a privileged Shipit account. No cryptographic primitive is broken; the attacker signs with their own genuine secret.

### Recommendation
Do not let attacker-supplied payload fields select the verification key independently of the field(s) later trusted for authorization decisions. Either:
- Verify against the secret of the organization that owns the *resolved* `Repository`/`Stack` (looked up via `repository.full_name`) rather than `repository.owner.login`, or
- After signature verification, assert `repository.owner.login` matches the owner encoded in `repository.full_name`, and reject the webhook if the two disagree, or
- Bind webhook secrets at the `Repository` level (not the raw payload-declared org) so the key used for verification is always the one associated with the actual target resource.

### Proof of Concept
1. Onboard/administer `attacker-org` in the target Shipit instance (a real, low-privilege GitHub organization with its own configured `webhook_secret` in `secrets.github`), alongside a separate, unrelated `victim-org` that also has stacks in the same Shipit instance.
2. Craft a JSON body:
```json
{
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/private-repo"},
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(attacker-org_webhook_secret, body)>`.
4. `POST /github/webhooks` with `X-Github-Event: push`, the above body, and the computed signature header.
5. `verify_signature` resolves `repository_owner = "attacker-org"`, verifies successfully using attacker-org's own secret [8](#0-7) .
6. `PushHandler` resolves stacks via `repository.full_name = "victim-org/private-repo"` [4](#0-3)  and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack [7](#0-6) , despite the attacker never possessing `victim-org`'s webhook secret or GitHub access.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
