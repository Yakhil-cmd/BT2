### Title
Webhook signature verification key is selected from an unverified field, decoupled from the repository actually mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization `webhook_secret` to validate the HMAC signature against using `repository_owner`, a value taken from the raw JSON body itself (`repository.owner.login` or `organization.login`). Separately, event handlers resolve the repository/stack to act on using a different JSON field from the same payload, `repository.full_name`. Because the signature check only proves "this body was signed with organization X's secret" and never asserts that `repository.owner.login` and `repository.full_name` refer to the same organization, an attacker who legitimately controls (or knows the webhook secret of) *any* organization configured in Shipit's multi-org GitHub config can forge a payload that is validly signed for their own organization but whose `repository.full_name` points at a *different* organization's tracked repository/stack.

### Finding Description
`repository_owner` is used purely to pick the verification key:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` resolves the org-specific `webhook_secret` from `secrets.github` and constructs/memoizes a `GitHubApp` bound to that secret: [2](#0-1) 

`GitHubApp#verify_webhook_signature` only checks the HMAC against `@webhook_secret`, the secret configured for the org chosen above — it never checks that this org matches anything else in the payload: [3](#0-2) 

Once `create` proceeds, every `Handler` resolves the *actual* target repository from a **different** field of the same JSON body, `repository.full_name`, with no cross-check against `repository_owner`/the org that was authenticated:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`PushHandler`, for example, directly triggers a sync (and, with continuous deployment enabled, a downstream deploy) for whatever stack is resolved this way: [5](#0-4) 

**The broken binding**: `organization authenticated (repository_owner used to pick webhook_secret)` should equal `organization whose repository/stack is written to (repository.full_name)`, but the code never enforces this equality — both are independently attacker-supplied fields inside the same signed body, and the HMAC only certifies "signed by owner-of-secret," not "internally consistent." This is the same root-cause pattern as the `EnsureClosure` bug: a stateful/keyed check that is satisfied for one identity is silently reused/trusted for a different, unverified identity in the same operation.

### Impact Explanation
An attacker who is an administrator of, or otherwise possesses the `webhook_secret` for, any single organization onboarded into a multi-tenant Shipit instance (a normal, unprivileged condition relative to *other* tenants' repositories) can forge webhook events that are validly signed under their own org's secret but whose `repository.full_name`/`branch`/`sha` fields target a stack belonging to a completely different organization they have no access to. Depending on the event type this can:
- Force `GithubSyncJob`/`sync_github` to run against a victim stack with an attacker-chosen `after` sha via the `push` handler, which — combined with continuous deployment — can result in an unauthorized deploy of an attacker-chosen commit.
- Inject forged `status`/`check_suite` results for a victim commit, which deploy-gating logic elsewhere may treat as legitimate CI signal.
- Create/archive `ReviewStack`s or manipulate `pull_request`/`membership` state for a repository outside the attacker's authorized organization.

This crosses the "cross-repository writes / unauthorized deploy" boundary called out as Critical impact.

### Likelihood Explanation
Likelihood is Low: it requires the Shipit deployment to use the multi-organization GitHub config (`github_default_organization` non-nil, multiple orgs in `secrets.github`) and requires the attacker to legitimately control one of those onboarded organizations' `webhook_secret` while targeting another tenant's repository — a realistic but non-default multi-tenant configuration.

### Recommendation
After signature verification succeeds, cross-check that the organization used to select the verification key (`repository_owner`) actually matches the owner embedded in `repository.full_name` (and `organization.login` where present) before dispatching to any handler; reject the request (422) on mismatch. Handlers should also independently assert that the resolved `Repository`'s `owner` equals the authenticated `repository_owner` rather than trusting `repository.full_name` unconditionally.

### Proof of Concept
1. Shipit is configured with multiple GitHub orgs, e.g. `secrets.github = { "attacker-org" => {webhook_secret: S1, ...}, "victim-org" => {webhook_secret: S2, ...} }`, and `victim-org/victim-repo` is a tracked `Repository` with an active `Stack` (`continuous_deployment: true`).
2. Attacker is an admin of `attacker-org` and therefore knows `S1` (their own legitimately configured GitHub App webhook secret).
3. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": {"login": "attacker-org"},
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(S1, body)` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner` = `"attacker-org"`, loads `attacker-org`'s `GitHubApp` (secret `S1`), and the HMAC check passes because the attacker legitimately knows `S1`.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack — an operation the attacker was never authorized to trigger for `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
