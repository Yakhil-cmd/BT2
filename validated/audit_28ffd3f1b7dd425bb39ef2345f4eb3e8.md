## Finding: Cross-organization webhook spoofing due to mismatched identity fields used for signature verification vs. repository targeting

### Title
Cross-organization GitHub webhook forgery via mismatched `repository.owner.login` (signature selection) and `repository.full_name` (target lookup) - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`), read directly from the untrusted JSON body. Every event handler, however, resolves the actual `Repository`/`Stack` to act on using a *different* field of the same payload: `repository.full_name`. Because these are independent, attacker-controlled fields inside a single JSON document, a webhook that is validly signed for organization A can carry a `repository.full_name` pointing at a stack belonging to organization B, and every handler will act on B's data as if the request were authenticated for B.

### Finding Description [1](#0-0) 

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
``` [2](#0-1) 

`Shipit.github(organization: repository_owner)` selects a per-organization `GitHubApp` (and its `webhook_secret`) in multi-org deployments, a documented and supported configuration: [3](#0-2)  and `docs/setup.md` "Using Multiple Github Applications". The signature is checked only against that one organization's secret via `verify_webhook_signature`: [4](#0-3) .

Once the request passes this check, the raw JSON body is dispatched unmodified to the registered handlers: [5](#0-4) . Every handler resolves its target repository via a completely different field, `repository.full_name`, not `repository.owner.login`: [6](#0-5) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

For example, `PushHandler` triggers a GitHub sync for whichever stack matches `repository.full_name`: [7](#0-6) . `StatusHandler` is worse: it doesn't even use `stacks`/`repository_name` — it looks up `Commit.where(sha: params.sha)` globally across the entire installation and writes a GitHub status directly onto the matching commit, with zero repository/organization scoping at all: [8](#0-7) .

**The binding that is broken:** the organization whose secret authenticated the request (`repository.owner.login` / `organization.login`) is not the same binding checked against the repository that is actually written to (`repository.full_name`, or in `StatusHandler`'s case, no binding check whatsoever). This is the exact class of bug described in CVE-2022-27782 — a security-relevant identity used to establish trust for a connection/session is not re-checked before that trust is reused for a materially different operation.

### Impact Explanation
An attacker who can obtain (or is legitimately entitled to, e.g. as an admin of *any one* organization configured on a multi-org Shipit instance) a valid webhook signature for organization A can forge:
- A `push` event whose `repository.full_name` points at organization B's stack, forcing `GithubSyncJob` to run against B's repository/commit history.
- A `status` or `check_suite` event with an arbitrary `sha`, injecting a fabricated "success" CI status onto a commit belonging to any stack tracked anywhere in the Shipit instance (`StatusHandler` performs no owner check at all), which can affect merge-queue/mergeability decisions and downstream deploy/rollback safety gating that depend on commit statuses.

This is a cross-repository/cross-organization write triggered through an authentication boundary that was validated for a different tenant than the one being mutated.

### Likelihood Explanation
Exploitability depends on the attacker being able to produce one valid `X-Hub-Signature` for any organization configured in the Shipit instance's multi-org `github` secrets. This is realistic in Shopify/enterprise-style multi-tenant Shipit deployments, where a legitimate contributor/admin of one small onboarded organization can obtain a workable signature for that org's secret and craft the cross-referencing payload, without ever needing write access, a Shipit session, or credentials belonging to the victim organization.

### Recommendation
- In `WebhooksController#verify_signature`, derive the organization used for secret selection from the same field the handlers use to resolve the target repository (`repository.full_name`'s owner segment), and reject the request if `repository.owner.login`/`organization.login` disagree with the owner segment of `repository.full_name`.
- In `Handlers::Handler`/`StatusHandler`/`CheckSuiteHandler`, scope all repository/commit lookups to the organization that was actually verified for the request (e.g., pass the verified organization down to handlers and filter `Commit`/`Stack` lookups by it), rather than trusting `repository.full_name` unconditionally.

### Proof of Concept
Assume a multi-org Shipit instance configured with `OrgA` (attacker-controlled/known secret) and `OrgVictim` (target), per `test/dummy/config/secrets_double_github_app.yml`-style config. The attacker sends:

```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<computed with OrgA's webhook_secret>

{
  "sha": "<sha of a commit tracked in a OrgVictim stack>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgVictim/some-repo" }
}
```

`verify_signature` resolves `repository_owner` to `"OrgA"`, looks up `Shipit.github(organization: "OrgA")`, and the HMAC verifies successfully against `OrgA`'s secret. `StatusHandler#process` then runs `Commit.where(sha: params.sha)` — with no reference to `"OrgA"` or `"OrgVictim"` at all — and writes the forged "success" status onto the `OrgVictim` commit. [8](#0-7)

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
