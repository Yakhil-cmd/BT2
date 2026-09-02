### Title
Webhook signing-organization is decoupled from the repository the payload actually mutates, enabling cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the **same, attacker-supplied JSON body** it is about to validate. Every downstream `Webhooks::Handlers::Handler` subclass, however, resolves the repository/stack that gets *acted upon* using a different field of that same body: `repository.full_name` (`Handler#repository_name`) [1](#0-0) . Nothing ties these two lookups together, so an attacker who legitimately controls a webhook secret for one GitHub organization configured in a multi-tenant Shipit instance can forge a signed payload whose `repository.owner.login` matches their own org (so the signature check passes) while `repository.full_name` names a stack that belongs to a *different* organization in the same Shipit deployment.

### Finding Description
Verification path:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`Shipit.github(organization:)` resolves the per-org config (and thus the per-org `webhook_secret`) purely from this attacker-controlled `repository_owner` string:
```ruby
def github(organization: github_default_organization)
  ...
  config = github_app_config(organization)
  raise GithubOrganizationUnknown, organization if config.nil?
  @github[organization] ||= GitHubApp.new(organization, config)
end
``` [3](#0-2) 

`verify_webhook_signature` only checks that the raw body's HMAC matches *whatever secret was looked up for that organization*; it never confirms that the same organization owns the repository the payload is about to modify: [4](#0-3) 

Once verification passes, `create` dispatches the raw params to the handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [5](#0-4) 

Every handler locates its target stack via `repository.full_name`, independent of `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [1](#0-0) 

**The broken binding, as an equality:**
`organization whose secret authenticated the request (repository.owner.login)` **≠** `organization/repository the handler acts on (repository.full_name)`.

Before the attack, these two are implicitly assumed equal because GitHub itself always signs a payload with the secret of the repository named in that same payload. Shipit never enforces this invariant server-side. An attacker who is a legitimate webhook-sender for OrgA (e.g. has push/admin access to any repo Shipit tracks under OrgA and can therefore trigger or replay OrgA-signed events, or otherwise possesses OrgA's `webhook_secret` value) can sign a body where `repository.owner.login = "OrgA"` (so `verify_webhook_signature` uses OrgA's secret and succeeds) but `repository.full_name = "OrgB/victim-repo"` (so the handler operates on OrgB's stack). This is only exploitable in multi-organization deployments, which Shipit explicitly supports (`Shipit.github_organizations`, `Shipit.github_app_config`) [6](#0-5) .

### Impact Explanation
With a forged, "validly signed" webhook for OrgB's repository, an attacker who only controls OrgA can, without any credentials on OrgB:
- Force `PushHandler` to enqueue `GithubSyncJob` and sync arbitrary commits into OrgB's tracked branch state [7](#0-6) .
- Inject fabricated commit `status`/`check_suite` events tied to OrgB commits.
- Drive `PullRequest` handlers to archive/create/unarchive OrgB `ReviewStack`s [8](#0-7) .

These are cross-organization writes into a repository/stack the attacker does not control, satisfying the Critical "cross-repository writes" impact bar.

### Likelihood Explanation
Requires a Shipit instance configured with more than one GitHub organization (a documented, supported configuration) and requires the attacker to be a legitimate webhook sender for at least one of those organizations (e.g. any collaborator able to trigger GitHub events on a repo under OrgA, or anyone who has captured OrgA's `webhook_secret` through normal, non-privileged means such as being an org member with webhook settings visibility). No Shipit session, API token, or GitHub App private key is needed—only the ability to produce/replay a body whose signature is valid for the org named inside that same body.

### Recommendation
In `WebhooksController#verify_signature`, after computing `github_app` from `repository_owner`, also verify that `params.dig('repository', 'full_name')` (or `organization.login`) is actually owned by that same `repository_owner` before dispatching to handlers—i.e., reject the payload if `repository.full_name.split('/').first != repository_owner`. Alternatively, resolve the target `Repository`/`Stack` first and derive the verifying organization from the *persisted* repository's owner rather than from attacker-supplied payload fields.

### Proof of Concept
1. Shipit is deployed with two configured GitHub orgs, `OrgA` and `OrgB`, each with its own `github.webhook_secret` (as in the supported multi-org secrets schema) [9](#0-8) .
2. Attacker knows/controls `OrgA`'s `webhook_secret` (e.g., is a member able to view/rotate OrgA's app webhook secret, or replays a genuine OrgA webhook delivery).
3. Attacker crafts JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac(OrgA_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner = "OrgA"`, loads OrgA's `GitHubApp`, and `verify_webhook_signature` succeeds because the signature genuinely matches OrgA's secret [10](#0-9) .
6. `create` parses the body and calls `PushHandler`, which resolves `stacks` via `repository.full_name = "OrgB/victim-repo"` and enqueues `GithubSyncJob` for OrgB's stack [7](#0-6) , even though the request was never signed by OrgB.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-50)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```
