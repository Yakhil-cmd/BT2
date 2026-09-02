### Title
Cross-organization write via organization/repository binding mismatch in webhook signature verification - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment (multiple GitHub Apps configured under distinct organization keys in `secrets.yml`, as documented in `docs/setup.md`), the webhook signature is verified using the GitHub App/secret selected from the payload's `repository.owner.login` (or `organization.login`) field, while the code that actually mutates state (finds the `Repository`/`Stack` to sync/write to) uses the unrelated `repository.full_name` field from the same payload. Because these two fields are never cross-checked against each other, an attacker who holds a valid webhook secret for *any* one organization configured on the instance can forge a payload whose `repository.owner.login` matches their own org (so it authenticates) but whose `repository.full_name` names a repository belonging to a *different* organization configured on the same instance, causing writes (e.g., triggering `GithubSyncJob`, archiving/unarchiving review stacks) against a repository/org the attacker was never authorized for.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to validate the signature against based on `repository_owner`, which is read straight out of the untrusted JSON payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks the org up in `secrets.github` by that string and returns its `GitHubApp`, whose `webhook_secret` is then used to HMAC-verify the raw body: [3](#0-2) [4](#0-3) 

Once the signature validates, `WebhooksController#create` dispatches the *entire, attacker-controlled* JSON to the registered handlers with no further tie to `repository_owner`: [5](#0-4) 

Handlers determine which `Repository`/`Stack` to act on using a completely different field, `repository.full_name`, via `Handler#repository_name` / `Handler#stacks`: [6](#0-5) 

and `Repository.from_github_repo_name` splits `owner/name` out of that string with no relation to the field used for signature selection: [7](#0-6) 

`PushHandler#process`, for example, uses this to call `stack.sync_github(expected_head_sha:)` on any stack matching the branch of whatever repository `full_name` claims: [8](#0-7) 

Pull-request handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler`, etc.) likewise resolve the target `Repository`/`ReviewStack` from `params.repository.full_name` independently of `repository_owner`, and then call state-mutating operations (`find_or_create!`, `archive!`, `unarchive!`) on it: [9](#0-8) 

This is the structural analog of the reported `_FB721Approve` bug: the check binds authorization to one identity (`msgSender_`/`_isApprovedForAll[msgSender_][...]` in the report; here, the org selected by `repository.owner.login` used to pick the verifying secret) while the effectful operation acts on a *different* identity (the approved `id_`'s actual owner in the report; here, the repository/stack resolved from `repository.full_name`). Nothing enforces `repository.owner.login == repository.full_name.split('/').first`.

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written." An org admin who legitimately controls a GitHub App/webhook secret for Org A on a shared Shipit instance can forge webhook deliveries that pass signature verification (using Org A's secret) yet cause GithubSyncJob syncs, review-stack creation, or review-stack archival/unarchival against Org B's stacks — an unauthorized cross-repository/cross-organization state change performed through the engine's own trust logic, without needing Org B's webhook secret, GitHub App private key, or any Shipit session/API token. This matches the "cross-repository writes" / unauthorized-deploy-trigger class of High/Critical impact in scope, since `sync_github` can advance the recorded HEAD of an unrelated stack and review-stack handlers can create/archive infrastructure for a repository the attacker does not own.

### Likelihood Explanation
Requires: (1) the instance to be configured in the documented multi-organization mode (`docs/setup.md`, "Use this configuration schema if you are configuring multiple Github applications for different Github organizations"), and (2) the attacker to be a legitimate holder of a webhook secret for at least one of the configured organizations (e.g., an org admin who installed their own GitHub App on the same shared Shipit instance). Given that this multi-tenant configuration is an explicitly supported/documented deployment mode, and the only requirement is control of one org's own webhook secret (not a privileged Shipit account), likelihood is High for any deployment that actually hosts multiple organizations behind one Shipit instance.

### Recommendation
In `WebhooksController#verify_signature`, after verifying the signature, re-derive (or cross-check) the organization actually used for signing against the organization embedded in `repository.full_name` (and any other repository fields the handlers will use), rejecting the webhook if they don't match:

```diff
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
+ verified &&= repository_owner_matches_full_name?
  head(422) unless verified
  ...
end

+def repository_owner_matches_full_name?
+  full_name = params.dig('repository', 'full_name')
+  return true if full_name.blank?
+  full_name.split('/', 2).first&.casecmp?(repository_owner)
+end
```

Alternatively, scope handler lookups so that `Repository.from_github_repo_name` (and all handler `repository`/`stacks` resolution) is constrained to the organization that verified the request, rather than trusting `repository.full_name` unconditionally.

### Proof of Concept
Conceptual PoC (requires a multi-org `secrets.yml` with orgs `acme` and `victimorg`, and attacker controlling `acme`'s webhook secret):

1. Attacker computes `X-Hub-Signature` for a crafted JSON body using `acme`'s known `webhook_secret`.
2. Attacker sets the payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "full_name": "victimorg/victim-repo",
    "owner": { "login": "acme" }
  }
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "acme")` and validates the signature successfully (attacker's own secret).
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victimorg/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on `victimorg`'s stack — a write the attacker was never authorized to trigger.

Note: I could not execute this end-to-end in a live multi-org environment from static analysis alone; the trust-boundary mismatch (verification key selection vs. resolution key for writes) is confirmed directly from the cited source, but real-world exploitability additionally depends on operators actually running Shipit in the documented multi-organization mode with more than one org's webhook secret in play.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
```
