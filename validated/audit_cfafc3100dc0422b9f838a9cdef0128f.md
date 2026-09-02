### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but every event handler acts on the unrelated `repository.full_name` field — allowing cross-repository event injection - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to validate the HMAC against using the attacker-influenced JSON field `repository.owner.login` (with an `organization.login` fallback). Once the signature check passes, the raw, fully attacker-controlled JSON body is dispatched unmodified to every registered `Shipit::Webhooks::Handlers::Handler`, which instead resolve the target `Repository`/`Stack` using a **different** field, `repository.full_name` (`Handler#repository_name`). Nothing ties these two fields together, so the organization whose credentials authenticate the request is not the repository whose state gets mutated.

### Finding Description
In the controller: [1](#0-0) 

`verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(...)`, where: [2](#0-1) 

`repository_owner` is read straight out of the untrusted JSON body (`params.dig('repository', 'owner', 'login')`), before the signature over that same body has even been validated.

Once `head(422)` is not triggered, `create` fans the parsed body out to every handler for the event: [3](#0-2) 

Every handler resolves its target repository/stack independently via `Handler#repository_name`/`#stacks`, which reads a *different* JSON field, `repository.full_name`: [4](#0-3) 

`Repository.from_github_repo_name` simply splits this string and does a DB lookup with no cross-check against `repository.owner.login`: [5](#0-4) 

Crucially, `verify_webhook_signature` treats a missing per-organization secret as an automatic pass: [6](#0-5) 

Because Shipit supports multiple organizations, each with its own independently configured `webhook_secret` (`Shipit.github_app_config`/`TOP_LEVEL_GH_KEYS`): [7](#0-6) 

any organization onboarded to this Shipit instance **without** a configured `webhook_secret` becomes a skeleton key: an attacker sets `repository.owner.login` to that unsecured organization's name (satisfying `verify_signature` unconditionally, since `webhook_secret` is blank) while setting `repository.full_name` to an arbitrary **other** organization's repository whose stacks they don't control. The equality the code implicitly assumes — `organization that authenticated == repository that is written` — is never enforced, so it can be broken by decoupling the two fields.

### Impact Explanation
Handlers act on the mismatched target repository's `Stack`/`Commit` records with no further authorization:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` on stacks belonging to the victim repository, using an attacker-supplied SHA [8](#0-7) .
- `StatusHandler` writes forged commit statuses (`create_status_from_github!`) onto the victim repo's commits [9](#0-8) , which can influence CI-gated auto-deploy/merge-queue logic for a repository the attacker has no access to.
- `CheckSuiteHandler` schedules check-run refresh jobs against the victim stack's commits [10](#0-9) .

Since Shipit stacks can be configured for continuous deployment / merge queues driven by commit status and sync state, this cross-repository event injection can influence deploy/merge decisions on a stack the attacker does not own — matching the "unauthorized deploy/rollback" and "cross-repository writes" impact classes. I was not able to fully trace `Stack#sync_github`'s downstream side effects (e.g., whether it can directly enqueue a deploy) within the available context, so the exact severity ceiling (forced deploy vs. state corruption/CI status forgery) is not fully confirmed — this should be validated against `app/models/shipit/stack.rb#sync_github`.

### Likelihood Explanation
Likelihood is Low-to-Medium: it requires the Shipit deployment to manage multiple GitHub organizations where at least one has no `webhook_secret` configured (an explicitly supported, documented configuration path — `verify_webhook_signature` returns `true` when the secret is blank). No Shipit session, API token, or knowledge of any real secret is required; the attacker needs only to know the unsecured organization's name (often public) and the victim's `owner/repo` full name (also public) and to be able to reach the public `/webhooks` endpoint.

### Recommendation
- Verify the webhook against the same `full_name`/repository the handlers will act on, not a loosely related field picked independently by each layer. At minimum, cross-check that `repository.owner.login` (used to select signing keys) matches the owner segment of `repository.full_name` (used by handlers) before dispatching.
- Do not treat a blank/unconfigured `webhook_secret` as an implicit "verified" pass across the whole multi-org routing table; scope that bypass narrowly, or require an explicit opt-in flag per organization, and log/alert when an unsigned webhook is accepted.
- Consider having `Handler#repository_name`/`#stacks` resolution use the already-verified organization context instead of independently trusting `repository.full_name` from the raw payload.

### Proof of Concept
Preconditions: Shipit instance configured for 2+ organizations; `org-b` has no `webhook_secret` set; `org-a/private-repo` is a real tracked stack.

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything-or-omitted

{
  "repository": {
    "owner": { "login": "org-b" },
    "full_name": "org-a/private-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```

1. `WebhooksController#repository_owner` → `"org-b"`.
2. `Shipit.github(organization: "org-b").verify_webhook_signature(...)` → `true` (blank secret).
3. `PushHandler` resolves `repository_name` = `"org-a/private-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `org-a`'s stack, despite the request never being authenticated for `org-a`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
