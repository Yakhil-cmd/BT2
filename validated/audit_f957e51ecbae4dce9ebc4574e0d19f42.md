### Title
Webhook signature is verified against an attacker-chosen organization while the acted-upon repository comes from the same unverified payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC signature with based on `repository_owner`, a value read straight from the **unverified** JSON body. Once the signature check passes, the entire raw payload is handed to event handlers, which independently derive the target repository/stack from `payload.dig('repository', 'full_name')`. Nothing ties the organization that was authenticated to the repository that is actually written to, so a signature that is valid for organization A's webhook secret can be replayed with a `repository.full_name` pointing at organization B's stack.

### Finding Description
`verify_signature` picks the verifying key using attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`repository_owner` is derived purely from `params.dig('repository','owner','login')` (or `organization.login`), both fully attacker-supplied fields inside the raw POST body, before any cryptographic check has occurred. `Shipit.github(organization:)` then resolves a distinct `webhook_secret` per organization from `secrets.github`, confirming this is a genuine multi-tenant configuration where each org has its own independent signing secret: [3](#0-2) 

Once `verify_signature` succeeds (using the secret for whatever org name the attacker put in the JSON body), the controller dispatches the *entire* raw payload, unmodified, to the event handlers: [4](#0-3) 

Handlers such as `PushHandler` and `CheckSuiteHandler` never re-check that `repository.full_name` belongs to the organization whose secret validated the signature — they independently resolve the target `Stack`/`Repository` from the same untrusted body: [5](#0-4) [6](#0-5) [7](#0-6) 

This is the same bug class as the report's NDC issue: an operation (`transferAssetToNodeDelegator`) trusts an index/identifier that is not the same one that was validated, letting a swap invalidate the binding. Here the equality that should hold is:

`organization used to select/verify the webhook secret == organization that owns the repository the handler mutates`

Before the attacker's request, this equality always holds because GitHub itself sets `repository.owner.login`/`organization.login` consistently with the delivering org and signs the whole body with that org's real secret. After the attacker's crafted request, the attacker sets `repository.owner.login` to an org whose secret they know (e.g., their own org, for which they configured the Shipit webhook and therefore know `webhook_secret`), computes `X-Hub-Signature` with that known secret over the full raw body, but sets `repository.full_name` (used by `Handler#repository_name`/`#stacks`) to a **different**, victim repository/stack registered under another organization on the same Shipit instance. `verify_signature` passes because it only checked internal consistency of (chosen org, secret, raw body) — never that `repository.owner.login` equals `repository.full_name`'s owner.

### Impact Explanation
This lets an attacker who legitimately controls a Shipit-tracked repository/organization (and therefore knows that org's `webhook_secret`, since they configured it) forge signed events (`push`, `check_suite`, `status`) that are accepted by the controller and then act on an arbitrary victim stack hosted by a different organization on the same Shipit instance. `PushHandler` triggers `stack.sync_github(expected_head_sha: ...)` on the victim's stack, and `CheckSuiteHandler`/`StatusHandler` can create/alter commit statuses (`Commit#create_status_from_github!`) which gate CI-based deploy checks. This is a cross-repository write / cross-tenant boundary break — the Critical-tier impact category "cross-repository writes."

### Likelihood Explanation
Requires the attacker to control at least one organization/repository configured in the same multi-tenant Shipit instance (thus knowing its `webhook_secret`), and knowledge of another tracked repository's `full_name` (visible in the Shipit UI/API for any stack). No GitHub App private key, no Shipit session, and no elevated permissions on the victim repository are needed — only the ability to send a raw HTTP POST to `/github/webhooks` with a forged JSON body and a correctly-computed HMAC using a secret the attacker already legitimately possesses for their own org.

### Recommendation
After verifying the signature, re-derive `repository_owner` (or equivalently validate) from the same organization context used to select the secret, and reject the request if `repository.full_name`'s owner does not match the organization whose secret validated the signature. Alternatively, scope handler dispatch so that `stacks`/`Repository.from_github_repo_name` lookups are constrained to repositories belonging to the verified organization, not merely to `repository.full_name` taken from the unauthenticated field.

### Proof of Concept
1. Attacker legitimately owns `org-attacker/repo-attacker`, tracked by the same Shipit instance, and knows `secrets.github[:org-attacker][:webhook_secret]` (they configured it).
2. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": {
       "full_name": "org-victim/repo-victim",
       "owner": { "login": "org-attacker" }
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_for_org-attacker, raw_body)>`.
4. POST to `/github/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "org-attacker")`, verifies successfully against the attacker's own known secret.
6. `PushHandler` is invoked with the full payload; `Handler#repository_name` reads `"org-victim/repo-victim"` and triggers `sync_github` on the victim's stack — an org-crossing, unauthenticated write the attacker was never authorized to perform.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
