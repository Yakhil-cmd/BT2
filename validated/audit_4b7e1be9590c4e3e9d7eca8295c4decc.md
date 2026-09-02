This confirms a concrete binding-break: the webhook signature is verified against an organization derived from one JSON field (`repository.owner.login`, with fallback to `organization.login`), while every handler resolves the affected `Repository`/`Stack` using a completely different field in the same attacker-supplied JSON body (`repository.full_name`). Nothing ties these two fields together.

### Title
Webhook signature verification organization does not bind to the repository the handler acts on, allowing cross-organization event forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the `X-Hub-Signature` against using `repository_owner`, computed from the unsigned request body itself: `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`. [1](#0-0) [2](#0-1) 

But every event handler ignores `repository.owner.login` entirely and instead resolves the target `Repository`/`Stack` using `repository.full_name`, via `Shipit::Webhooks::Handlers::Handler#repository_name` / `#stacks`, or the equivalent `Repository.from_github_repo_name(params.repository.full_name)` calls used across handlers (push, status, pull_request/*). [3](#0-2) [4](#0-3) 

### Finding Description
In a multi-organization Shipit deployment, `Shipit.github(organization:)` maps an organization name to a distinct `GitHubApp` instance configured with its own `webhook_secret` (`Shipit.github_app_config`). [5](#0-4) 
`WebhooksController#verify_signature` picks that app/secret using `repository_owner`, taken straight out of the untrusted JSON payload before the signature has been checked. [6](#0-5) 

The equality the design intends is: `organization whose secret authenticated the request == organization that owns the repository the handler mutates`. In this engine, that equality is never enforced. An attacker who legitimately controls (or has previously obtained) the webhook secret for **any one** onboarded GitHub organization, `org-A`, can craft a payload where `repository.owner.login` = `org-A` (so `verify_signature` picks `org-A`'s app/secret and the HMAC computed over the full raw body validates) while `repository.full_name` = `org-B/some-repo` — a repository belonging to a completely different, unrelated organization also registered in the same Shipit instance. Because `Repository.from_github_repo_name` looks the repo up purely by `owner/name` string parsed out of `full_name` with no cross-check against the authenticating organization, the handler operates on `org-B`'s stack. [7](#0-6) 

Concretely with the `push` handler: a forged `push` event signed with `org-A`'s secret but `repository.full_name = "org-B/prod-repo"` will resolve `org-B`'s stacks and enqueue `stack.sync_github(expected_head_sha: params.after)` for a branch that never received the real push — this can be used to force a sync against an attacker-chosen SHA/branch state on a repository the attacker has no relationship to. [8](#0-7) 
Similarly, `pull_request` handlers (opened/closed/labeled/assigned/edited) will create, archive/unarchive, or mutate review stacks/pull-request state belonging to `org-B`'s repositories, and `status_handler` will forge commit statuses for any commit SHA that happens to exist in Shipit's `Commit` table regardless of which org it was verified against (status handler doesn't even use `repository.full_name`, it matches purely by `sha`, compounding the same organization/repository binding gap). [9](#0-8) 

### Impact Explanation
This is a High-severity authorization-boundary crossing: an entity that only holds credentials (webhook secret) for organization A can forge webhook-driven, GitHub-authenticated-looking events that mutate state (sync triggers, review-stack archive/unarchive, pull-request/label state, commit statuses) belonging to organization B's stacks in the same multi-tenant Shipit instance, without ever having any access, token or authorization for organization B. This crosses the "GitHub identity/organization authenticated" vs "repository actually written" binding explicitly called out as in-scope, and in the push case can trigger unauthorized deploy-related syncs against a foreign repository.

### Likelihood Explanation
Exploitability requires only that: (1) the target Shipit instance is configured for multiple GitHub organizations (a documented, supported configuration — see `config/secrets.development.example.yml` multi-org schema), and (2) the attacker possesses (or is entitled to) the webhook secret for at least one onboarded organization — e.g. they are a legitimate GitHub org admin who installed the Shipit app for their own org, a normal, expected scenario for a permissionless/multi-tenant deploy tool. No compromise of the target organization is required at all — this is precisely the class of "authenticated for org A, acting on org B" cross-tenant confusion.

### Recommendation
In `WebhooksController#verify_signature`/`#create`, after verifying the signature, re-derive the organization strictly from `repository.full_name` (or `organization.login`) and assert it matches the `repository_owner` used to select the signing app/secret before dispatching to handlers; alternatively, look up the `Repository` via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and reject the event if `repository.owner != repository_owner_used_for_signature_verification`.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (`config/secrets.development.example.yml` multi-org schema).
2. As an attacker who only knows `org-a`'s `webhook_secret` (e.g., a legitimate GitHub App/webhook admin for `org-a`), craft a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(org-a_webhook_secret, raw_body)`.
4. POST to `/github/webhooks` with header `X-Github-Event: push`. `verify_signature` calls `Shipit.github(organization: "org-a")` (from `repository.owner.login`) and validates successfully. [1](#0-0) 
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-b/victim-repo")`, matching `org-b`'s repository, and enqueues `sync_github` on `org-b`'s stacks despite the request never being authenticated for `org-b`. [8](#0-7) [3](#0-2)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
