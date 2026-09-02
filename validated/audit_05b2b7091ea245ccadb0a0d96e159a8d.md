### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while handlers act on the unverified `repository.full_name` field, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's HMAC secret to validate a webhook against using `repository.owner.login` (falling back to `organization.login`), but `WebhooksController#create` dispatches the *entire, unmodified* JSON payload to handlers, which independently derive the acted-upon repository from `repository.full_name`. These two fields are never cross-checked, so the organization whose secret authenticates the request is not bound to the repository the handler actually writes to.

### Finding Description
Shipit supports multi-tenant GitHub App configuration: multiple organizations can be configured under `secrets.github`, each with its own `webhook_secret` [1](#0-0) . The `github()` accessor loads the specific org's config and secret via `Shipit.github(organization: repository_owner)` [2](#0-1) .

`verify_signature` computes `repository_owner` purely from the request body: [3](#0-2) 
It then verifies the raw body's HMAC using that organization's secret only: [4](#0-3) 

Once verification passes, `create` re-parses the same body and hands it, unmodified, to the event handlers: [5](#0-4) 

Handlers such as `PushHandler` and `CheckSuiteHandler` resolve the target `Repository`/`Stack` from `repository.full_name` — a *different* JSON field than the one used for signature-org selection: [6](#0-5) 

Because `repository.owner.login` and `repository.full_name` are independent, attacker-controlled strings in the same request body, and only the former is bound to the signature check, an attacker who legitimately controls one onboarded organization ("org-A", and thus knows org-A's `webhook_secret`) can:
1. Set `repository.owner.login` (or `organization.login`) to `"org-A"` so `verify_signature` picks org-A's secret and the HMAC validates successfully.
2. Set `repository.full_name` to `"org-B/some-repo"` (a different, victim organization's repository configured in the same Shipit instance).

The signature check passes (it only ever inspected org-A's secret), yet `Handler#stacks` / `Handler#repository_name` resolve and act on org-B's repository [6](#0-5) . This breaks the equality the rule set calls out explicitly: *organization that authenticated* (org-A, via its verified webhook secret) **≠** *repository that is written* (org-B/some-repo, acted on by the handler).

Concretely, `StatusHandler` will create a commit status on any matching commit sha across the *entire* install [7](#0-6) , and `CheckSuiteHandler`/`PushHandler` will trigger check-run refreshes and GitHub syncs on stacks belonging to org-B [8](#0-7) [9](#0-8)  — all forged by an operator who is only authorized (has a valid webhook secret) for org-A.

### Impact Explanation
An attacker who is a legitimate, low-privilege participant in only one organization onboarded to a shared/multi-tenant Shipit instance can forge GitHub `status`, `push`, or `check_suite` webhooks that are attributed to and acted upon for a completely different organization's repositories/stacks. Forged `status` events can mark arbitrary commits with fabricated CI/status states, which Shipit's deploy-safety gating (blocking statuses) relies on to decide whether a commit range is safe to deploy — enabling an unauthorized deploy of a victim organization's stack. This is a cross-organization write achieved purely by exploiting a verification/binding mismatch, not by session or token compromise.

### Likelihood Explanation
This requires the deployment to host more than one GitHub organization (the multi-org `secrets.github` config path in `lib/shipit.rb`), which is an explicitly supported configuration, not a misconfiguration. Any authorized owner/admin of one onboarded organization already knows that organization's own webhook secret (they configured it), and crafting an HTTP POST to `/webhooks` with the described field mismatch requires no special access beyond that. No GitHub App private key, session, or `ApiClient` token is needed — only knowledge of one org's own webhook secret, which is by design available to that org's Shipit configurator.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), enforce that the organization used to select the signing secret is the same organization actually acted upon by the handler — e.g., validate that `repository.full_name`'s owner segment equals `repository_owner`/`organization.login` before verification succeeds, or resolve the target `Repository`/`Stack` first and use *its* owner to select the verification secret, rejecting the payload if they disagree.

### Proof of Concept
Assume a Shipit instance configured with two organizations, `org-a` and `org-b`, each with distinct `webhook_secret`s (per the multi-org schema in `lib/shipit.rb`'s `github_app_config`). The attacker legitimately administers `org-a` and knows `org-a`'s webhook secret.

1. Attacker crafts a `status` webhook payload:
```json
{
  "sha": "<victim-commit-sha-in-org-b-repo>",
  "state": "success",
  "context": "ci/tests",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
2. Attacker computes `X-Hub-Signature` using `org-a`'s known webhook secret over the raw body.
3. `verify_signature` reads `repository_owner` = `"org-a"` (from `repository.owner.login`), loads `org-a`'s `GitHubApp`, and successfully verifies the signature against `org-a`'s secret [4](#0-3) .
4. `create` dispatches the same payload to `StatusHandler`, which looks up commits by `sha` (not scoped to the verified org) and creates a status record reflecting the forged `"success"` state [7](#0-6) , even though the actually-verified organization (`org-a`) has no relationship to `org-b/victim-repo`.
5. This forged status can satisfy Shipit's blocking-status/deploy-safety checks for `org-b`'s stack, enabling an unauthorized deploy that the attacker (an `org-a`-only participant) should never be able to influence.

### Citations

**File:** lib/shipit.rb (L170-181)
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
```

**File:** lib/shipit.rb (L190-200)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
