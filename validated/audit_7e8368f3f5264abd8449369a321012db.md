### Title
Webhook signature is verified against `repository.owner.login` but every event handler acts on the independently-controlled `repository.full_name` field, allowing cross-organization writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `params.dig('repository', 'owner', 'login')`, but every `Webhooks::Handlers::Handler` subclass (push, status, pull_request, etc.) locates the `Repository`/`Stack` to act on using the sibling field `repository.full_name` (or `params.repository.full_name`). Because the JSON body is attacker-supplied and only the *whole payload's* HMAC is checked (not a binding between these two specific fields), a party who legitimately controls one organization's webhook secret in a multi-org Shipit install can forge a payload whose `repository.owner.login` matches their own org (so the signature check passes) while `repository.full_name` points at a completely different organization's repository.

### Finding Description
`Shipit::WebhooksController#verify_signature` derives the app used for verification from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization app credentials/secrets from `secrets.github`, supporting multi-org configurations documented in `docs/setup.md` and `config/secrets.development.shopify.yml`: [3](#0-2) 

Once the signature is accepted, `WebhooksController#create` dispatches the *entire raw JSON body* to handler classes: [4](#0-3) 

Every handler resolves the target `Repository`/`Stack` using `repository.full_name`, a field never checked against `repository.owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` simply splits the string on `/` with no ownership check: [8](#0-7) 

**The broken equality:** `organization authenticated by verify_signature (repository.owner.login)` should equal `organization of the repository actually written to (derived from repository.full_name)`. Nothing in the code enforces this. Both fields live in the same attacker-controlled JSON body; GitHub itself always sends them consistent, but a forger who only needs a valid HMAC for *one* org (the one whose secret they possess) can set `full_name` to any other onboarded org/repo.

### Impact Explanation
This crosses the "organization authenticated versus repository written" trust boundary explicitly called out in scope. Concretely, in a Shipit deployment configured with multiple GitHub organizations (a supported, documented configuration), an actor who administers/controls one onboarded organization (and can therefore set that org's webhook secret and fire arbitrary signed webhook deliveries to Shipit, e.g. via the GitHub App's "Redeliver"/webhook test tooling, or by installing their own GitHub App if Shipit trusts self-service org onboarding) can send a validly-signed `push`, `status`, `pull_request`, or `check_suite` event where `repository.full_name` names a repository belonging to a *different* onboarded organization. Handlers then act on that other org's `Stack`/`Repository`:
- `PushHandler` calls `stack.sync_github(expected_head_sha:)` on a foreign stack.
- `StatusHandler` injects an arbitrary commit status (`create_status_from_github!`) onto a foreign commit, which feeds directly into `Commit#deployable?` and the merge queue's CI gating.
- `pull_request` handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) create/archive/unarchive review stacks belonging to the foreign repository.

Forged commit statuses are especially significant because `Commit#deployable?` and merge-queue eligibility rely on them, meaning an attacker could make a foreign repository's commit falsely appear CI-green and trigger cross-repository unauthorized deploys/merges. This satisfies the "cross-repository writes" / "unauthorized deploy" bar.

### Likelihood Explanation
Exploitability requires: (1) a Shipit instance configured with the multi-organization `github:` secrets schema (an explicitly documented and supported configuration), and (2) the attacker controlling at least one of the onboarded organizations (i.e., being able to know/set that org's webhook secret or otherwise produce validly-signed deliveries for it — normally granted to whoever installs the GitHub App for that org). This is not a generic unauthenticated attack against a single-org install, but for any Shopify-style multi-tenant deployment it is a realistic, low-effort attack path since it needs no code execution, no stolen tokens, and no repository write access on the *target* org — only administrative control of a co-tenant organization.

### Recommendation
Bind the field used for signature-org selection to the field used for repository resolution:
- Derive the acting organization consistently from `repository.full_name` (splitting on `/`) rather than a separate `repository.owner.login`/`organization.login` field, or
- After selecting the signing org via `repository_owner`, explicitly assert (in `WebhooksController` or in `Handler`) that `repository.full_name.split('/').first.casecmp(repository_owner) == 0` before dispatching to handlers, rejecting (422) any payload where these disagree.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` "Using Multiple Github Applications").
2. Attacker, who administers `attacker-org`'s GitHub App, crafts a `push` webhook payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha already known to exist in victim-org/target-repo>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/target-repo"
  }
}
```
3. Attacker signs the raw body with `attacker-org`'s `webhook_secret` and POSTs it to `/webhooks` with header `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully validates the signature (attacker legitimately owns this secret).
5. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/target-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — an org boundary crossing that should have been rejected.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
