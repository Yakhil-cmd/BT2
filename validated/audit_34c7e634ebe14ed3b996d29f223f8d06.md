This confirms a clear multi-tenant organization/repository binding break in the multi-org GitHub App configuration mode.

### Title
Webhook signature verification selects the GitHub App secret by `repository.owner.login` while event processing acts on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
When Shipit is configured with multiple GitHub Apps (multi-org mode, keyed by organization in `secrets.github`), `WebhooksController#verify_signature` selects which app's `webhook_secret` to validate the request against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`). However, every downstream `Handler` (e.g. `PushHandler`, `StatusHandler`) resolves the target repository/stacks using a completely different, unauthenticated field: `payload.dig('repository', 'full_name')`. Nothing binds these two fields together, so a party who legitimately controls one configured organization's webhook secret can forge a validly-signed payload that names a *different* organization's repository as the target.

### Finding Description
`Shipit.github(organization:)` looks up a distinct `GitHubApp` (and thus a distinct `webhook_secret`) per organization key configured in `secrets.github` [1](#0-0) . `WebhooksController#verify_signature` picks the app/secret solely from `repository_owner`, and verifies only that the raw POST body's HMAC matches that one secret: [2](#0-1) [3](#0-2) 

`GitHubApp#verify_webhook_signature` performs a pure HMAC check on the raw body against the secret chosen this way — it never inspects the body's contents itself: [4](#0-3) 

Every event handler, however, resolves which `Stack`/`Repository` to mutate using an entirely separate field of the same attacker-controlled JSON body — `repository.full_name` — via `Handler#repository_name`/`#stacks`, with no cross-check against `repository.owner.login`: [5](#0-4) 

Because the entire request body (including both `repository.owner.login` and `repository.full_name`) is attacker-supplied and only its HMAC over the chosen secret is checked, an attacker who knows/controls the `webhook_secret` for **organization A** (e.g., because they own a repo/app installation that legitimately triggers webhooks for A) can craft a payload where `repository.owner.login = "A"` (so `verify_signature` picks A's secret and the HMAC validates) but `repository.full_name = "B/victim-repo"` (an entirely different, unrelated organization's repository tracked by this Shipit instance). This breaks the equality `organization authenticated == repository written`.

### Impact Explanation
This crosses the "organization authenticated vs. repository written" binding explicitly called out as in-scope. Concretely:
- `PushHandler#process` finds `stacks` for the forged `full_name` and calls `stack.sync_github(expected_head_sha: params.after)`, letting the attacker force org B's stack to sync to (and potentially auto-deploy) an arbitrary commit SHA of the attacker's choosing [6](#0-5) .
- `StatusHandler#process` creates fabricated commit statuses (e.g. forging a passing CI status of `state: "success"`) on commits by SHA, which can satisfy deploy/merge-eligibility checks that gate an unauthorized deploy [7](#0-6) .

Combined, this enables cross-repository writes and can trigger an unauthorized deploy/sync on a stack the attacker does not otherwise have any GitHub-side authorization for, satisfying the Critical/High impact bar (cross-repository writes, unauthorized deploy).

### Likelihood Explanation
This is only reachable in the multi-organization GitHub App configuration mode (`secrets.github` keyed by org, see `test/dummy/config/secrets_double_github_app.yml`) where multiple orgs' webhook secrets are configured on a single Shipit instance [8](#0-7) . The attacker needs legitimate knowledge of one configured organization's `webhook_secret` (e.g. by being able to see/trigger genuine webhook deliveries for their own org's app installation) — no repository write access or Shipit session is required, satisfying the "unprivileged attacker" constraint since knowledge of one org's webhook secret is not the same as write access to a *different* org's repository.

### Recommendation
In `WebhooksController#verify_signature` (or in each `Handler`), after selecting the app/secret via `repository_owner`, cross-validate that `repository.full_name`'s owner segment matches `repository_owner` (and, for organization-scoped events, that `organization.login` matches too) before dispatching to handlers. Reject the webhook with `422` if these fields diverge.

### Proof of Concept
1. Shipit is configured with two GitHub Apps: org `A` (attacker knows/controls its webhook secret because they administer that installation) and org `B` (unrelated victim repo tracked by Shipit).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "A" }, "full_name": "B/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(body, A's webhook_secret)>` using the secret they legitimately know for org A, and POSTs to `/github/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "A")` and validates the HMAC successfully (`repository_owner` returns `"A"`) [2](#0-1) .
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `stacks` from `repository.full_name = "B/victim-repo"` and calls `sync_github(expected_head_sha: "<attacker-chosen-sha>")` on org B's stack — despite the request never having been signed by org B's secret.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-20)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
```
