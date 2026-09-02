I have enough evidence to confirm this analog. The confirmed chain: `WebhooksController#verify_signature` selects which organization's `webhook_secret` to check against using an attacker-controlled field from the *unauthenticated* JSON body (`repository.owner.login`, falling back to `organization.login`), while every event handler determines *which repository/stack to mutate* using a different, independently-attacker-controlled field in the same body (`repository.full_name`). Nothing binds these two fields together, and multi-org Shipit deployments are documented and supported with `webhook_secret` optionally left blank per-organization (shown as `# nil` in `config/secrets.development.shopify.yml`, `config/secrets.development.example.yml`, and `test/dummy/config/secrets_double_github_app.yml`), in which case `GitHubApp#verify_webhook_signature` trivially returns `true` with no HMAC check at all.

### Title
Webhook signature verification keyed on an unauthenticated organization field lets an attacker forge events for repositories in a different, secret-protected organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Finding Description
`WebhooksController#verify_signature` picks which GitHub App/secret to validate the signature against using `repository_owner`, which is read straight out of the untrusted JSON body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` treats an organization with no configured `webhook_secret` as always "verified": [3](#0-2) 

Meanwhile, every webhook handler resolves the repository/stack to act on using a *different* field of the same body, `repository.full_name`, via `Handler#repository_name`/`#stacks`: [4](#0-3) 

`PushHandler#process` and `StatusHandler#process` then mutate state (syncs commits, records CI status) based solely on that resolved stack/commit, with no cross-check that `repository.owner.login` (used to pick the signature secret) matches the organization implied by `repository.full_name` (used to pick the target repository): [5](#0-4) [6](#0-5) 

Shipit explicitly supports and documents multi-organization configuration where each org has its own (optionally empty) `webhook_secret`: [7](#0-6) [8](#0-7) 

The bindings the report's arithmetic-operator bug generalizes to here are broken exactly as described in scope: **"an organization that authenticated versus the repository that is written"**. The equality that should hold is:

`org(repository_owner used to select the verifying secret) == org(repository.full_name used to resolve the mutated Stack)`

Before the attacker's request, both fields are populated consistently by GitHub itself, so the equality always holds. After the attacker's forged request, the two fields are independently attacker-controlled, so the equality can be broken while validation still reports success — because verification never re-derives or compares the org from `repository.full_name`, and any org lacking a `webhook_secret` bypasses HMAC checking entirely for the org named in `repository.owner.login`/`organization.login`.

### Impact Explanation
If a Shipit instance manages multiple GitHub organizations (a documented, first-class configuration path) and at least one configured organization has no `webhook_secret` set (also a documented, default/optional state), an unprivileged external attacker can:
1. Send a forged `X-Github-Event: push` (or `status`) webhook with `repository.owner.login` set to the org that has no `webhook_secret`, so `verify_signature` passes unconditionally.
2. Set `repository.full_name` in the same payload to `"<protected-org>/<repo>"`, targeting a Stack that belongs to a completely different, secret-protected organization.
3. `PushHandler`/`StatusHandler` then act on that stack — syncing arbitrary refs, injecting fabricated commit `Status` records (`state: "success"`), which flips `Commit#deployable?` and can trigger `Stack#trigger_continuous_delivery` to auto-deploy an attacker-chosen commit under continuous deployment, per `Commit#schedule_continuous_delivery`.

This is an unauthorized cross-organization/cross-repository write and can escalate into an unauthorized deploy — matching the report's "Critical: cross-repository writes, or an unauthorized deploy" impact bar. No `webhook_secret`, `ApiClient` token, or Shipit session is required from the attacker; the only precondition is the target instance's own documented multi-org configuration having one org without a webhook secret, which is not a deviation from how the engine is meant to be mounted.

### Likelihood Explanation
Likelihood is moderate and configuration-dependent: it requires (a) a multi-organization Shipit deployment and (b) at least one configured org with an empty `webhook_secret`. Both are supported, documented defaults (the shipped example configs ship with `webhook_secret: # nil`), so this is plausible in real deployments, especially staging/secondary orgs where operators often skip setting a webhook secret. Once that precondition holds, exploitation requires only a single unauthenticated HTTP POST with a crafted JSON body — no credentials, sessions, or reconnaissance beyond knowing the target's org names (often public, e.g., via GitHub org/repo names visible in the Shipit UI itself).

### Recommendation
In `WebhooksController#verify_signature`, do not let `repository_owner` (derived purely from the payload) silently select a no-secret org to bypass authentication for events targeting a different org. Concretely: require every configured GitHub App/organization to have a non-blank `webhook_secret` before accepting any webhook traffic for it (fail closed, not open, when unset), and additionally verify that the organization implied by `repository.full_name` matches `repository_owner`/the organization whose secret validated the signature before handlers are allowed to act on it.

### Proof of Concept
Given a Shipit instance configured as in `test/dummy/config/secrets_double_github_app.yml` (two orgs, `OrgOne`/`OrgTwo`, both with `webhook_secret: # nil`, illustrating the always-bypassable case), or more realistically a real deployment where `OrgOne` has a real secret and `OrgTwo` (attacker-accessible/no-secret org) does not:

```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything   # ignored because OrgTwo has no webhook_secret

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgTwo" },      // selects secret-less org -> verify_webhook_signature returns true
    "full_name": "OrgOne/protected-repo" // resolves the actual Stack acted on by PushHandler
  }
}
```

`verify_signature` calls `Shipit.github(organization: "OrgTwo")` (per `app/controllers/shipit/webhooks_controller.rb:25` and `:59-62`), which has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`) regardless of the actual `X-Hub-Signature` header. `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) then resolves stacks via `repository.full_name = "OrgOne/protected-repo"` and calls `stack.sync_github(expected_head_sha: params.after)`, forging a push event for a repository the attacker never controls or authenticated against.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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
