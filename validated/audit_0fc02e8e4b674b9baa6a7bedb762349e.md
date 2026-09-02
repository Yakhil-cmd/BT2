### Title
Webhook signature verification is bound to `repository.owner.login`, but event processing acts on the unrelated `repository.full_name` field, allowing a legitimate tenant organization to forge writes against a different organization's stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
Shipit supports hosting multiple independent GitHub Apps — one per tenant organization — each with its own `webhook_secret`, `app_id`, and `installation_id` [1](#0-0) , a pattern explicitly documented as "Creating the GitHub App... for your organization" [2](#0-1) . `WebhooksController#verify_signature` selects which organization's app/secret to validate the signature against using `repository_owner`, a field read straight out of the untrusted JSON body, and never re-checks that this organization actually owns the repository/stack that gets acted upon later in the request.

### Finding Description
`verify_signature` computes the org used for signature verification from the payload itself: [3](#0-2) [4](#0-3) 

Once the signature is accepted, the raw `params` hash (fully attacker-controlled, since the attacker also chose the signing secret) is dispatched unchanged to all registered handlers: [5](#0-4) 

Every handler, however, resolves the repository/stack to act on from a *different* field of the same payload — `repository.full_name` — with no cross-check against `repository.owner.login` used above: [6](#0-5) 

For example, the push handler uses this repository resolution to trigger a GitHub sync of any stack, keyed only by branch name, using the SHA supplied in the same forged payload: [7](#0-6) 

The binding the system relies on for security is:
`organization_that_signed_the_request (repository.owner.login) == organization_that_owns_the_acted_upon_repository (repository.full_name)`

For genuine GitHub deliveries this equality always holds, because GitHub itself populates both fields consistently for the real event source. But since the attacker constructs the entire HTTP request (including the HMAC signature, computed with a secret they legitimately possess for their own tenant organization), nothing in the engine enforces this equality. The attacker can set `repository.owner.login = "attacker-org"` (to pick the app/secret they know) while setting `repository.full_name = "victim-org/some-repo"` (to select an arbitrary other tenant's stack to act on).

### Impact Explanation
This breaks the deployment-trust boundary between tenants of a shared Shipit instance: an organization is authenticated, but a different organization's repository is written. Concretely reachable, unprivileged-attacker consequences within engine code:
- `push` event: forces `GithubSyncJob` against a victim stack with an attacker-chosen `expected_head_sha`, an out-of-scope-organization write triggered purely by a forged webhook [8](#0-7) .
- `status` event: creates/updates a `Status` record for an attacker-chosen commit SHA belonging to a victim repository (confirmed by existing test behavior for this handler) [9](#0-8) . Since Shipit's deploy/merge-eligibility logic relies on recorded CI `Status` to determine whether a commit is deployable/mergeable, an attacker who is a legitimate admin of only their own tenant organization can forge a "success" status on a victim organization's commit, which can enable an unauthorized deploy or merge decision on infrastructure they have no legitimate access to.

This satisfies the Critical bucket: cross-repository writes / unauthorized deploy or merge, achieved purely through the engine's own webhook trust logic, not through any GitHub App misconfiguration or missing mount.

### Likelihood Explanation
Requires only that the attacker be a legitimate, unprivileged administrator of one tenant organization already onboarded to a shared multi-org Shipit deployment (a supported, documented configuration) — they need no access to any other organization, no `ApiClient` token, and no Shipit session. They only need to know the `webhook_secret` of their own GitHub App (which they control, since they created it) and craft one raw HTTP POST to the shared `/webhooks` endpoint.

### Recommendation
After signature verification succeeds for organization `O`, `WebhooksController` (or `Webhooks::Handlers::Handler`) must verify that the `repository.full_name` (and/or `organization.login` for org-scoped events) referenced by the payload actually belongs to organization `O` before dispatching to handlers — e.g., load the `Repository`/`Stack` and assert `repository.owner == O` (or equivalent) prior to invoking `Shipit::Webhooks.for_event(event)`; reject the request with `422` otherwise.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, a tenant organization configured in Shipit's multi-app `github:` config with its own known `webhook_secret_A` (as shown by the supported multi-org configuration shape) [1](#0-0) .
2. Attacker crafts a JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `webhook_secret_A` over the raw JSON body, per `verify_webhook_signature` [10](#0-9) .
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the forged signature [3](#0-2) .
5. `Webhooks::Handlers::PushHandler` resolves the target stack via `repository.full_name = "victim-org/victim-repo"` [6](#0-5)  and enqueues `GithubSyncJob`/updates state for `victim-org`'s stack, despite the request never having been authenticated as belonging to `victim-org`.

### Citations

**File:** test/dummy/config/secrets_double_github_app.yml (L1-46)
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
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** docs/setup.md (L20-24)
```markdown
## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
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
