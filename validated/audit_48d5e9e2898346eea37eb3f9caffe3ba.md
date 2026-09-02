I'll investigate the codebase for the specific trust-boundary patterns mentioned before drawing any conclusion.This looks like a promising lead — the webhook signature is verified against an organization derived from `repository.owner.login`, but the actual repository written to may be looked up via a different field (`repository.full_name`) within the same JSON body. Let me check the actual webhook handlers.### Title
Cross-organization webhook forgery via organization-scoped signature verification vs. unscoped payload processing - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against based on the `repository.owner.login` (or `organization.login`) field of the *same* untrusted JSON body it is about to validate. In a multi-organization Shipit deployment (a supported, documented configuration — see `config/secrets.development.example.yml`), each GitHub organization has its own `webhook_secret`. However, the code paths that *act* on the verified payload (`Shipit::Webhooks::Handlers::Handler#repository_name`, used by `PushHandler`, and `StatusHandler#process`) either key off a *different* field of the body (`repository.full_name`) or don't scope by repository/organization at all. This breaks the equality: `organization whose secret authenticated the request == repository/commit that gets written`.

### Finding Description
`WebhooksController#verify_signature` ( [1](#0-0) ) does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is read straight from the untrusted body: [2](#0-1) 

`GitHubApp#verify_webhook_signature` ( [3](#0-2) ) only proves that *the whole raw body* was signed with *that organization's* secret — it says nothing about which repository/commit inside the body is legitimate for that org.

Shipit explicitly supports one webhook secret **per GitHub organization** ( [4](#0-3) ). Any attacker who has installed their own (legitimate) Shipit-compatible GitHub App on an organization they control (`OrgA`) knows `OrgA`'s `webhook_secret` and can therefore compute a valid `X-Hub-Signature` for **any body content**, as long as `repository.owner.login` (or `organization.login`) in that body equals `"OrgA"`.

Once signature verification passes, `WebhooksController#create` dispatches the entire attacker-controlled body to handlers: [5](#0-4) 

Two handlers then act on fields that were never bound to the verified `repository.owner.login`:

1. `PushHandler`/`Handler#repository_name` resolves the target repository using `repository.full_name` — a different JSON field than the one used for signature-org selection: [6](#0-5) [7](#0-6) 
Nothing enforces `repository.full_name.split('/').first == repository.owner.login`. An attacker can set `owner.login = "OrgA"` (satisfies signature check) while setting `full_name = "OrgB/victim-repo"`, causing `stacks` to resolve to a stack that belongs to an organization the attacker does not control, and triggers `stack.sync_github(expected_head_sha: params.after)` on it.

2. `StatusHandler#process` is worse: it does not check the repository/organization at all, only the commit `sha`: [8](#0-7) 
Any commit SHA (`Commit.where(sha: params.sha)`), regardless of which repository/organization it belongs to in Shipit's database, gets a forged CI status attached via `create_status_from_github!`. Since a valid `X-Hub-Signature` only had to be computed with the attacker's *own* org's secret, an attacker can forge a `state: "success"` status for a required CI `context` (used by `ci.require`, see README) on a **victim's** commit that they have no relationship to, as long as they can learn/guess the commit SHA (SHAs are public on `github.com`).

### Impact Explanation
Shipit's `ci.require` deploy-gating mechanism relies on `Commit#statuses` reflecting real GitHub CI outcomes. By forging a webhook whose signature validates against the attacker's own (self-controlled) organization's secret, but whose payload content targets a commit/repository belonging to a different organization hosted on the same Shipit instance, an attacker can inject a fabricated "success" status for a required context. This can unblock the deploy checklist/merge-queue gating for a stack the attacker has no authorization over, enabling an **unauthorized deploy** of unreviewed/unvalidated code — the Critical impact category ("unauthorized deploy, rollback or merge"). The push-handler variant additionally allows forcing a `GithubSyncJob` resync against an arbitrary organization's stack using attacker-chosen `ref`/`after` values.

### Likelihood Explanation
This requires: (a) the Shipit instance to be configured for multiple GitHub organizations (a documented, supported configuration), and (b) the attacker to control (or have installed) a GitHub App on at least one of those organizations, which is a low bar since organization owners routinely self-service install GitHub Apps on their own orgs and thus legitimately know that org's `webhook_secret`. No `ApiClient` token, session, or repository write access to the *victim* org is required — only knowledge of a target commit SHA (public information) or push metadata (branch name, discoverable from a public repo). This satisfies the "unprivileged-attacker" constraint relative to the victim organization/stack.

### Recommendation
Bind the payload's organization/repository fields used for authorization to the identity actually proven by the signature:
- In `WebhooksController`, after resolving `repository_owner` and verifying the signature, re-validate that any repository/commit acted upon by a handler actually belongs to that same verified organization (e.g., pass the verified `repository_owner` into handlers and have `Handler#repository_name`/`StatusHandler` reject records whose organization doesn't match).
- In `StatusHandler#process`, scope `Commit.where(sha: params.sha)` to commits whose `stack.repository.owner` equals the verified organization, instead of matching solely by SHA across the entire installation.
- Consider deriving the HMAC-selection organization from a value provided out-of-band by GitHub (e.g. by trying all configured org secrets, or requiring a per-org distinct webhook URL/path) rather than trusting a field embedded in the very payload being verified, and cross-check it against every field subsequently trusted from that payload.

### Proof of Concept
Given a Shipit instance configured for two organizations `OrgA` (attacker-controlled installation, secret `S_A` known to attacker) and `OrgB` (victim, hosts stack `OrgB/victim-repo`, unrelated to attacker):

1. Attacker crafts a `status` webhook body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/attacker-repo" },
  "sha": "<victim commit sha, e.g. from GitHub PR page of OrgB/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "branches": [{ "name": "master" }]
}
```
2. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S_A, raw_body)` since they know `S_A`.
3. POST to `/webhooks` with header `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository.owner.login`), succeeds because the attacker signed with `S_A` — [9](#0-8) .
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matching the victim's commit — and calls `create_status_from_github!`, writing a forged "success" status onto `OrgB`'s commit, with no check that it belongs to `OrgA` — [8](#0-7) .

This is theoretically reachable through the engine's own code with no need for a `webhook_secret`/`ApiClient` belonging to the victim organization; it only requires legitimate credentials the attacker already possesses for their own, unrelated organization. I was unable to fully trace how `ci.require`/deploy checklist gating consumes `Commit#statuses` end-to-end (that logic lives in view/deploy-checklist code partially excluded from scope), so the exact UI flow from "forged status" to "deploy button becomes clickable" could not be fully confirmed within the indexed engine code; this should be validated with a live Devin session against the full repository if a definitive proof of unauthorized-deploy triggering is required.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
