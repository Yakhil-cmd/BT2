### Title
Webhook Signature Verified Against `repository.owner.login`, But Event Handlers Act on Unrelated `repository.full_name` / Commit `sha` Fields, Enabling Cross-Organization Forgery of CI Status — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to validate an inbound webhook against by reading `repository.owner.login` (or `organization.login`) straight out of the same JSON body it is about to verify. Once the HMAC check passes, the actual event handlers (e.g. `StatusHandler`, `Handler#repository_name`) act on *different, unverified* fields of that same body — `repository.full_name` and, most critically, a bare `sha` string — with no check that these fields belong to the organization whose secret validated the request. This breaks the equality the signature is supposed to establish: `organization whose secret signed the payload == organization/repository the payload is allowed to mutate`.

### Finding Description
`repository_owner` is derived entirely from attacker-controlled payload content: [1](#0-0) 

It is used only to pick which `Shipit.github(organization:)` secret to verify the signature against: [2](#0-1) 

This is analogous to the reported bug: a value that is *supposed* to represent the trusted party (the treasury/associated-token-account, here the GitHub organization) is read from unauthenticated input and only checked for internal consistency with the signature, never checked against what the rest of the code will actually act on.

Downstream, `Handler#repository_name` (used by `PushHandler`, `PullRequest` handlers, etc.) reads a **different** field, `repository.full_name`, to locate the `Repository`/`Stack` to mutate: [3](#0-2) 

Most severely, `StatusHandler` doesn't even scope by repository — it matches commits **globally by `sha`** across the entire Shipit installation and writes a CI status onto them: [4](#0-3) 

Because `repository.owner.login` (used to pick the secret) and `repository.full_name` / `sha` (used to decide what gets written) are independent JSON fields inside the same attacker-authored body, an attacker who legitimately controls one GitHub organization that this Shipit instance trusts (i.e., they have that org's own `webhook_secret`, configured per the engine's documented multi-org support) can:
1. Set `repository.owner.login` to **their own** organization, so `verify_signature` fetches and validates against **their own** `webhook_secret` — which they legitimately know.
2. Set `sha` to a commit SHA belonging to a **completely different, unrelated tracked repository/stack** (SHAs of public repos are public information), or set `repository.full_name` to another org's repo for `push`/`pull_request` handlers.
3. Sign the crafted body with their own secret, which is exactly what `verify_signature` checks.

The webhook passes signature verification (their own secret matches their own signature) and is then processed by `StatusHandler`, which searches `Commit.where(sha: params.sha)` with no organizational or repository boundary check at all, letting the attacker write a fabricated `success` CI status onto a commit belonging to a repository/stack they have no relationship to.

Multi-organization support is a first-class, documented Shipit configuration (each org gets its own `webhook_secret`/`oauth` block): [5](#0-4) 

so this is not a hypothetical deployment topology — the engine explicitly supports and documents multiple mutually-untrusted organizations sharing one Shipit instance, which is exactly the trust boundary this bug crosses.

### Impact Explanation
Forging a `status` event lets an unprivileged-relative-to-the-victim-repo attacker inject a fabricated passing CI status (`state: "success"`) onto an arbitrary tracked commit in a repository/stack belonging to a different organization on the same Shipit instance. Since Shipit gates deploys on `ci.require` statuses, this can be used to satisfy CI requirements Shipit would otherwise block on, contributing to an **unauthorized deploy** of a stack the attacker does not own or have permissions for — a Critical-tier impact per the scope rules (unauthorized deploy / cross-repository writes). The same organization-vs-repository binding failure also lets `push`/`pull_request`/`check_suite` handlers be triggered against a `repository.full_name` unrelated to the signing organization, since `Handler#repository_name` never cross-checks `repository.owner.login`.

### Likelihood Explanation
Exploitation requires only that the attacker administers one GitHub organization (with its own webhook secret) that the Shipit operator has configured as a trusted multi-org source — no access to Shipit sessions, `ApiClient` tokens, `api_clients_secret`, or the victim organization's own webhook secret is needed. Target commit SHAs are public GitHub data. This makes the attack realistic in any Shipit deployment that legitimately serves more than one GitHub organization, which the engine explicitly supports and documents.

### Recommendation
After signature verification succeeds, re-derive the acting organization/repository strictly from the verified `repository.owner.login`/`organization.login` field and enforce equality against every field subsequently used to select records to mutate (`repository.full_name`, and for `StatusHandler`, the repository owning the matched `Commit`/`Stack`). Concretely: scope `StatusHandler#process` to commits whose stack's repository owner matches `repository.owner.login`, and have `Handler#repository_name` assert `repository.full_name`'s owner equals the verified `repository_owner` before performing any lookup, rejecting the event otherwise.

### Proof of Concept
1. Operator configures Shipit for two orgs, `attacker-org` (installed by the attacker, who therefore knows its `webhook_secret`) and `victim-org` (tracked stacks/commits belong here).
2. Attacker crafts a `status` webhook JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/throwaway" },
  "sha": "<known public sha of a commit tracked under victim-org's stack>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC check passes (attacker signed with the correct secret for that org).
5. `Shipit::Webhooks::Handlers::StatusHandler.call(params)` runs `Commit.where(sha: params.sha)` — matching the victim-org commit purely by SHA — and calls `commit.create_status_from_github!(params)`, writing a forged `success` status onto a commit the attacker has no relationship to, potentially satisfying `ci.require` and enabling an unauthorized deploy of the victim stack.

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
