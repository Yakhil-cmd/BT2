### Title
Cross-org signature-org / target-repo split lets an attacker mutate a victim stack's archive state via `pull_request` `labeled` webhooks - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus which `webhook_secret` gates the request) using `params.dig('repository','owner','login')`, while `LabeledHandler` resolves the repository/stack to mutate using an entirely separate field, `params.repository.full_name`. These two values are never cross-checked, so a payload can be "authenticated" under one org's (no-secret) configuration while acting on a different org's repository.

### Finding Description
The broken binding is: `repository_owner_used_for_auth == repository_full_name_owner_used_for_mutation` is assumed but never enforced.

- `verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and looks up `github_app = Shipit.github(organization: repository_owner)` [1](#0-0) , then calls `github_app.verify_webhook_signature`.
- `verify_webhook_signature` returns `true` unconditionally `unless webhook_secret` is configured for that org [2](#0-1) . In a multi-org deployment (`config/secrets.yml` with a top-level org-keyed `github:` block, as documented in `docs/setup.md`), any org that has `webhook_secret: nil` will accept **any** payload, signed or not, for events "owned" by that org login.
- Separately, `LabeledHandler#repository` resolves the actual target using `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [3](#0-2) , a completely independent string from `repository.owner.login`. Nothing in `WebhooksController#create`, `verify_signature`, or `LabeledHandler` checks that `repository.full_name`'s owner segment matches `repository.owner.login`.
- Attack: attacker registers/controls a GitHub org (or simply crafts a JSON payload) whose login is a no-secret org configured in Shipit (e.g. `someothergithuborg` per `docs/setup.md:182-209`/`config/secrets.development.shopify.yml`), sets `repository.owner.login` to that org, but sets `repository.full_name` to `victim-org/victim-repo` (a real, blocking_statuses-configured stack's repo). They POST this to `/webhooks` with header `X-Github-Event: pull_request` and body `action: "labeled"`, without any valid signature (or any signature at all, since verification is skipped).
- `verify_signature` passes (no-secret org), `LabeledHandler.process` runs `respond_to_label_change?` → `handle` → `stack.archive!` or `stack.unarchive!` on the victim's `Shipit::Repository.review_stacks` matched from `full_name` [4](#0-3) .
- Existing guards that fail to stop this: `drop_unhandled_event` only checks the event type is handled; `verify_signature`'s `GithubOrganizationUnknown` rescue only fires if the org name is literally absent from config — it does nothing if the org exists but has no secret; there is no `ExplicitParameters` constraint tying `repository.owner.login` to `repository.full_name`; `Repository` model validations only validate the `full_name` format of the *target* repo, not its relation to the authenticating org.

### Impact Explanation
An unauthenticated, unprivileged attacker can flip archive/unarchive state on a review stack belonging to a repository/org they do not control and never authenticated against, purely by naming a different, no-secret-configured org in the `repository.owner.login` field of a forged webhook. Because archiving/unarchiving a stack affects `blocked?`/deploy gating semantics documented for `blocking_statuses`-configured stacks, this is state manipulation of one repository's records via a payload that was never validated against that repository's org, matching the Critical category "a payload for one repository mutating another's stack." It is repeatable against any victim stack whose repo is a review-stack-enabled repository, as long as any org in Shipit's multi-org config lacks a `webhook_secret`.

### Likelihood Explanation
This requires: (1) the Shipit deployment to use the multi-org `github:` config schema (explicitly documented and supported), and (2) at least one configured org to have no `webhook_secret` set (also explicitly a supported/documented configuration — `webhook_secret: # nil`). Given those two common, documented conditions, the attack costs nothing beyond crafting one HTTP POST with a chosen JSON body — no GitHub account interaction, no secrets, no privileged role required.

### Recommendation
Cross-validate that the org used to select/verify the webhook signature (`repository.owner.login` / `organization.login`) matches the owner segment of `repository.full_name` before dispatching to handlers, and/or require that every configured org (and the fallback/default) have a mandatory non-blank `webhook_secret`, removing the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Minitest plan under `test/controllers/webhooks_controller_test.rb`:
1. Stub `Shipit.secrets.github` with a multi-org config: `attacker_org: { webhook_secret: nil, ... }` and `victim_org: { webhook_secret: "victimsecret", ... }` (mirroring `test/dummy/config/secrets_double_github_app.yml` structure).
2. Create a `shipit_stack` for `victim_org/victim_repo` with `review_stacks_enabled` / provisioning label configured, and a review stack currently unarchived (or archived, to test the opposite direction).
3. POST to `/webhooks` with `X-Github-Event: pull_request`, no `X-Hub-Signature` header (or an arbitrary bogus one), and body: `action: "labeled"`, `repository: { owner: { login: "attacker_org" }, full_name: "victim_org/victim_repo" }`, plus required `pull_request`/`labels` fields matching the provisioning label.
4. Assert response is `200 OK` (not `422`), and assert `stack.reload.archived?` (or `unarchived?`) changed as `archive?`/`unarchive?` logic dictates — proving the record for `victim_org/victim_repo`, which never supplied `victimsecret`, was mutated by a payload authenticated only against `attacker_org`'s (secret-less) config.
5. Negative control: repeat with `webhook_secret` set (non-nil) for `attacker_org` and an invalid signature — expect `422` and no stack mutation, confirming the divergence only exists when the "chosen" org lacks a secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-57)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
