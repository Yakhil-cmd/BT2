## Title
Cross-organization webhook signature confusion allows unauthorized commit-status and stack writes across repositories - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

## Summary

## Finding Description
The reported bug class is a binding break between what is *authorized* (the source contract's ability to move a token) and what is *executed* (moving *any* token, including one the caller shouldn't control). The equivalent binding in Shipit is: **the GitHub organization whose webhook secret verified the request signature** must equal **the repository whose stacks/commits the handler subsequently mutates**. In this engine that equality is never enforced.

`WebhooksController#verify_signature` selects which `GithubApp`/secret to verify against purely from the payload's `repository.owner.login` (or `organization.login`) field: [1](#0-0) 

Shipit supports configuring **multiple independent GitHub organizations**, each with its own `webhook_secret` (`config/secrets.development.example.yml`), so any organization admin who legitimately owns a Shipit-configured GitHub App/webhook secret for their *own* org can compute a valid `X-Hub-Signature` for **any payload body they choose**, since HMAC verification only proves the message was signed with *that org's* secret — it says nothing about which repository the payload's other fields describe.

Once the signature check passes, the handlers determine *which* repository/stack/commit to write to using a **different field** than the one used for authentication:
- `Webhooks::Handlers::Handler#stacks` resolves scope from `payload.dig('repository', 'full_name')`, not `repository.owner.login`: [2](#0-1) 
- `StatusHandler#process` doesn't even scope by repository at all — it updates **any** `Commit` in the entire Shipit instance whose `sha` matches the attacker-supplied value, regardless of which repo/org owns it: [3](#0-2) 

So an attacker who controls a legitimate but low-privilege GitHub App installation (their own org, e.g. `attacker-org`, with a webhook secret they know) can send a forged `status` webhook where `repository.owner.login = "attacker-org"` (making `verify_signature` pass using their own secret) while `sha` is a real commit SHA belonging to a victim's repository tracked by a different stack. `Commit.where(sha: params.sha)` will match across the whole instance and `create_status_from_github!` will write an attacker-chosen `state`/`context`/`description`/`target_url` onto that victim commit.

`PushHandler`, `CheckSuiteHandler`, and the `PullRequest::*` handlers are scoped via `repository.full_name`, which is likewise never cross-checked against the org whose secret authenticated the request — an attacker could set `repository.owner.login` to their own org (to pass signature verification) and `repository.full_name` to a victim repo/stack path, causing `stack.sync_github`, PR archive/unarchive, or check-run refresh actions to run against a stack they don't own.

## Impact Explanation
This breaks the "organization authenticated == repository written" binding called out in scope. `StatusHandler` in particular lets an attacker forge success/failure CI statuses on arbitrary commits system-wide. Since Shipit's merge/deploy tooling (status checks used to gate merges and deploys) relies on `Commit` statuses being trustworthy signals from CI, an attacker-controlled successful status write on a victim's commit can unlock deploy/merge gating that depends on required status checks, constituting an unauthorized deploy path — matching the Critical impact category ("an unauthorized deploy"). Even the lower-severity handlers (`PushHandler`, `CheckSuiteHandler`, PR handlers) allow an authenticated-but-unrelated org to trigger stack syncs/archival/unarchival on repositories/stacks they don't own, which is a cross-repository write.

## Likelihood Explanation
Any party who has legitimately been granted their own Shipit-configured GitHub App/org (a normal, unprivileged onboarding step supported by the multi-org config documented in `config/secrets.development.example.yml`) can exploit this without any additional privilege escalation — they simply need to know a target commit SHA (public information on GitHub) and craft the JSON body themselves, computing the signature with their own secret. No `ApiClient` token, GitHub App private key, or session is required, satisfying the "unprivileged attacker" constraint.

## Recommendation
Cross-validate the authenticated organization against the actual repository being mutated: after `verify_signature` succeeds, derive the target `Repository`/`Stack` and assert that `repository.owner.login`/`organization.login` used for signature selection matches the *owner* of the repository resolved via `repository.full_name` (and, for `StatusHandler`, scope `Commit` lookups by the commit's owning repository, not merely `sha`). Reject the webhook (422) on mismatch.

## Proof of Concept
1. Attacker is an admin of `attacker-org`, which has a legitimate Shipit GitHub App installation with `webhook_secret = S_attacker` (per `config/secrets.development.example.yml` multi-org format).
2. Attacker obtains a real commit SHA for `victim-org/victim-repo` (e.g. from GitHub's public commit history).
3. Attacker builds a `status` event payload:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac(S_attacker, body)>` and POSTs to `/github/webhooks`.
5. `WebhooksController#verify_signature` resolves `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and verifies successfully against the attacker's own secret — see `app/controllers/shipit/webhooks_controller.rb:24-30`.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` — see `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` — writing an attacker-controlled "success" status onto the victim's commit with no check that the commit belongs to `attacker-org`.

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
