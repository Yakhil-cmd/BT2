Confirmed root cause: the `repository_owner` used to select the GitHub App/secret for signature verification is not bound to the `repository.full_name` value that handlers use to select which `Stack`/repository to act on.

### Title
Webhook signature is verified against a different organization's secret than the repository the payload actually mutates - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the GitHub App (and thus the HMAC secret) to verify a webhook against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` [1](#0-0) . Every downstream handler (`PushHandler`, `StatusHandler`, etc.) instead resolves the target `Stack` using `payload.dig('repository', 'full_name')` via `Handler#repository_name`/`#stacks` [2](#0-1) . In a multi-organization Shipit deployment (`docs/setup.md` documents per-organization `webhook_secret`s), an attacker who legitimately controls a GitHub organization/app installation whose webhook secret is configured in Shipit can sign an arbitrary payload with their own valid secret while setting `repository.owner.login` to their own org (so verification passes) and setting `repository.full_name` to a different, victim organization's repository that also has a Stack configured in the same Shipit instance.

### Finding Description
The signature check computes: `verified = Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)` where `repository_owner` is `params.dig('repository','owner','login')` [3](#0-2) . This only proves the payload was signed with the secret belonging to the organization named at `repository.owner.login`. It does not prove that the *action taken* — driven by `repository.full_name` in `Handler#repository_name` — corresponds to that same organization. Because `repository.owner.login` and `repository.full_name` are independent, attacker-controlled JSON fields inside the same signed body, an attacker who is a legitimate operator of Organization A (and therefore knows/controls a valid HMAC secret registered for A, e.g. by installing their own GitHub App instance under multi-org config) can produce a validly-signed body where `repository.owner.login = "orgA"` but `repository.full_name = "orgB/victim-repo"`. `verify_signature` authenticates the request as coming from Org A (true), but `PushHandler`/`StatusHandler` then act on Org B's stack, e.g. triggering `stack.sync_github(expected_head_sha: params.after)` [4](#0-3)  or writing arbitrary commit statuses via `commit.create_status_from_github!(params)` for any commit sha across any repo tracked by Shipit [5](#0-4) . This breaks the intended binding: "organization that authenticated == repository that is written."

### Impact Explanation
This allows cross-repository writes: an attacker with control of one onboarded GitHub organization's webhook credentials can inject forged push/status events that mutate `Stack`s belonging to a different organization also configured on the same Shipit instance (e.g. forcing spurious `sync_github` calls, or forging CI/commit statuses that Shipit's merge-queue/deploy gating (`release_status?`, CI checks) relies on). Forged commit statuses can influence whether commits are considered "deployable," potentially enabling unauthorized deploy decisions downstream. This matches the "cross-repository writes" / escalation criteria.

### Likelihood Explanation
Requires the Shipit instance to be configured with multiple GitHub organizations/apps (a documented, supported configuration in `docs/setup.md`), and requires the attacker to control (or have installed) one of those GitHub Apps/orgs so they possess a valid signature for at least one org — a comparatively low bar since GitHub Apps can often be installed by any organization admin, and the attacker never needs Shipit application credentials. The vulnerable code path (`repository_owner` vs `repository_name` mismatch) is unconditional and always reachable for `push`/`status`/other webhook events.

### Recommendation
Verify the webhook signature using the same field that the handler will use to select the target repository/stack (`repository.full_name`, or bind the verification to the resolved `Repository`/`Stack`'s configured organization) rather than an independent `owner.login`/`organization.login` field. Concretely, derive `repository_owner` for signature verification from the same `repository.full_name` used by `Handler#repository_name`, or after verifying, re-check that the resolved repository's owner matches the organization whose secret validated the signature before invoking handlers.

### Proof of Concept
1. Shipit is configured with two GitHub organizations, `orgA` and `orgB`, each with its own `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications" section), and each has a `Stack` tracked in Shipit for `orgA/repo` and `orgB/victim-repo` respectively.
2. Attacker legitimately controls `orgA`'s GitHub App installation/webhook secret (e.g., they installed the Shipit GitHub App on their own org as permitted by the workflow).
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<arbitrary sha attacker wants processed>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(orgA_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` computes `Shipit.github(organization: "orgA")` (from `repository.owner.login`) and successfully verifies the signature against `orgA`'s secret [3](#0-2) .
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgB/victim-repo")` [2](#0-1)  and calls `stack.sync_github(expected_head_sha: params.after)` on `orgB`'s stack — an action the attacker was never authorized to trigger, using credentials that only prove control of `orgA`.

**Uncertainty:** I was not able to directly execute this end-to-end in the codebase (no test harness available in this read-only session), so this is derived purely from static analysis of `webhooks_controller.rb` and `handler.rb`/`push_handler.rb`/`status_handler.rb`. I could not fully audit every other handler (`check_suite_handler.rb`, `membership_handler.rb`, `pull_request/*`) for the same pattern, though the shared `Handler#repository_name` base method suggests they share this exposure.

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
