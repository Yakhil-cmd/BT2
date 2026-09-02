## Extremely important — very interesting finding, but this is critically important to flag as unverified: the `StatusHandler` confirms the impact chain, without needing to check every remaining detail.

The `StatusHandler#process` at [1](#0-0)  writes a `Status` onto **any** `Commit` matching `params.sha` globally (no scoping by the `repository` that was authenticated) — `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. This confirms the write target is decoupled from the org used for signature verification.

### Title
Webhook signature verification binds to the wrong field, allowing cross-repository status/push forgery — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to check the HMAC signature against using `repository_owner` (`params.dig('repository','owner','login')`), a value taken from the **unverified request body**. `Shipit::Webhooks` handlers, however, act on a *different* field of that same unverified body — `payload.dig('repository', 'full_name')` (`Handler#repository_name`) or, in `StatusHandler`, on `sha` alone with no repository scoping at all. The equality the engine implicitly relies on — "the organization whose secret validated this signature" == "the repository/commit the handler writes to" — is never enforced.

### Finding Description [2](#0-1)  picks the `GithubApp` config purely from `repository_owner`, which is read straight out of the JSON body before the signature is checked. [3](#0-2)  resolves the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` — a sibling field that is never cross-checked against `repository_owner`. `StatusHandler#process` [1](#0-0)  doesn't even use the repository at all — it matches any `Commit` by `sha` across the whole instance.

In a multi-org deployment (explicitly supported and documented at [4](#0-3) ), each org has its own `webhook_secret`. A tenant who legitimately owns one onboarded org (and therefore legitimately knows *their own* `webhook_secret`) can craft an arbitrary raw JSON body, set `repository.owner.login` to their own org (so `verify_signature` selects and validates against *their own* secret via `verify_webhook_signature` at [5](#0-4) ), while setting `repository.full_name` (or, for `status` events, simply `sha`) to point at a completely unrelated stack/commit belonging to a different org/repo. The signature check passes because it only proves "signed by org A's key" — it proves nothing about which repository the payload content claims to describe.

This is the direct analog of the reported bug class: `markBeetleSafe()` verified *ownership of the caller* but not *the context/timing of the action*; here, `verify_signature` verifies *which org's key produced the HMAC* but not *whether the payload's repository/commit actually belongs to that org*.

### Impact Explanation
An attacker who controls one legitimately onboarded, unprivileged org can:
- Inject arbitrary CI `Status` objects (`success`/`failure`) onto any commit hash in any other tenant's stack (`StatusHandler`), which can flip CI-gating (`required_statuses`) used by `MergeRequest`/continuous-delivery logic ( [6](#0-5) ), potentially causing an **unauthorized merge or deploy** on a stack they do not own.
- Trigger `GithubSyncJob`/`stack.sync_github` on arbitrary victim stacks via forged `push` events (`PushHandler`), and manipulate other handlers keyed on `repository.full_name` (pull_request/membership/check_suite), all cross-tenant.

This satisfies the Critical bar in the rules ("cross-repository writes … unauthorized deploy, rollback or merge") if a required CI status can be forged to unblock a merge/deploy queue.

### Likelihood Explanation
Requires only that the attacker legitimately controls one onboarded org's own webhook secret in a multi-org Shipit deployment — no privileged Shipit account, no victim's secret, no write access to the victim repo, and no Shipit session/API token. This is a plausible, realistic configuration (explicitly documented as supported) and the mismatch is unconditional in the code, not dependent on a misconfiguration like a blank secret.

### Recommendation
Bind the field used to select the verifying `GithubApp`/secret to the same field the handlers use to resolve the target repository (`repository.full_name`), and additionally verify, post-signature, that `repository.owner.login` and the resolved `Repository#owner` are consistent with the org whose secret validated the request. For `StatusHandler`, scope the `Commit` lookup by the verified repository, not by `sha` alone.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, onboarded to a shared Shipit instance with its own `webhook_secret_A`.
2. Attacker crafts a `status` webhook JSON body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/attacker-repo"}, "sha": "<victim commit sha>", "state": "success", ...}`.
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_A, body)` and POSTs to the webhooks endpoint with `X-Github-Event: status`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates successfully against `webhook_secret_A` (per [5](#0-4) ).
5. `StatusHandler#process` matches `Commit.where(sha: <victim commit sha>)` — a commit belonging to a stack the attacker does not own — and writes a forged `success` status onto it, independent of `attacker-org`.

**Note on limitations:** I could not fully trace `lib/shipit.rb`'s `Shipit.github(organization:)` resolution logic and the exact raising point of `GithubOrganizationUnknown` (the grep matched but content wasn't rendered before tool access ended), nor did I verify the exact merge-queue/continuous-delivery code path that consumes `required_statuses` to confirm an end-to-end forced merge/deploy. These would need to be confirmed in a follow-up session to fully substantiate the Critical-severity claim versus a High-severity "unauthenticated write of arbitrary commit-status/stack-sync state" claim.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/deploy_spec.rb (L194-196)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end
```
