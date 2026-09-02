### Title
Webhook signature verification keys off `repository.owner.login`, while every event handler acts on the unrelated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to validate an inbound webhook against based on `repository_owner`, a field read directly out of the *unverified* JSON body. Every downstream `Handler` (push, status, check_suite, pull_request, membership) instead resolves the target `Repository`/`Stack`/`Commit` using `repository.full_name`, a separate, independently attacker-controlled field in that same body. The equality the app implicitly relies on — "the organization whose secret authenticated this payload" == "the repository that gets written to" — is never enforced.

### Finding Description
`verify_signature` picks the app/secret to check with using only the `owner.login` sub-field of the payload: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` only proves the raw body was HMAC-signed with *some* configured organization's `webhook_secret` — it says nothing about which repository inside that body is legitimate for that organization: [3](#0-2) 

Every `Handler` subclass, however, resolves the actual `Repository`/`Stack` to mutate from a *different* field, `repository.full_name`: [4](#0-3) 

Because `repository.owner.login` and `repository.full_name` are two independent JSON keys inside a single POST body that the attacker fully controls, and Shipit explicitly supports hosting multiple GitHub organizations behind one instance with per-org secrets, an actor who legitimately installed their own GitHub App/org on this Shipit instance (and thus knows their own `webhook_secret`) can:
1. Set `repository.owner.login` (and/or `organization.login`) to their own org, so `Shipit.github(organization: repository_owner)` resolves to *their* `GitHubApp` and secret.
2. Compute a valid `X-Hub-Signature` HMAC over the full raw body using that known secret.
3. Set `repository.full_name` to `victim-org/victim-repo` — any repository already tracked as a `Stack` in the same Shipit instance.

`verify_signature` succeeds (the signature is valid for the org that was picked), yet `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc. all act on the victim's `Stack`/`Commit` records because they never re-check that `repository.full_name`'s owner matches `repository_owner`. [5](#0-4) [6](#0-5) 

### Impact Explanation
`StatusHandler#process` calls `commit.create_status_from_github!(params)` for any `Commit` matching the forged `sha`, letting the attacker inject a fabricated passing/green CI status onto a victim repository's commit that Shipit tracks. Since Shipit's deploy/merge gating (CI requirement checks, merge queue, continuous deployment) reads these `Status`/`CheckRun` records, this can trick a legitimate authorized Shipit user or an automated merge/deploy flow into treating an untested or malicious commit as CI-green, enabling an **unauthorized deploy** of code the attacker never had write access to — directly matching the High-impact criteria ("unauthorized deploy... or... escalation into authorization"). `PushHandler` similarly triggers `GithubSyncJob` for a victim `Stack` from a forged `push` event, and `CheckSuiteHandler`/`membership_handler` can inject fabricated check-run or team/membership state for repos/orgs the attacker does not own.

### Likelihood Explanation
This requires the attacker to have (or create) a legitimate low-privilege GitHub App/organization installation on the same Shipit instance — a normal, unprivileged onboarding step, not elevated access to the victim org, the victim's `webhook_secret`, or any Shipit session/API token. Any deployment supporting multiple orgs (as explicitly documented and supported in `config/secrets.development.example.yml`) is exposed by default, since there is no code path that cross-checks the signing org against the acted-upon repository.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`/`#stacks`), require that the repository/organization used to select the verifying secret is the *same* repository/organization the handler subsequently acts on — e.g., derive `repository_owner` and enforce `payload.dig('repository','full_name').split('/').first == repository_owner` before processing, rejecting mismatches with `422`.

### Proof of Concept
1. Shipit instance configured with two orgs, `attacker-org` and `victim-org` (per multi-org config), each with a `Stack` tracking `victim-org/victim-repo`.
2. Attacker installs their own GitHub App for `attacker-org` on this Shipit instance and obtains their own `webhook_secret` (standard, unprivileged setup step).
3. Attacker crafts a `status` webhook body:
```json
{
  "sha": "<victim commit sha tracked by Shipit>",
  "state": "success",
  "context": "ci/attacker-forged",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")`, verifies successfully against the attacker's own secret.
6. `StatusHandler#process` matches `Commit.where(sha: params.sha)` for the victim's tracked commit and calls `create_status_from_github!`, injecting a forged green status onto a repository the attacker never had access to.

### Citations

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
