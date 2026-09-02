### Title
Webhook signature verification is bound to `repository.owner.login` while all handlers act on `repository.full_name`, allowing a no-secret-org payload to mutate an unrelated victim stack - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) using `params.dig('repository','owner','login')`, but every `pull_request` handler (including `LabelCapturingHandler`) resolves the target `Repository`/`Stack` using the independent `params.repository.full_name` field [1](#0-0) [2](#0-1) . If Shipit is configured for multi-org (`github_default_organization` present) and one configured org has no `webhook_secret`, `GitHubApp#verify_webhook_signature` returns `true` unconditionally for any payload claiming that org as owner [3](#0-2) , while the `repository.full_name` field in the same JSON body can independently name any other configured/victim organization's repository.

### Finding Description
The broken binding: the code implicitly assumes `params.dig('repository','owner','login') == params.repository.full_name.split('/').first`, but nothing enforces this equality.

- `verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and asks `Shipit.github(organization: repository_owner)` for the app used to validate `X-Hub-Signature` [1](#0-0) [4](#0-3) .
- `GitHubApp#verify_webhook_signature` short-circuits `return true unless webhook_secret`, i.e., any org configured without a `webhook_secret` accepts any payload with no HMAC check at all [3](#0-2) . The docs explicitly show this multi-org config shape and per-org `webhook_secret` fields (some `nil`), confirming this is a supported configuration, not a hypothetical [5](#0-4) [6](#0-5) .
- Once verified (bypassed), `LabelCapturingHandler` (and `ReviewStackAdapter`, `Repository.from_github_repo_name`) derive the target repository purely from `params.repository.full_name`, a field the attacker controls independently of `repository.owner.login` [7](#0-6) [8](#0-7) .
- `capture_labels` then persists `params.pull_request.labels.map(&:name)` onto the resolved stack's `PullRequest` via `pull_request.update!(labels: ...)` with no ownership check tying the write back to the org that "authenticated" the request [9](#0-8) .

Exploit flow: attacker crafts a `pull_request` `action=opened` JSON body with `repository.owner.login = "no-secret-org"` (a Shipit-configured org whose config has `webhook_secret: nil`) but `repository.full_name = "victim-org/victim-repo"` (the real, secret-protected victim org/stack), sends it unauthenticated to `POST /webhooks` with any garbage `X-Hub-Signature`. `verify_signature` looks up `no-secret-org`'s `GitHubApp`, finds `webhook_secret` blank, and returns `true` without ever checking the signature against `victim-org`'s actual secret. The handler proceeds and mutates the `victim-org/victim-repo` stack's `PullRequest#labels`.

Existing guards fail here because: `drop_unhandled_event` only checks the event type exists, not payload consistency; `ExplicitParameters` schema only validates types/presence, not cross-field consistency between `repository.owner.login` and `repository.full_name`; there is no `Repository` validator enforcing that a webhook's authenticating org matches the acted-upon repo's owner.

### Impact Explanation
An attacker who merely owns/controls a GitHub org configured in Shipit with a missing `webhook_secret` can forge webhook events that mutate a completely different, victim tenant's stack/PR state (`PullRequest#labels`), which is explicitly called out in scope as Critical: "a payload for one repository mutating another's stack, commit, task or team." This is repeatable for any `pull_request` handler (not just labels), against any repository/organization configured in the same Shipit instance, as long as one org in the multi-org config lacks a `webhook_secret`. The `merge_queue_enabled` amplification path (labels feeding into `ReviewStack#env` and then into deploy/merge command environments) could not be fully re-verified in this session due to tool-call exhaustion — `ReviewStack#env`/`PullRequest#labels` source was located but not read before the session ended, so I cannot confirm with certainty that label names become uppercased env keys reaching `PTY.spawn`/`merge!`. The core cross-tenant write (label mutation on an unauthenticated basis) is confirmed independent of that unverified detail.

### Likelihood Explanation
Requires: (1) Shipit deployed with the multi-org `github:` config format, (2) at least one configured org lacking `webhook_secret` (a documented, supported configuration, not exotic), (3) attacker knows or can enumerate which org that is (e.g., by testing signature-less webhooks), and (4) a target stack exists for the `full_name` chosen. Attacker cost is a single unauthenticated HTTP POST with a crafted JSON body — no credentials, no GitHub App access, no valid HMAC needed for the no-secret org. This is trivially repeatable and scriptable.

### Recommendation
Bind signature verification to the same repository identity the handlers act upon: derive the verifying `GitHubApp`/org from `repository.full_name`'s owner segment (or an explicit `Repository` lookup) rather than the independently-attacker-controlled `repository.owner.login`/`organization.login` fields, and reject the payload if `repository.owner.login` does not match the owner segment of `repository.full_name`. Additionally, do not allow `verify_webhook_signature` to silently pass (`return true unless webhook_secret`) for organizations that have live installations handling real repositories — require an explicit "public/no-auth" opt-in per org rather than blank-secret-implies-trusted.

### Proof of Concept
Minitest plan under `test/controllers/webhooks_controller_test.rb` (no live GitHub):
1. Stub `Shipit.secrets.github` with two orgs: `no-secret-org` (webhook_secret: nil) and `victim-org` (webhook_secret: "realsecret"), mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. Create a `victim-org/victim-repo` `Stack` with `merge_queue_enabled: true` and an existing `PullRequest` fixture with `labels: []`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, a garbage `X-Hub-Signature`, and JSON body: `{"action":"opened","number":1,"pull_request": {...}, "repository": {"owner": {"login": "no-secret-org"}, "full_name": "victim-org/victim-repo"}, "sender": {...}}`.
4. Assert response is `200`/`204` (not `422`), i.e., `verify_signature` did not reject despite the payload never being signed with `victim-org`'s secret — write this as the explicit equality check: assert `repository_owner ("no-secret-org") != repository.full_name.split('/').first ("victim-org")` yet the request is accepted.
5. Assert `victim-org/victim-repo`'s `PullRequest#labels` was updated to reflect the attacker-forged labels, proving a write occurred against a stack that was never authenticated by its own secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-66)
```ruby
          def repo_name
            params.repository["full_name"]
          end
```
