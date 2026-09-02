### Title
Verifier/handler field divergence lets an org-without-`webhook_secret` "authenticate" a forged `pull_request:labeled` webhook that archives/unarchives an arbitrary repository's review stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the signing config using `repository_owner`, which falls back to `params.dig('organization','login')` when `repository.owner.login` is absent. `GitHubApp#verify_webhook_signature` unconditionally returns `true` when the selected org has no `webhook_secret` configured. `LabeledHandler`, however, resolves the target repository/stack from the independent `params.repository.full_name` field, so an attacker can bind the verification decision to a lenient, secret-less org while pointing the actual mutation at any other repository's review stack.

### Finding Description
The broken binding: the code implicitly assumes `repository_owner` (used to choose the `GitHubApp`/secret for signature verification) always equals the owner segment of `repository.full_name` (used by the handler to locate the target `Repository`/`Stack`). In fact these are two independently attacker-controlled JSON fields, and nothing enforces `repository_owner == repository.full_name.split('/').first`.

Path:
1. `Shipit::WebhooksController#repository_owner` — `params.dig('repository','owner','login') || params.dig('organization','login')`. [1](#0-0) 
2. `#verify_signature` uses that value to pick the `GitHubApp`: `Shipit.github(organization: repository_owner)` then calls `verify_webhook_signature`. [2](#0-1) 
3. `GitHubApp#verify_webhook_signature` — `return true unless webhook_secret` — i.e., for any org configured without a `webhook_secret`, every signature (even garbage/absent) is accepted. [3](#0-2) 
4. `LabeledHandler#repository` resolves the actual target repository from `params.repository.full_name`, a completely separate field from the one used in steps 1-3, and there is no code anywhere cross-checking these two values against each other. [4](#0-3) 
5. `LabeledHandler#handle` then calls `stack.archive!`/`stack.unarchive!` based on the provisioning label, mutating the review stack for whatever repository `full_name` names. [5](#0-4) 
6. The `LabeledHandler` params schema requires `repository.full_name` but does not require `repository.owner.login`, so an attacker can omit the latter to force the `repository_owner` fallback to `organization.login` while still supplying an arbitrary `repository.full_name`. [6](#0-5) 

Exploit request: an unauthenticated `POST /webhooks` with header `X-Github-Event: pull_request`, an arbitrary/garbage `X-Hub-Signature`, and a JSON body containing `organization.login = "org-without-secret"` (a configured Shipit org lacking `webhook_secret`), no `repository.owner.login`, and `repository.full_name = "victim-org/victim-repo"` (any repository with review stacks enabled) plus `action: "labeled"`, a valid-looking `pull_request` object/labels, and `sender`. Because `repository_owner` resolves to `"org-without-secret"`, `verify_webhook_signature` returns `true` unconditionally (step 3), the request passes `before_action :verify_signature`, and `LabeledHandler` archives or unarchives `victim-org/victim-repo`'s review stack per the forged labels — a repository that never authenticated this request and may belong to an entirely different, properly-secured org.

None of the existing guards prevent this: `drop_unhandled_event` and `check_if_ping` are unrelated; `ExplicitParameters` only validates presence/types, not cross-field consistency between `repository_owner` and `repository.full_name`; there is no `force_github_authentication`, `User#authorized?`, or repository-ownership check in the webhook path (it's intentionally unauthenticated, relying solely on signature verification, which is the exact control being subverted).

### Impact Explanation
The attacker causes a state-changing effect — archiving or unarchiving a review stack — for a repository (`victim-org/victim-repo`) that is not the repository/org that authenticated the request. This is a payload for one (secret-less) org's "identity" mutating another repository's stack, matching the Critical category "a payload for one repository mutating another's stack." Any Shipit deployment configured with multiple orgs (per `docs/setup.md`'s "Using Multiple Github Applications" pattern) where at least one org has no `webhook_secret` set is fully exposed: the attacker can target any repository with review stacks enabled, regardless of that repository's own org's webhook_secret configuration, since the target is picked purely from `repository.full_name` and never re-validated. This is repeatable per request with no rate limiting relevant to the impact itself.

### Likelihood Explanation
Preconditions: (a) the Shipit instance uses the multi-org `github:` config format, (b) at least one configured org has no `webhook_secret` (an explicitly documented/supported configuration, per `config/secrets.development.shopify.yml` showing `webhook_secret: # nil` as a valid example), and (c) the target repository has `review_stacks_enabled` and a matching open PR label state. No secrets, sessions, or GitHub credentials are required by the attacker — only knowledge of a victim org name with no secret and a target repository's `full_name`, both of which may be discoverable (e.g., from public Shipit UI, GitHub org listings, or documentation). The request is a single unauthenticated HTTP POST, trivially repeatable.

### Recommendation
Do not allow `repository_owner`/`organization.login` fallback to select a verifier independently of the repository actually acted upon by handlers. Specifically: derive the repository owner used for signature-verifier selection from the same `repository.full_name` field the handlers use (or require `repository.owner.login` to be present and match the owner segment of `repository.full_name`), and reject the webhook if they diverge. Additionally, treat a missing/blank `webhook_secret` as "reject all webhooks for this org" rather than "accept all webhooks unconditionally" in `GitHubApp#verify_webhook_signature`, or require every configured org to have a non-blank `webhook_secret`.

### Proof of Concept
Minitest plan under `test/controllers/webhooks_controller_test.rb` (or a new test), no live GitHub:

1. Configure two orgs in test secrets: `org_without_secret` (no `webhook_secret`) and `org_with_secret` (`webhook_secret: "s3cr3t"`).
2. Create `shipit_repositories(:victim)` under `org_with_secret/victim-repo` with `review_stacks_enabled: true`, provisioning behavior set (e.g., `provisioning_behavior: allow_with_label`), and a review `Stack` that is currently unarchived (or archived, per scenario), associated to a PR number.
3. Build payload:
   ```ruby
   payload = {
     action: 'labeled',
     number: 42,
     pull_request: { id: 1, number: 42, url: '...', title: 't', state: 'open', additions: 1, deletions: 0,
                      head: { sha: 'abc', ref: 'branch' }, user: { login: 'attacker' },
                      assignees: [], labels: [{ name: repository.provisioning_label_name }] },
     repository: { full_name: 'org_with_secret/victim-repo' }, # no owner.login present
     organization: { login: 'org_without_secret' },
     sender: { login: 'attacker' }
   }.to_json
   ```
4. `@request.headers['X-Github-Event'] = 'pull_request'; @request.headers['X-Hub-Signature'] = 'sha1=deadbeef'` (garbage signature, no relation to `org_with_secret`'s real secret).
5. Assert equality-before: `stack.archived? == original_state` (e.g., `false`).
6. `post :create, body: payload, as: :json`.
7. Assert `response.status == 200`.
8. Assert equality-after has changed despite the signature never being validated against `org_with_secret`'s secret: `stack.reload.archived? != original_state` — proving that a payload "authenticated" only under `org_without_secret`'s lenient (no-secret) verifier mutated `org_with_secret`'s `victim-repo` stack.
9. Control assertion: repeat with `organization.login` removed and `repository.owner.login = 'org_with_secret'` present (forcing correct verifier selection with the real secret) and the same forged signature — assert `response.status == 422` and the stack state is unchanged, demonstrating the divergence is caused specifically by the fallback selecting the wrong (secret-less) verifier.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L33-39)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
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
