### No vulnerability found for this question.

**Reasoning:** In `--one-time` mode, the main loop calls `os.Exit(exitCode)` immediately after a single successful sync completes (after hooks finish and `log.DeleteErrorFile()` runs), terminating the entire process — including the goroutine serving the HTTP `/` endpoint [1](#0-0) . There is no way for the process to keep the HTTP server alive to serve stale "ready" responses after subsequent sync failures, because there are no subsequent syncs in one-time mode: the loop only continues retrying (with `failCount`/`getMaxFailures` gating) *until* the first success, at which point it exits outright [2](#0-1) .

The `setRepoReady()`/`getRepoReady()` latch itself has no `unset` path and never resets on failure [3](#0-2) , but this is documented, intended behavior for the `/` endpoint: the README explicitly states it "return[s] a 5xx error until the first sync is complete, and a 200 status thereafter" — i.e., readiness is defined as "first sync completed," not "data is currently fresh" [4](#0-3) . That contradicts the invariant asserted in the question, which is not actually the specified contract of this endpoint.

Separately, `Logger.Error`, `writeContent`, `ExportError`, and `DeleteErrorFile` in `pkg/logging/logging.go` have no interaction with the `repoReady` flag at all — they only manage a JSON error file via temp-file-then-rename in `--root` [5](#0-4) . There is no code path by which attacker-controlled repo content, refs, or HTTP requests can influence this logging/error-file logic to affect readiness latching, so the specific function targets named in the question are unrelated to the described exploit narrative.

Given the process-exit-on-success behavior of `--one-time` and the documented semantics of the readiness endpoint, the described attack path is not reachable/valid as scoped.

### Citations

**File:** main.go (L1052-1073)
```go
	for {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), *flSyncTimeout)

		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
			failCount++
			updateSyncMetrics(metricKeyError, start)
			if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
				log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
				os.Exit(1)
			}
			log.Error(err, "error syncing repo, will retry", "failCount", failCount)
		} else {
			if !initialSyncDone {
				initialSyncDone = true
				waitTime = *flPeriod
				if *flInitPeriod != *flPeriod {
					log.V(0).Info("initial sync complete, switching to normal period", "initPeriod", flInitPeriod.String(), "period", flPeriod.String())
				}
			}
			// this might have been called before, but also might not have
			setRepoReady()
```

**File:** main.go (L1095-1118)
```go
			if *flOneTime {
				// Wait for hooks to complete at least once, if not nil, before
				// checking whether to stop program.
				// Assumes that if hook channels are not nil, they will have at
				// least one value before getting closed
				exitCode := 0 // is 0 if all hooks succeed, else is 1
				if prePubExechookRunner != nil && changed {
					if err := prePubExechookRunner.WaitForCompletion(); err != nil {
						exitCode = 1
					}
				}
				if exechookRunner != nil {
					if err := exechookRunner.WaitForCompletion(); err != nil {
						exitCode = 1
					}
				}
				if webhookRunner != nil {
					if err := webhookRunner.WaitForCompletion(); err != nil {
						exitCode = 1
					}
				}
				log.DeleteErrorFile()
				log.V(0).Info("exiting after one sync", "status", exitCode)
				os.Exit(exitCode)
```

**File:** main.go (L1273-1287)
```go
// repoReady indicates that the repo has been synced.
var readyLock sync.Mutex
var repoReady = false

func getRepoReady() bool {
	readyLock.Lock()
	defer readyLock.Unlock()
	return repoReady
}

func setRepoReady() {
	readyLock.Lock()
	defer readyLock.Unlock()
	repoReady = true
}
```

**File:** README.md (L397-402)
```markdown
    --http-bind <string>, $GITSYNC_HTTP_BIND
            The bind address (including port) for git-sync's HTTP endpoint.
            The '/' URL of this endpoint is suitable for Kubernetes startup and
            liveness probes, returning a 5xx error until the first sync is
            complete, and a 200 status thereafter. If not specified, the HTTP
            endpoint is not enabled.
```

**File:** pkg/logging/logging.go (L108-139)
```go
func (l *Logger) writeContent(content []byte) {
	if _, err := os.Stat(l.root); os.IsNotExist(err) {
		fileMode := os.FileMode(0775) // umask applies
		if err := os.Mkdir(l.root, fileMode); err != nil {
			l.Logger.Error(err, "can't create the root directory", "root", l.root)
			return
		}
	}
	tmpFile, err := os.CreateTemp(l.root, "tmp-err-")
	if err != nil {
		l.Logger.Error(err, "can't create temporary error-file", "directory", l.root, "prefix", "tmp-err-")
		return
	}
	defer func() {
		if err := tmpFile.Close(); err != nil {
			l.Logger.Error(err, "can't close temporary error-file", "filename", tmpFile.Name())
		}
	}()

	if _, err = tmpFile.Write(content); err != nil {
		l.Logger.Error(err, "can't write to temporary error-file", "filename", tmpFile.Name())
		return
	}

	errorFile := filepath.Join(l.root, l.errorFile)
	if err := os.Rename(tmpFile.Name(), errorFile); err != nil {
		l.Logger.Error(err, "can't rename to error-file", "temp-file", tmpFile.Name(), "error-file", errorFile)
		return
	}
	if err := os.Chmod(errorFile, 0644); err != nil {
		l.Logger.Error(err, "can't change permissions on the error-file", "error-file", errorFile)
	}
```
