The retry loop in `waitUntilCodespaceConnectionReady` is bounded, not unbounded. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** internal/codespaces/codespaces.go (L18-23)
```go
var codespaceStatePollingBackoff backoff.BackOff = backoff.NewExponentialBackOff(
	backoff.WithInitialInterval(1*time.Second),
	backoff.WithMultiplier(1.02),
	backoff.WithMaxInterval(10*time.Second),
	backoff.WithMaxElapsedTime(5*time.Minute),
)
```

**File:** internal/codespaces/codespaces.go (L89-117)
```go
	err := backoff.Retry(func() error {
		var err error
		if firstRetry {
			firstRetry = false
		} else {
			codespace, err = apiClient.GetCodespace(ctx, codespace.Name, true)
			if err != nil {
				return backoff.Permanent(fmt.Errorf("error getting codespace: %w", err))
			}
		}

		if connectionReady(codespace) {
			return nil
		}

		// Only react to changes in the state (so that we don't try to start the codespace twice)
		if codespace.State != lastState {
			if codespace.State == api.CodespaceStateShutdown {
				err = apiClient.StartCodespace(ctx, codespace.Name)
				if err != nil {
					return backoff.Permanent(fmt.Errorf("error starting codespace: %w", err))
				}
			}
		}

		lastState = codespace.State

		return &TimeoutError{message: "codespace not ready yet"}
	}, backoff.WithContext(codespaceStatePollingBackoff, ctx))
```

**File:** pkg/cmd/codespace/ports.go (L324-365)
```go
func (a *App) ForwardPorts(ctx context.Context, selector *CodespaceSelector, ports []string, allInterfaces bool) (err error) {
	portPairs, err := getPortPairs(ports)
	if err != nil {
		return fmt.Errorf("get port pairs: %w", err)
	}

	codespace, err := selector.Select(ctx)
	if err != nil {
		return err
	}

	codespaceConnection, err := codespaces.GetCodespaceConnection(ctx, a, a.apiClient, codespace)
	if err != nil {
		return fmt.Errorf("error connecting to codespace: %w", err)
	}

	// Run forwarding of all ports concurrently, aborting all of
	// them at the first failure, including cancellation of the context.
	group, ctx := errgroup.WithContext(ctx)
	for _, pair := range portPairs {
		group.Go(func() error {
			listen, _, err := codespaces.ListenTCP(pair.local, allInterfaces)
			if err != nil {
				return err
			}
			defer listen.Close()

			a.errLogger.Printf("Forwarding ports: remote %d <=> local %s", pair.remote, listen.Addr())
			fwd, err := portforwarder.NewPortForwarder(ctx, codespaceConnection)
			if err != nil {
				return fmt.Errorf("failed to create port forwarder: %w", err)
			}
			defer safeClose(fwd, &err)

			opts := portforwarder.ForwardPortOpts{
				Port: pair.remote,
			}
			return fwd.ForwardPortToListener(ctx, opts, listen)
		})
	}
	return group.Wait() // first error
}
```
