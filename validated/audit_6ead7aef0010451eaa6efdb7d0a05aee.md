[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** pkg/logging/logging.go (L94-105)
```go
func (l *Logger) DeleteErrorFile() {
	if l.errorFile == "" {
		return
	}
	errorFile := filepath.Join(l.root, l.errorFile)
	if err := os.Remove(errorFile); err != nil {
		if os.IsNotExist(err) {
			return
		}
		l.Logger.Error(err, "can't delete the error-file", "filename", errorFile)
	}
}
```

**File:** pkg/logging/logging.go (L116-120)
```go
	tmpFile, err := os.CreateTemp(l.root, "tmp-err-")
	if err != nil {
		l.Logger.Error(err, "can't create temporary error-file", "directory", l.root, "prefix", "tmp-err-")
		return
	}
```

**File:** pkg/logging/logging.go (L132-136)
```go
	errorFile := filepath.Join(l.root, l.errorFile)
	if err := os.Rename(tmpFile.Name(), errorFile); err != nil {
		l.Logger.Error(err, "can't rename to error-file", "temp-file", tmpFile.Name(), "error-file", errorFile)
		return
	}
```
