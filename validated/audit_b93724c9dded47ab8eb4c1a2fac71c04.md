[1](#0-0) [2](#0-1)

### Citations

**File:** pkg/logging/logging.go (L49-83)
```go
func (l *Logger) Error(err error, msg string, kvList ...any) {
	l.Logger.WithCallDepth(1).Error(err, msg, kvList...)
	if l.errorFile == "" {
		return
	}
	payload := struct {
		Msg  string
		Err  string
		Args map[string]any
	}{
		Msg:  msg,
		Args: map[string]any{},
	}
	if err != nil {
		payload.Err = err.Error()
	}
	if len(kvList)%2 != 0 {
		kvList = append(kvList, "<no-value>")
	}
	for i := 0; i < len(kvList); i += 2 {
		k, ok := kvList[i].(string)
		if !ok {
			k = fmt.Sprintf("%v", kvList[i])
		}
		payload.Args[k] = kvList[i+1]
	}
	jb, err := json.Marshal(payload)
	if err != nil {
		l.Logger.Error(err, "can't encode error payload")
		content := fmt.Sprintf("%v", err)
		l.writeContent([]byte(content))
	} else {
		l.writeContent(jb)
	}
}
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
