[1](#0-0) [2](#0-1)

### Citations

**File:** pkg/cmd/extension/http.go (L68-71)
```go
type releaseAsset struct {
	Name   string
	APIURL string `json:"url"`
}
```

**File:** pkg/cmd/extension/http.go (L100-103)
```go
	var f *os.File
	if f, downloadErr = os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755); downloadErr != nil {
		return
	}
```
