// Package httpjson decodes strict JSON request bodies and writes JSON responses. Its functions are safe
// for concurrent use.
package httpjson

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

const maximumBodyBytes = 64 << 10

// Decode requires Content-Type application/json, reads at most 64 KiB, rejects unknown fields and trailing data.
// Errors are plain; callers wrap them as *auth.Error{Kind: auth.ErrInvalidRequest}.
func Decode(writer http.ResponseWriter, request *http.Request, target any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, maximumBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON body: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON body must hold exactly one value")
	}
	return nil
}

// Write writes body as JSON with status, Content-Type application/json and Cache-Control no-store.
func Write(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	// Bodies are the library's own response types, which always encode; a write error means the client is
	// gone and there is nobody left to answer.
	_ = json.NewEncoder(writer).Encode(body)
}
