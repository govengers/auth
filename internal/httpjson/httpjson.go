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
// Errors are plain and never repeat request text; callers wrap them as *auth.Error{Kind: auth.ErrInvalidRequest}.
func Decode(writer http.ResponseWriter, request *http.Request, target any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, maximumBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return decodeError(err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON body must hold exactly one value")
	}
	return nil
}

// decodeError says what is wrong with a body without its text: encoding/json's messages quote the request (an
// unknown field's name, which may be an email address), and the error reaches the outcome and the wide event.
func decodeError(err error) error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return fmt.Errorf("JSON body exceeds %d bytes", maximumBodyBytes)
	}
	return errors.New("JSON body does not decode: malformed, a value of the wrong type or an unknown field")
}

// internalErrorBody is auth.WriteError's body for an internal error (this package cannot import auth).
const internalErrorBody = `{"code":"internal","message":"internal error"}`

// Write writes body as JSON with status, Content-Type application/json and Cache-Control no-store. A body
// that does not encode (an identity carrying an invalid auth.Permission from application code) is answered
// 500 internal instead, before anything was written.
func Write(writer http.ResponseWriter, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		status, encoded = http.StatusInternalServerError, []byte(internalErrorBody)
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	// A write error means the client is gone and there is nobody left to answer.
	_, _ = writer.Write(append(encoded, '\n'))
}
