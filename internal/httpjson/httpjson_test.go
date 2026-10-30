package httpjson

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type loginInput struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

func TestDecode(t *testing.T) {
	testCases := []struct {
		name        string
		contentType string
		body        string
		want        loginInput
		wantError   bool
	}{
		{name: "valid", contentType: "application/json", body: `{"identifier":"ada","password":"pw"}`, want: loginInput{Identifier: "ada", Password: "pw"}},
		{name: "charset parameter", contentType: "application/json; charset=utf-8", body: `{"identifier":"ada"}`, want: loginInput{Identifier: "ada"}},
		{name: "trailing whitespace", contentType: "application/json", body: "{\"identifier\":\"ada\"}\n  ", want: loginInput{Identifier: "ada"}},
		{name: "missing content type", body: `{}`, wantError: true},
		{name: "form content type", contentType: "application/x-www-form-urlencoded", body: `{}`, wantError: true},
		{name: "text content type", contentType: "text/plain", body: `{}`, wantError: true},
		{name: "malformed content type", contentType: "application/json; =", body: `{}`, wantError: true},
		{name: "unknown field", contentType: "application/json", body: `{"identifier":"ada","admin":true}`, wantError: true},
		{name: "trailing value", contentType: "application/json", body: `{"identifier":"ada"}{"identifier":"eve"}`, wantError: true},
		{name: "trailing garbage", contentType: "application/json", body: `{"identifier":"ada"} x`, wantError: true},
		{name: "empty body", contentType: "application/json", body: "", wantError: true},
		{name: "syntax error", contentType: "application/json", body: `{"identifier":`, wantError: true},
		{name: "wrong type", contentType: "application/json", body: `{"identifier":1}`, wantError: true},
		{name: "too large", contentType: "application/json", body: `{"identifier":"` + strings.Repeat("a", 64<<10) + `"}`, wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", strings.NewReader(testCase.body))
			if testCase.contentType != "" {
				request.Header.Set("Content-Type", testCase.contentType)
			}
			var got loginInput
			err := Decode(httptest.NewRecorder(), request, &got)
			if testCase.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.want, got)
		})
	}
}

// Decode errors become the cause of a refusal and reach the outcome and the wide event, so they must not
// repeat request text (LOG-009): an unknown field's name may be an email address or a secret.
func TestDecodeErrorsRepeatNoRequestText(t *testing.T) {
	const canary = "alice@example.test"
	testCases := []struct {
		name      string
		body      string
		wantError string
	}{
		{name: "unknown field", body: `{"` + canary + `":true}`, wantError: "does not decode"},
		{name: "unknown nested field", body: `{"identifier":"ada"}{"` + canary + `":true}`, wantError: "exactly one value"},
		{name: "wrong type", body: `{"identifier":{"` + canary + `":1}}`, wantError: "does not decode"},
		{name: "syntax error", body: `{"identifier":` + canary + `}`, wantError: "does not decode"},
		{name: "too large", body: `{"` + canary + strings.Repeat("a", 64<<10) + `":true}`, wantError: "exceeds 65536 bytes"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", strings.NewReader(testCase.body))
			request.Header.Set("Content-Type", "application/json")

			err := Decode(httptest.NewRecorder(), request, &loginInput{})

			require.Error(t, err)
			require.NotContains(t, err.Error(), "alice")
			require.ErrorContains(t, err, testCase.wantError)
		})
	}
}

func TestDecodeAcceptsBodyAtTheLimit(t *testing.T) {
	padding := strings.Repeat("a", 64<<10-len(`{"identifier":""}`))
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", strings.NewReader(`{"identifier":"`+padding+`"}`))
	request.Header.Set("Content-Type", "application/json")

	var got loginInput
	require.NoError(t, Decode(httptest.NewRecorder(), request, &got))
	require.Equal(t, padding, got.Identifier)
}

func TestWrite(t *testing.T) {
	recorder := httptest.NewRecorder()

	Write(recorder, http.StatusCreated, map[string]string{"code": "created"})

	require.Equal(t, http.StatusCreated, recorder.Code)
	require.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	require.JSONEq(t, `{"code":"created"}`, recorder.Body.String())
}

func TestWriteAnswers500ForABodyThatDoesNotEncode(t *testing.T) {
	recorder := httptest.NewRecorder()

	Write(recorder, http.StatusOK, map[string]any{"channel": make(chan int)})

	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	require.JSONEq(t, `{"code":"internal","message":"internal error"}`, recorder.Body.String())
}
