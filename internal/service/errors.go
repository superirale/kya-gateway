package service

import "fmt"

// APIError carries an HTTP status and stable error code to the API layer.
type APIError struct {
	Status int    `json:"-"`
	Code   string `json:"code"`
	Msg    string `json:"message"`
}

func (e *APIError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Msg) }

func badRequest(msg string) *APIError   { return &APIError{400, "MALFORMED_REQUEST", msg} }
func invalid(msg string) *APIError      { return &APIError{422, "INVALID_SCHEMA", msg} }
func unauthorized(msg string) *APIError { return &APIError{401, "UNAUTHENTICATED", msg} }
func forbidden(msg string) *APIError    { return &APIError{403, "FORBIDDEN", msg} }
func notFound(msg string) *APIError     { return &APIError{404, "NOT_FOUND", msg} }
func conflict(code, msg string) *APIError {
	return &APIError{409, code, msg}
}

// Exported constructors for the HTTP layer.
var (
	BadRequest   = badRequest
	Invalid      = invalid
	Unauthorized = unauthorized
	Forbidden    = forbidden
	NotFound     = notFound
)
