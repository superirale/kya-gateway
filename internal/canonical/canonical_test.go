package canonical

import (
	"errors"
	"testing"
)

func TestCanonicalizeSortsAndCompacts(t *testing.T) {
	got, err := Canonicalize([]byte(`{ "b": 1, "a": {"y": [true, null, "x"], "x": -0 }, "c": "é\n\u0001" }`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"x":0,"y":[true,null,"x"]},"b":1,"c":"é\n\u0001"}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestCanonicalRejectsAmbiguity(t *testing.T) {
	cases := map[string]error{
		`{"a":1,"a":2}`:               ErrDuplicateKey,
		`{"n":{"a":1,"a":1}}`:         ErrDuplicateKey,
		`{"amount":1.5}`:              ErrFloat,
		`{"amount":1e3}`:              ErrFloat,
		`{"amount":9007199254740993}`: ErrUnsafeInt,
	}
	for in, want := range cases {
		if _, err := Canonicalize([]byte(in)); !errors.Is(err, want) {
			t.Errorf("%s: got %v want %v", in, err, want)
		}
	}
	if _, err := Canonicalize([]byte(`{"a":1} {}`)); err == nil {
		t.Error("expected trailing data error")
	}
}

func TestDoesNotHTMLEscape(t *testing.T) {
	got, err := Marshal(map[string]string{"k": "<a&b>"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"k":"<a&b>"}` {
		t.Fatalf("got %s", got)
	}
}

func TestSigningMessage(t *testing.T) {
	got, err := SigningMessage("D", map[string]int{"z": 1, "a": 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "D\n{\"a\":2,\"z\":1}" {
		t.Fatalf("got %q", got)
	}
}
