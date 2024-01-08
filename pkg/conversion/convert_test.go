package conversion

import (
	"reflect"
	"testing"
)

func Test_parseMavenVersionRange(t *testing.T) {
	tests := []struct {
		name     string
		verRange string
		want     []string
	}{
		{
			name:     "case 1",
			verRange: "[6,7]",
			want:     []string{"6", "7"},
		},
		{
			name:     "case 2",
			verRange: "[6,7)",
			want:     []string{"6"},
		},
		{
			name:     "case 3",
			verRange: "(6,7]",
			want:     []string{"7"},
		},
		{
			name:     "case 4",
			verRange: "(6,8)",
			want:     []string{"7"},
		},
		{
			name:     "case 5",
			verRange: "(6,7)",
			want:     []string{},
		},
		{
			name:     "case 6",
			verRange: "(,7]",
			want:     []string{"7-"},
		},
		{
			name:     "case 7",
			verRange: "[6,)",
			want:     []string{"6+"},
		},
		{
			name:     "case 8",
			verRange: "[6]",
			want:     []string{"6"},
		},
		{
			name:     "case 9",
			verRange: "[2.0,2.1,2.2,2.3]",
			want:     []string{"2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getVersionsFromMavenVersionRange(tt.verRange); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseMavenVersionRange() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_convertToCamel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "key without dash, no conversion",
			input: "className",
			want:  "className",
		},
		{
			name:  "key with dash, must be converted",
			input: "package-remainder",
			want:  "packageRemainder",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertToCamel(tt.input); got != tt.want {
				t.Errorf("convertToCamel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_convertMessageString(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want string
	}{
		{
			name: "message with custom vars",
			msg:  "test message {{package-remainder}} was found {{type}} and {{some other}}",
			want: "test message {{packageRemainder}} was found {{type}} and {{someOther}}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertMessageString(tt.msg); got != tt.want {
				t.Errorf("convertMessageString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_trimMessage(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want string
	}{
		{
			name: "message with trailing and ending newlines",
			msg:  "\n\ntest    message\n\n",
			want: "test message",
		},
		{
			name: "message with newlines in the middle",
			msg:  "\n\ntest \n message\n\n",
			want: "test \n message",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trimMessage(tt.msg); got != tt.want {
				t.Errorf("convertMessageString() = %v, want %v", got, tt.want)
			}
		})
	}
}
