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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getVersionsFromMavenVersionRange(tt.verRange); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseMavenVersionRange() = %v, want %v", got, tt.want)
			}
		})
	}
}
