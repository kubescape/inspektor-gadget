package syscalls

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSyscallExecve(t *testing.T) {
	// Captured from Linux 7.0.0-1017-azure. The trailing __data_loc field
	// contains a copy of filename, not an additional syscall argument.
	format, err := os.ReadFile("testdata/sys_enter_execve.format")
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.ReplaceAll(string(format), "\tfield:__data_loc char[] __filename_val;\toffset:40;\tsize:4;\tsigned:0;\n", "")
	legacy = strings.ReplaceAll(legacy, ` \"%s\"`, "")
	legacy = strings.ReplaceAll(legacy, ", __get_str(__filename_val)", "")
	for name, input := range map[string]string{
		"captured": string(format),
		"legacy":   legacy,
	} {
		t.Run(name, func(t *testing.T) {
			declaration, err := parseSyscall("execve", input)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, "execve", declaration.name)
			assert.Equal(t, uint8(3), declaration.GetParameterCount())
			assert.Equal(t, []param{
				{position: 1, name: "filename", isPointer: true},
				{position: 2, name: "argv", isPointer: true},
				{position: 3, name: "envp", isPointer: true},
			}, declaration.params)
		})
	}
}

func TestParseLineInternalFields(t *testing.T) {
	for _, test := range []struct {
		name     string
		field    string
		expected *param
	}{
		{name: "syscall number", field: "int __syscall_nr"},
		{name: "filename metadata", field: "__data_loc char[] __filename_val"},
		{name: "other string metadata", field: "__data_loc char[] __pathname_val"},
		{name: "filename pointer", field: "const char * filename", expected: &param{position: 1, name: "filename", isPointer: true}},
		{name: "metadata-like pointer name", field: "const char * __filename_val", expected: &param{position: 1, name: "__filename_val", isPointer: true}},
		{name: "scalar", field: "int flags", expected: &param{position: 1, name: "flags"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, err := parseLine("\tfield:"+test.field+";\toffset:16;\tsize:8;\tsigned:0;", 9)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestGetSyscallNumberByName(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		description string
		name        string
		number      int
		arch        string
		expectedok  bool
	}{
		{
			description: "getting syscalls number from name",
			name:        "open_tree",
			number:      428,
			arch:        "amd64",
			expectedok:  true,
		},
		{
			description: "getting syscall number from name",
			name:        "close_range",
			number:      436,
			arch:        "amd64",
			expectedok:  true,
		},
		{
			description: "getting syscall number from name",
			name:        "accept",
			number:      200,
			arch:        "arm64",
			expectedok:  true,
		},
		{
			description: "getting syscall number from name",
			name:        "futex",
			number:      98,
			arch:        "arm64",
			expectedok:  true,
		},
		{
			description: "empty syscall name",
			name:        "",
			number:      -1,
			expectedok:  false,
			arch:        "arm64",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s (%s)", test.description, test.arch), func(t *testing.T) {
			if runtime.GOARCH != test.arch {
				t.Skipf("skipping test for %s, only for %s", runtime.GOARCH, test.arch)
			}
			number, ok := GetSyscallNumberByName(test.name)
			assert.Equal(test.expectedok, ok, "expected ok to be %v, got %v", test.expectedok, ok)
			assert.Equal(test.number, number, "expected number to be %d, got %d", test.number, number)
		})
	}
}

func TestGetSyscallNameByNumber(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		description string
		name        string
		number      int
		arch        string
		expectedok  bool
	}{
		{
			description: "getting syscalls name from number",
			name:        "open_tree",
			number:      428,
			arch:        "amd64",
			expectedok:  true,
		},
		{
			description: "getting syscall name from number",
			name:        "close_range",
			number:      436,
			arch:        "amd64",
			expectedok:  true,
		},
		{
			description: "getting syscall name from number",
			name:        "accept",
			number:      200,
			arch:        "arm64",
			expectedok:  true,
		},
		{
			description: "getting syscall name from number",
			name:        "futex",
			number:      98,
			arch:        "arm64",
			expectedok:  true,
		},
		{
			description: "empty syscalls number",
			name:        "",
			number:      -1,
			expectedok:  false,
			arch:        "arm64",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s (%s)", test.description, test.arch), func(t *testing.T) {
			if runtime.GOARCH != test.arch {
				t.Skipf("skipping test for %s, only for %s", runtime.GOARCH, test.arch)
			}
			name, ok := GetSyscallNameByNumber(test.number)
			assert.Equal(test.expectedok, ok, "expected ok to be %v, got %v", test.expectedok, ok)
			assert.Equal(test.name, name, "expected number to be %d, got %d", test.name, name)
		})
	}
}
