// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnerRowsNative(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler required")
	}
	header, err := os.ReadFile("../full/owner_roles.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(header)
	start := strings.Index(text, "__noinline int eo_rows_complete(")
	end := strings.Index(text, "static __noinline int eo_validate_task_impl(")
	if start < 0 || end <= start {
		t.Fatal("actual completeness predicate missing")
	}
	source := `
#include <stdint.h>
#include <assert.h>
#define __noinline __attribute__((noinline))
#define ER_ACTIVE 8
#define ER_SLOTS 16
#define __u32 uint32_t
struct er_row{uint64_t uid,epoch,role;};
struct er_authority{uint64_t uid,epoch,root;uint32_t fresh,reserved;};
struct eo_work{struct{uint32_t count,reserved;struct er_authority active[8];}candidate;struct{struct er_row rows[16];}merge;};
` + text[start:end] + `
int main(void){
 struct eo_work w={0};assert(eo_rows_complete(&w)==0);assert(eo_rows_complete(0)==-1);
 w.candidate.count=9;assert(eo_rows_complete(&w)==-1);w.candidate.count=8;
 for(int i=0;i<8;i++){w.candidate.active[i].uid=i+1;w.candidate.active[i].epoch=2;w.merge.rows[i]=(struct er_row){i+1,2,3};}
 assert(eo_rows_complete(&w)==0);
 for(int i=0;i<8;i++){
  struct er_row saved=w.merge.rows[i];w.merge.rows[i].role=0;assert(eo_rows_complete(&w)==-1);w.merge.rows[i]=saved;
  w.merge.rows[15]=saved;assert(eo_rows_complete(&w)==-1);w.merge.rows[15]=(struct er_row){0};
  w.merge.rows[i].epoch++;assert(eo_rows_complete(&w)==-1);w.merge.rows[i]=saved;
 }
 assert(eo_rows_complete(&w)==0);return 0;
}
`
	dir := t.TempDir()
	file := filepath.Join(dir, "rows.c")
	binary := filepath.Join(dir, "rows")
	if err = os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-O2", "-Wall", "-Wextra", "-Werror", file, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
