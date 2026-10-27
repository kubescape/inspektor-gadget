#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
#define ER_ACTIVE 8
#define ER_UNKNOWN UINT64_MAX
#define FE_INVALID 1
#define FE_ROLE_CONFLICT 3
#define EO_FAULT_STATE 8
struct linux_binprm {int unused;};
struct er_row {__u64 uid,epoch,role;};
struct eo_exec_tx {__u64 bprm,cgroup,generation,owner_cookie;__u32 owned,slot,suppress,checks;struct er_row pending[8];};
struct eo_task {int lock;__u32 flags;struct {__u64 version;struct er_row rows[16];}committed;struct eo_exec_tx exec;};
struct eo_config {__u64 cookie,cgroup;__u32 gate_slot;};
struct fe_header {__u64 generation;};
struct er_authority {__u64 uid,epoch,root;};
struct eo_work {__u64 a_epoch;struct {__u64 base_version;}merge;struct {__u32 count;struct er_authority active[8];}candidate;};
struct fe_decision {__u32 deny,error;__u64 proposed_roles[8];};
static struct eo_task task;
static struct eo_config config;
static struct fe_header head;
static struct eo_work work;
static struct linux_binprm bprm;
static int locked,hard_fault,invalid_rows;
static __u64 fault_generation,fault_bits;
static struct eo_config*eo_config(void){return &config;}
static void*bpf_get_current_task_btf(void){return &task;}
static struct eo_task*eo_lookup_task(void*current){(void)current;return &task;}
static const void*eo_blob(int slot,int key){(void)slot;(void)key;assert(!locked);return &head;}
static void bpf_spin_lock(int*lock){(void)lock;assert(!locked);locked=1;}
static void bpf_spin_unlock(int*lock){(void)lock;assert(locked);locked=0;}
static void eo_clear_pending(struct eo_exec_tx*tx){memset(tx->pending,0,sizeof(tx->pending));}
static void eo_exec_suppress(void){assert(!locked);task.exec.suppress=1;eo_clear_pending(&task.exec);}
static void eo_quarantine(struct eo_task*s){assert(!locked);s->flags|=2;hard_fault=1;}
static void eo_fault(int bit){assert(!locked);hard_fault|=bit;}
static void eo_data_fault(__u64 generation,__u64 bit){assert(!locked);fault_generation=generation;fault_bits|=bit;}
static struct eo_work*eo_get_work(void){assert(!locked);return &work;}
static void eo_put_work(struct eo_work*w){(void)w;assert(!locked);}
static int eo_load_candidate(struct eo_work*w,int slot,int mask){(void)slot;(void)mask;assert(!locked);w->a_epoch=head.generation;return 0;}
static int eo_validate_task(struct eo_task*s,struct eo_work*w){assert(!locked);w->merge.base_version=s->committed.version;return invalid_rows?-1:0;}
/* ACTUAL_PROPOSAL */
static void reset(void){
 memset(&task,0,sizeof(task));memset(&work,0,sizeof(work));
 config=(struct eo_config){99,123,4};head.generation=7;
 task.flags=1;task.committed.version=2;task.committed.rows[0]=(struct er_row){1,2,777};
 task.exec=(struct eo_exec_tx){.bprm=(__u64)&bprm,.cgroup=123,.generation=7,.owner_cookie=99,.owned=1,.slot=4};
 work.candidate.count=1;work.candidate.active[0]=(struct er_authority){1,2,777};
 hard_fault=invalid_rows=locked=0;fault_generation=fault_bits=0;
}
static void preserved(void){assert(task.flags==1);assert(task.committed.version==2);assert(task.committed.rows[0].role==777);assert(!hard_fault);}
int main(void){
 for(__u32 error=1;error<=3;error++){
  reset();struct fe_decision d={.error=error};task.exec.pending[0]=(struct er_row){1,2,42};
  assert(eo_exec_propose(&bprm,&d)==-1);preserved();assert(task.exec.suppress&&!task.exec.pending[0].uid);assert(fault_generation==7&&fault_bits==(1ULL<<error));
 }
 reset();struct fe_decision d={.deny=1};assert(!eo_exec_propose(&bprm,&d));preserved();assert(task.exec.suppress&&!fault_generation);
 reset();d=(struct fe_decision){.proposed_roles={10}};assert(!eo_exec_propose(&bprm,&d));preserved();assert(task.exec.pending[0].role==10);
 d.proposed_roles[0]=20;assert(eo_exec_propose(&bprm,&d)==-1);preserved();assert(task.exec.suppress&&!task.exec.pending[0].uid&&fault_generation==7&&fault_bits==(1ULL<<3));
 // A later revision/attempt retains committed actor role and can propose again.
 task.exec.suppress=0;task.exec.generation=head.generation=8;d.proposed_roles[0]=30;
 assert(!eo_exec_propose(&bprm,&d));preserved();assert(task.exec.pending[0].role==30&&fault_generation==7);
 // Transaction identity/epoch mismatch and missing accepted rows remain hard.
 for(int failure=0;failure<7;failure++){
  reset();d=(struct fe_decision){.proposed_roles={10}};
  switch(failure){case 0:task.exec.bprm++;break;case 1:task.exec.owner_cookie++;break;case 2:task.exec.slot++;break;case 3:task.exec.generation++;break;case 4:task.exec.cgroup++;break;case 5:task.exec.pending[0]=(struct er_row){1,3,10};break;case 6:invalid_rows=1;break;}
  assert(eo_exec_propose(&bprm,&d)==-1);assert(hard_fault&&(task.flags&2)&&task.exec.suppress&&!fault_generation);assert(task.committed.rows[0].role==777);
 }
 return 0;
}
