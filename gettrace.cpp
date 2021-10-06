/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <fstream>
#include "pin.H"
#include "Cache.h"
#include "Cache.cpp"
#include "Config.h"
#include "Config.cpp"
#include "PPFileParser.cpp"


using namespace std;

bool full_sim = false;
//Statistics
static UINT64 total = 0;
static UINT64 recorded_instr = 0;
static UINT64 recorded_instr_int = 0;
static UINT64 mem_req = 0;
static UINT64 filtered = 0;
static UINT64 num_ifetch = 0;
static UINT64 filt_ifetch = 0;
static int num_slices = 1;
// c_total is static instruction count, ok to leave global.
UINT64 c_total = 0;
//

//global ok
static std::map<std::string,IMG> * images = new std::map<std::string,IMG>();

//should probably become local
static std::list<PSlice*> * slices = new std::list<PSlice*>();
static std::map<Point *,long unsigned int> * execount = new std::map<Point * , long unsigned int>();

//should become local, but only required if using the functionality
static long unsigned int seq_number=0;
static std::map<string,long unsigned int> * dependency = new std::map<string,long unsigned int>();

static std::list<long unsigned int> * depList = new std::list<long unsigned int>();
static std::list<std::list<string> *> * deletelist = new std::list<std::list<string> *>();

static std::list<REG> * compRRegs = new std::list<REG>();

//options
static KNOB<string> KnobTraceFile(KNOB_MODE_WRITEONCE , "pintool","t","trace.out","specify trace output file name.");
static KNOB<string> KnobStatsFile(KNOB_MODE_WRITEONCE , "pintool","s","stats.out","specify stats output file name.");
static KNOB<string> KnobConfigFile(KNOB_MODE_WRITEONCE , "pintool","c","Cache.cfg","specify config file name.");
static KNOB<string> KnobMode(KNOB_MODE_WRITEONCE, "pintool", "mode","cpu","specify the mode of the output trace.");

static KNOB<BOOL> KnobPhysicalAddress(KNOB_MODE_WRITEONCE,"pintool","paddr","0", "generate traces with physical addresses.");

static KNOB<string> KnobPinPoints(KNOB_MODE_WRITEONCE, "pintool", "ppoints", "", "set the pinpoints output file.");

//static KNOB<string> KnobSimpoints(KNOB_MODE_WRITEONCE, "pintool", "points", "", "set the simpoint file.");
static KNOB<string> KnobCoverage(KNOB_MODE_WRITEONCE, "pintool", "cvg", "", "set the coverage.");
static KNOB<BOOL> KnobFastOption(KNOB_MODE_WRITEONCE, "pintool", "fast", "0", "enable the fast simulation mode.");

//cache options

//L1
static KNOB<int> KnobL1Size(KNOB_MODE_WRITEONCE, "pintool", "l1_size","-1","specify the size of the first level cache as power of two.");
static KNOB<int> KnobL1Assoc(KNOB_MODE_WRITEONCE, "pintool", "l1_assoc","-1","specify the associativity of the first level cache as power of two.");
static KNOB<int> KnobL1BlockSize(KNOB_MODE_WRITEONCE, "pintool", "l1_block_size","-1","specify the block size of the first level cache as power of two.");
//L2
static KNOB<int> KnobL2Size(KNOB_MODE_WRITEONCE, "pintool", "l2_size","-1","specify the size of the second level cache as power of two.");
static KNOB<int> KnobL2Assoc(KNOB_MODE_WRITEONCE, "pintool", "l2_assoc","-1","specify the associativity of the second level cache as power of two.");
static KNOB<int> KnobL2BlockSize(KNOB_MODE_WRITEONCE, "pintool", "l2_block_size","-1","specify the block size of the second level cache as power of two.");
//L3
static KNOB<int> KnobL3Size(KNOB_MODE_WRITEONCE, "pintool", "l3_size","-1","specify the size of the third level cache as power of two.");
static KNOB<int> KnobL3Assoc(KNOB_MODE_WRITEONCE, "pintool", "l3_assoc","-1","specify the associativity of the third level cache as power of two.");
static KNOB<int> KnobL3BlockSize(KNOB_MODE_WRITEONCE, "pintool", "l3_block_size","-1","specify the block size of the third level cache as power of two.");

//icache and dcache
static KNOB<BOOL> KnobIFEnable(KNOB_MODE_WRITEONCE, "pintool", "ifetch", "1", "enable the instruction cache.");
static KNOB<BOOL> KnobDCEnable(KNOB_MODE_WRITEONCE, "pintool", "dcache", "1", "enable the instruction cache.");

static KNOB<BOOL> KnobDebugPrints(KNOB_MODE_WRITEONCE, "pintool", "debug", "0", "enable debug prints.");
static KNOB<long unsigned int> KnobISize(KNOB_MODE_WRITEONCE, "pintool", "intervalsize", "100000000", "enable debug prints.");

//Instruction Cache and Instruction Fetch
static KNOB<BOOL> KnobICEnable(KNOB_MODE_WRITEONCE, "pintool", "icache", "1", "enable the instruction cache.");
static KNOB<int> KnobICSize(KNOB_MODE_WRITEONCE, "pintool", "ic_size","-1","specify the size of the instruction cache as power of two.");
static KNOB<int> KnobICAssoc(KNOB_MODE_WRITEONCE, "pintool", "ic_assoc","-1","specify the associativity of the instruction cache as power of two.");
static KNOB<int> KnobICBlockSize(KNOB_MODE_WRITEONCE, "pintool", "ic_block_size","-1","specify the block size of the instruction cache as power of two.");
//options end.

#define PAGEMAP_LENGTH 8 // pagemap contains 8 bytes of info for each virtual page
#define PAGE_SHIFT 12 // change if the page size is different than 4KB.

template <typename T>
std::string ToString(T val)
{
    std::stringstream stream;
    stream << val;
    return stream.str();
}

INT32 numThreads = 0;

// key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY tls_key = INVALID_TLS_KEY;

class thread_data_t
{
  public:
    thread_data_t(THREADID tid);
    ~thread_data_t();
    // UINT64 _nonmemcount;
    ofstream trace;
    string filename;
    Config cfg;
    std::list<Cache *> * caches = new std::list<Cache *>();
    Cache * firstcache;
    Cache * icache; 
    UINT64 t_total = 0;
    UINT64 t_recorded_instr = 0;
    UINT64 t_recorded_instr_int = 0;
    UINT64 t_mem_req = 0;
    UINT64 t_filtered = 0;
    UINT64 t_num_ifetch = 0;
    UINT64 t_filt_ifetch = 0;
    // int t_num_slices = 1;
    
    bool mem_filtered = true;
    bool mem2_filtered = true;
    int bbl_cnt = 0;
    // // read_count is used in analysis function, as to determine read registers, should be local but not a global sum since never used outside
    // but is actually also defined locally, so only use is at recordgeneral, only incremented...
    UINT64 read_count = 0;
    UINT64 write_count = 0;
    UINT64 read_hit = 0;
    UINT64 write_hit = 0;
    UINT64 icache_hit = 0;

    bool control= false;
    bool record = false;
    
    // list with cache requests
    std::list<Request> * reqList = new std::list<Request>();
};

thread_data_t::thread_data_t(THREADID tid)
{
    filename = KnobTraceFile.Value() + "." + decstr(getpid()) + "." + decstr(tid);
    // _nonmemcount = 0;
    // _ofile.open(filename.c_str());
    // if ( ! _ofile )
    // {
    //     cerr << "Error: could not open output file." << endl;
    //     exit(1);
    // }


}

thread_data_t::~thread_data_t()
{
    // _ofile.close();
    delete reqList;
    delete caches;
}

void finish(){
  //delete the data structures
  // if(KnobPhysicalAddress.Value()){
  //   fclose(pagemap);
  // }
  for(std::map<Point *, long unsigned int>::iterator it=execount->begin();it!=execount->end();++it) {
    delete it->first;
  }
  delete execount;
  //This should always print "Slices empty: 1"
  if(KnobDebugPrints.Value())
    printf("Slices empty : %d\n",slices->empty());
  delete slices;
  delete images;
  delete dependency;
  delete depList;
  for(std::list<std::list<string> *>::iterator it = deletelist->begin();it!=deletelist->end();++it){
    delete *it;
  }
  delete deletelist;
  // Start printing the statistics
  printf("Total Number of Instructions\t\t\t\t:%lu\t\t(until the end of selected slices for coverage traces.)\n",total);
  printf("Total Number of Recorded Instructions\t\t\t:%lu\n", recorded_instr);
  printf("Total Number of Recorded Memory Requests\t\t:%lu\n", mem_req);
  printf("Total Number of Filtered Memory Requests\t\t:%lu\n", filtered);
  printf("Total Number of Recorded IFetch Requests\t\t:%lu\n", num_ifetch);
  printf("Total Number of Filtered IFetch Requests\t\t:%lu\n", filt_ifetch);
  printf("Number of Slices\t\t\t\t\t:%d\n", num_slices);
}
/*
UINT64 getPhysicalAddr(long unsigned int addr){
  //long unsigned limit = 1UL << 33;
  //unsigned long get_page_frame_number_of_address(void *addr) {
   // Open the pagemap file for the current process
  if(KnobPhysicalAddress.Value()) {
    pagemap = fopen("/proc/self/pagemap", "rb");
  }
  // Seek to the page that the buffer is on
  // pagemap=call();
  unsigned long offset = addr / getpagesize() * _LENGTH;
  assert(fseek(, (unsigned long)offset, SEEK_SET) == 0 &&  "Failed to seek  to proper location");

  // The page frame number is in bits 0-54 so read the first 7 bytes and clear the 55th bit
  unsigned long page_frame_number = 0;
  fread(&page_frame_number, 1, _LENGTH-1, );

  page_frame_number &= 0x7FFFFFFFFFFFFF;

  unsigned long  distance_from_page_boundary_of_buffer = addr % getpagesize();
  unsigned long physical_addr = (page_frame_number << PAGE_SHIFT) + distance_from_page_boundary_of_buffer;
  //fprintf(addr_file,"%lu %lu %lu %lu\n",(long)addr, (long)physical_addr,page_frame_number,offset);
  //assert(limit>=physical_addr && "oops");

  if(KnobPhysicalAddress.Value()){
    fclose(pagemap);
  }
  return physical_addr;

  
  if(KnobPhysicalAddress.Value()) {
    proces_id = "Self in /proc/self/pagemap" with e.g. get_pid()
    system.exec("pagemap", proces_id, addr, get_page_size())
  }
*/

void initializeCounters(){
  for(std::list<PSlice*>::iterator it=slices->begin();it!=slices->end();++it) {
    execount->insert(std::make_pair((*it)->start,0));
    execount->insert(std::make_pair((*it)->end,0));
  }
}
//returns the counter value for the address if not in the counters return -1.
std::pair<bool, long unsigned int> getCounter(ADDRINT address) {
  for(std::map<Point *,long unsigned int>::iterator it = execount->begin();it!=execount->end();++it) {
    Point * pt = (*it).first;
    if(pt->symbolic){
      std::map<string, IMG>::iterator img = images->find(pt->lib_name);
      if (img == images->end()) continue;
      long unsigned int offset =  address - IMG_LowAddress(img->second);
      if(offset == pt->offset)
        return make_pair(true,(*it).second);
    }
    else {
      if(pt->address == address)
        return make_pair(true,(*it).second);
    }
  }
  return make_pair(false, 0);
}
void incrementCounter(ADDRINT address) {
  for(std::map<Point *,long unsigned int>::iterator it = execount->begin();it!=execount->end();++it) {
    Point * pt = (*it).first;
    if(pt->symbolic){
      std::map<string, IMG>::iterator img = images->find(pt->lib_name);
      if (img == images->end()) continue;
      long unsigned int offset =  address - IMG_LowAddress(img->second);
      if(offset == pt->offset){
        (*it).second++;
      }
    }
    else {
      if(pt->address == address)
        (*it).second++;
    }
  }
}

void removeOld(){
  for(std::map<string,long unsigned int>::iterator it = dependency->begin();it!=dependency->end();++it) {
    if(it->second==seq_number)
      dependency->erase(it);
  }
}

//update sequence number used for data dependency trace
void updateSeqNumber(){
  seq_number++;
  if(seq_number==128) seq_number = 0;
}

//reset sequence number used for data dependency traces
void resetSeqNumber(){
  seq_number=0;
}

//update data dependency window - returns the old entry with given address (-1 if not exists)
int insertDependency(string regname){
  std::map<string,long unsigned int>::iterator it = dependency->find(regname);
  int old = -1;
  if(it!=dependency->end()) {
    old = it->second;
    dependency->erase(it);
  }
  dependency->insert(make_pair(regname, seq_number-1));
  return old;
}

//between traces we should reset the window.
void resetDependencyWindow(){
  dependency->clear();
  resetSeqNumber();
}
//
int getDep(REG regobj){
  string reg = REG_StringShort(regobj);
  std::map<string, long unsigned int>::iterator it = dependency->find(reg);
  if(it!=dependency->end())
    return it->second;
  return -1;
}
//updates the execution count list for the starting and ending points in slices.
void updateCounters(ADDRINT address){
  incrementCounter(address);
}

string getCompDependency(REG read_base, REG read2_base, REG read_index, REG read2_index, THREADID threadid){
  thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
  for(std::list<REG>::iterator it = compRRegs->begin();it!=compRRegs->end();++it) {
    if(!tdata->mem_filtered && (strcmp(REG_StringShort(*it).c_str(), REG_StringShort(read_base).c_str())==0
                                || strcmp(REG_StringShort(*it).c_str(), REG_StringShort(read_index).c_str())==0)) {
      continue;
    }
    if(!tdata->mem2_filtered && (strcmp(REG_StringShort(*it).c_str(), REG_StringShort(read2_base).c_str())==0
                                || strcmp(REG_StringShort(*it).c_str(), REG_StringShort(read2_index).c_str())==0)) {
      continue;
    }
    int dep = getDep((*it));
    if(dep!=-1) {
      depList->push_back(dep);
    }
  }
  depList->sort();
  depList->unique();
  stringstream compDep;
  for(std::list<long unsigned int>::iterator it = depList->begin();it!=depList->end();++it) {
    compDep << " " << *it;
  }
  depList->clear();
  return compDep.str();
}

BOOL checkLimits(ADDRINT address, THREADID threadid) {
  thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
  if(full_sim) return true;
  bool isInLimits=false;
  if(tdata->control) { //we are in the slice limits but this could be the end point.
/*
    Point * pt = slices->front()->end;
    if(pt->symbolic){ //shared lib
      std::map<string, IMG>::iterator img = images->find(pt->lib_name);
      if (img == images->end()) return false;
      long unsigned int offset = address - IMG_LowAddress(img->second);
      if(offset == pt->offset && getCounter(address).first && pt->execount == getCounter(address).second) {
        tdata->control = false;
        trace.close();
        PSlice * slc = slices->front();
        delete slc;
        slices->pop_front();
        if(KnobDebugPrints.Value()) {
          printf("[DEBUG] Remaining Slices:\n");
          for(std::list<PSlice *>::iterator it=slices->begin();it!=slices->end();it++) {
            printf("%s\n",(*it)->dump_content().c_str());
          }
        }
        if(slices->empty()) {
          if(KnobDebugPrints.Value())
            printf("No slices left to execute.\n");
          finish();
          exit(0);
        }
      }
    }
    else { //not shared lib
      if(pt->address == address && getCounter(address).first && pt->execount == getCounter(address).second)
      {
        tdata->control = false;
        trace.close();
        PSlice * slc = slices->front();
        delete slc;
        slices->pop_front();
        if(KnobDebugPrints.Value()) {
          printf("[DEBUG] Remaining Slices:\n");
          for(std::list<PSlice *>::iterator it=slices->begin();it!=slices->end();it++) {
            printf("%s\n",(*it)->dump_content().c_str());
          }
        }
        if(slices->empty()){
          if(KnobDebugPrints.Value())
            printf("No slices left to execute.\n");
          finish();
          exit(0);
        }
      }
    }
*/
  /* 1. Check the recorded instruction count for the current interval
   *   Remove the current interval,
   *   close the file,
   *   reset the recorded instruction count
   */
    if (tdata->t_recorded_instr_int == KnobISize.Value()) {
      tdata->control = false;
      tdata->trace.close();
      PSlice * slc = slices->front();
      delete slc;
      slices->pop_front();
      if(KnobDebugPrints.Value()) {
        printf("[DEBUG] Remaining Slices:\n");
        for(std::list<PSlice *>::iterator it=slices->begin();it!=slices->end();it++) {
          printf("%s\n",(*it)->dump_content().c_str());
        }
      }
      if(slices->empty()){
        if(KnobDebugPrints.Value())
          printf("[DEBUG] No slices left to execute.\n");
        finish();
        exit(0);
      }
      tdata->t_recorded_instr_int=0;
    }
    isInLimits = true;
  }
  if(!tdata->control) //we are out of the slice limit. But the instruction may be the starting point.
  {
    if(slices->empty()) return false; //if we dont have any slices left then we won't record any more traces.
    Point * pt = slices->front()->start;
    if(pt->symbolic) { //shared lib
      std::map<string, IMG>::iterator img = images->find(pt->lib_name);
      if (img == images->end()) return false;
      long unsigned int offset =  address - IMG_LowAddress(img->second);
      if(offset == pt->offset && getCounter(address).first && pt->execount == getCounter(address).second) {
        resetDependencyWindow();
        tdata->control=true;
        if(KnobDebugPrints.Value())
          printf("[DEBUG] Started Slice: %d\n",slices->front()->slice);
        std::ostringstream tracefilename;
        tracefilename << tdata->filename << "." << slices->front()->slice;
        tdata->trace.open(tracefilename.str().c_str()); //open the new one for the new slice
        return true;
      }
    }
    else {
      if(pt->address == address && getCounter(address).first && pt->execount == getCounter(address).second)
      {
        tdata->control = true;
        if(KnobDebugPrints.Value())
          printf("[DEBUG] Started Slice: %d\n",slices->front()->slice);
        std::ostringstream tracefilename;
        tracefilename << tdata->filename << "." << slices->front()->slice;
        tdata->trace.open(tracefilename.str().c_str()); //open the new one for the new slice
        return true;
      }
    }
  }
  if(isInLimits) return true; //if this is the ending point then it should be recorded.
  tdata->bbl_cnt=0;
  return false;
}

VOID RecordInstructionFetch(ADDRINT iaddr, THREADID threadid){
  thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
  if(KnobIFEnable.Value()){
    ADDRINT phy_iaddr=iaddr;
    // cout<<"test1\n"; 
    if (KnobPhysicalAddress.Value()){
    // cout <<"test2\n";   
     /* *pid = NULL , *VA = NULL, *psize=NULL ;
     cout<< "test3\n"; 
      std::sprintf(pid, "%d", getpid());
      std::sprintf(VA, "%lu", iaddr);
      std::sprintf(psize, "%d", getpagesize());
	cout <<"test4\n";*/
	char command[1024];
      sprintf(command, "/imec/other/memseat/shi94/pagemap/pagemap '%s' '%s' '%s'",ToString(getpid()).c_str(),ToString(iaddr).c_str(),ToString(getpagesize()).c_str());
      FILE *fp = popen(command, "r");
      if ( fp == NULL )
      {
        perror("popen");
        exit(0);
      }else{
        char tmp[100], str[100];
        fgets(tmp,100,fp);
        strcat(str, tmp);
        phy_iaddr = strtoul(str,NULL,10);// 
        pclose(fp);
      }
    }
    //phy_iaddr = getPhysicalAddr(iaddr);
    if(tdata->icache!=NULL){
      bool hit = tdata->icache->send(Request(phy_iaddr, Request::Type::READ),tdata->reqList);
      if(hit) tdata->icache_hit++;
    }
    else {
      tdata->reqList->push_back(Request(phy_iaddr, Request::Type::READ));
    }
    if(tdata->record) {
      tdata->t_num_ifetch++;
      if(tdata->reqList->empty()) tdata->t_filt_ifetch++;
      for (std::list<Request>::iterator it = tdata->reqList->begin(); it != tdata->reqList->end(); ++it) {
        assert((it->type == Request::Type::READ) && "Instruction fetch should not return a write.");
        if(strcmp(KnobMode.Value().c_str(),"cpu")==0) {
          if(!KnobICEnable.Value() && !KnobDCEnable.Value())
            tdata->trace << tdata->bbl_cnt << " " << it->addr << " R" << std::endl;
          else
            tdata->trace << tdata->bbl_cnt << " " << it->addr << std::endl;
          tdata->bbl_cnt=0;
        } else if (strcmp(KnobMode.Value().c_str(),"datadep")==0) {
          removeOld();
          tdata->trace << seq_number << " READ " << it->addr << std::endl;
          updateSeqNumber();
        } else
          tdata->trace << "0x"<< std::hex << it->addr << " R" << std::endl;
      }
    }
    tdata->reqList->clear();
  }
}

VOID CountTotalInst(ADDRINT address, THREADID threadid)
{
  thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
  tdata->t_total++;
  tdata->bbl_cnt++;
  updateCounters(address);
  tdata->record = checkLimits(address, threadid);
  if(tdata->record) {
    tdata->t_recorded_instr++;
    tdata->t_recorded_instr_int++;
  }
  tdata->mem_filtered=true;
  tdata->mem2_filtered=true;
}
//recording read/write requests to the memory
VOID RecordGeneral(VOID * ip, VOID * addr, BOOL isWrite, REG base, REG index, BOOL isfirst, THREADID threadid){
  thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
  if(tdata->record) tdata->t_mem_req++;
  if(isWrite) tdata->write_count++;
  else tdata->read_count++;
  UINT64 addr_req = (long)addr;
  if(KnobPhysicalAddress.Value()){
    /*  char *command, *pid, *VA, *psize; 
      std::sprintf(pid, "%d", getpid());
      std::sprintf(VA, "%ld", (long)addr);
      std::sprintf(psize, "%d", getpagesize());
      sprintf(command, "./home/xinyu/trace_generator/src/pagemap '%s' '%s' '%s'", pid , VA, psize);*/
      char command[1024];
      sprintf(command, "/imec/other/memseat/shi94/pagemap/pagemap '%s' '%s' '%s'",ToString(getpid()).c_str(),ToString(addr).c_str(),ToString(getpagesize()).c_str());

      FILE *fp = popen(command, "r");
      UINT64 paddr;
      if ( fp == NULL )
      {
        perror("popen");
        exit(0);
      }else{
        /*char * tmp, *str;
        fgets(tmp,sizeof(tmp),fp);*/
        char tmp[100], str[100];
        fgets(tmp,100,fp);
        strcat(str, tmp);
        paddr = strtoul(str,NULL,10);// 
        pclose(fp);
      }
    addr_req = paddr;
  }
  if(tdata->firstcache!=NULL) {
    bool hit;
    if(!isWrite)
      hit = tdata->firstcache->send(Request(addr_req, Request::Type::READ),tdata->reqList);
    else
      hit = tdata->firstcache->send(Request(addr_req, Request::Type::WRITE),tdata->reqList);
    if(hit && !isWrite)
      tdata->read_hit++;
    else if (hit&&isWrite)
      tdata->write_hit++;
    if(hit && tdata->reqList->empty() && tdata->record) tdata->t_filtered++;
  }
  else {
    if(isWrite) tdata->reqList->push_back(Request(addr_req,Request::Type::WRITE));
    else tdata->reqList->push_back(Request(addr_req,Request::Type::READ));
  }
  UINT64 r_addr=0;
  UINT64 w_addr=0;
  bool w_check = false;
  bool r_check = false;
  //checking requestlist elements added in send()
  //iterating through the list
  for (std::list<Request>::iterator it = tdata->reqList->begin(); it != tdata->reqList->end(); ++it) {
    if(it->type == Request::Type::READ) {
      r_addr = it->addr;
      //assert(r_addr);
      r_check = true;
    }
    else if( it->type == Request::Type::WRITE){
      w_addr = it->addr;
      w_check = true;
    }
  }
  //update filtered memory op check
  if (tdata->record && !tdata->reqList->empty() && strcmp(KnobMode.Value().c_str(),"datadep")==0) {
    if (isfirst)
      tdata->mem_filtered = false;
    else
      tdata->mem2_filtered = false;
  }
  //recording the requests
  if(tdata->record && (r_check || w_check)) {
    if(strcmp(KnobMode.Value().c_str(),"cpu")==0)   { //Collect CPU traces
      if(!KnobDCEnable.Value() && (!KnobICEnable.Value()|| !KnobIFEnable.Value())) { //unfiltered trace
        if(r_check) {
          tdata->trace << tdata->bbl_cnt << " " << r_addr << " R" << std::endl;
          tdata->bbl_cnt=0;
        }
        if(w_check) {
          tdata->trace << tdata->bbl_cnt << " " << w_addr << " W" << std::endl;
          tdata->bbl_cnt=0;
        }
      }
      else {
        if(!w_check && r_check) {
          tdata->trace << tdata->bbl_cnt << " " << r_addr << std::endl;
        }
        else if( w_check && r_check )
          tdata->trace << tdata->bbl_cnt << " " << r_addr << " " << w_addr << std::endl; //includes writeback address
        assert(!(w_check && !r_check) && "A write should be always with a read request.");
        tdata->bbl_cnt=0;
      }
    } else if(strcmp(KnobMode.Value().c_str(),"datadep")==0) { //Collect data dependency included CPU traces
        //fprintf(trace,"dependent to reg: base: %s, index: %s\n",REG_StringShort(base).c_str(), REG_StringShort(index).c_str());
        stringstream deplist;
        int base_seq = getDep(base);
        int index_seq = getDep(index);
        if(base_seq != -1 || index_seq != -1 ) {
          deplist << " :";
          if(base_seq != index_seq) {
            if(base_seq!=-1)  deplist << " " << base_seq;
            if(index_seq!=-1) deplist << " " << index_seq;
          }
          else {
            if( base_seq!=-1)
              deplist << " " << base_seq;
          }
        }
      //  printf("deplist:%s\n",deplist.str().c_str() );
        if(r_check) {
          removeOld();
          tdata->trace << seq_number << " READ " << r_addr;
          if(deplist.str().length()>1)
            tdata->trace << deplist.str().c_str();
          tdata->trace << std::endl;
          updateSeqNumber();
      }
      if(w_check){
        removeOld();
        tdata->trace << seq_number << " WRITE " << w_addr << " : " << (seq_number -1) << std::endl;
        updateSeqNumber();
      }

    } else { //Collect memory traces
      if(r_check)
        tdata->trace << "0x" << std::hex << r_addr << " R" << std::endl;
      if(w_check)
        tdata->trace << "0x" << std::hex << w_addr << " W" << std::endl;
    }
  }
  tdata->reqList->clear();
}

//recording COMP
VOID RecordComp(VOID * ip, REG read_base, REG read2_base, REG read_index, REG read2_index, THREADID threadid){
  thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
  if(tdata->record) {
    removeOld();
    stringstream deplist;
    if(!(tdata->mem_filtered && tdata->mem2_filtered) || compRRegs->size()>0)
    deplist << ":";
    if(!tdata->mem_filtered && tdata->mem2_filtered)
      deplist << " " << seq_number-1;
    else if(!tdata->mem2_filtered && tdata->mem_filtered)
      deplist << " " << seq_number-1;
    else if(!tdata->mem_filtered && !tdata->mem2_filtered)
      deplist << " " << seq_number-1 << " " << seq_number-2;
    deplist << getCompDependency( read_base, read2_base, read_index, read2_index, threadid);
    compRRegs->clear();
    if(deplist.str().length()>1)
      tdata->trace << seq_number << " COMP " << deplist.str().c_str() << std::endl;
    else
      tdata->trace << seq_number << " COMP" << std::endl;
    updateSeqNumber();
  }

}

VOID UpdateRegisterMap(VOID * ip, REG reg) {
  insertDependency(REG_StringShort(reg));
}
VOID UpdateCompRegs(VOID * ip, REG reg) {
  if(REG_valid(reg)) {
    compRRegs->push_back(reg);
  }
}
// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
    c_total++;
    ADDRINT adr = INS_Address(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CountTotalInst,IARG_UINT64, adr, IARG_THREAD_ID,
      IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInstructionFetch, IARG_UINT64, adr, IARG_THREAD_ID, IARG_END);
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    // determine which registers are used for address generation for memory accesses
    REG read_base = REG_INVALID();
    REG read_index = REG_INVALID();
    REG read2_base = REG_INVALID();
    REG read2_index = REG_INVALID();
    int read_count=0;

    if(strcmp(KnobMode.Value().c_str(),"datadep")==0) {
      UINT32 opCount = INS_OperandCount(ins);
      for(UINT32 op = 0; op < opCount; op++) {
        REG base = INS_OperandMemoryBaseReg(ins, op);
        REG index = INS_OperandMemoryIndexReg(ins, op);
        if(REG_valid(base) || REG_valid(index)) {
          assert(read_count<2 && "Memory Operands should be less than 3. right??");
          if(read_count==0) {
            read_base = base;
            read_index = index;
            read_count=1;
          }
          else if( read_count==1) {
            read2_base = base;
            read2_index = index;
            read_count++;
          }
        }
      }
      read_count=0;
    }
    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        //determine which register is used for address generation
        REG base;
        REG index;
        if(read_count==0) {
          base = read_base;
          index= read_index;
          read_count++;
        }
        else {
          index= read2_index;
          base = read2_base;
        }
        bool isfirst = (memOp==0);
        //issue recording calls for memory operations
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordGeneral,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_BOOL, false,
                IARG_UINT32, base,
                IARG_UINT32, index,
                IARG_BOOL, isfirst,
                IARG_THREAD_ID,
                IARG_END);
        }
        // Note that in some architectures a single memory operand can be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordGeneral,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_BOOL, true,
                IARG_UINT32, base,
                IARG_UINT32, index,
                IARG_BOOL, isfirst,
                IARG_THREAD_ID,
                IARG_END);
        }
    }
    //If instruction is not a read or write and collecting data dependency traces
    //determine which registers are a dependency (except the ones used in memory accesses)
    if(strcmp(KnobMode.Value().c_str(),"datadep")==0) {
      for(unsigned int i=0;i<INS_MaxNumRRegs(ins);i++) {
        REG reg = INS_RegR(ins,i);
        INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)UpdateCompRegs,
                      IARG_INST_PTR,
                      IARG_UINT32, reg,
                      IARG_END);
      }
      for(unsigned int i=0;i<INS_MaxNumWRegs(ins);i++) {
        REG reg = INS_RegW(ins,i);
        INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)UpdateCompRegs,
                      IARG_INST_PTR,
                      IARG_UINT32, reg,
                      IARG_END);
      }
      INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)RecordComp,
                    IARG_INST_PTR,
                    IARG_UINT32, read_base,
                    IARG_UINT32, read2_base,
                    IARG_UINT32, read_index,
                    IARG_UINT32, read2_index,
                    IARG_THREAD_ID,
                    IARG_END);
      for(unsigned int i =0;i<INS_MaxNumWRegs(ins);i++) {
        REG reg = INS_RegW(ins,i);
        INS_InsertPredicatedCall(
          ins, IPOINT_BEFORE, (AFUNPTR)UpdateRegisterMap,
          IARG_INST_PTR,
          IARG_UINT32, reg,
          IARG_END);
        }
      }
}


VOID Fini(INT32 code, VOID *v)
{
    finish();
}


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR( "This Pintool prints a trace of memory accesses\n"
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

//returns the first slice id.
int setSliceLimits(){
  if(!KnobFastOption.Value() && strcmp(KnobCoverage.Value().c_str(),"")==0) return 0;
  Parser * parser = new Parser();
  parser->parse(KnobPinPoints.Value());
  PSlice * first = NULL;
  if(KnobFastOption.Value()) {
    first = parser->getFastPoint();
    if(first==NULL) {
      printf("Cannot find any slices, try changing the interval size.\n");
      exit(0);
    }
    slices->push_back(first);
  }
  else if (strcmp(KnobCoverage.Value().c_str(),"")!=0) {
    slices = parser->slices;
    num_slices = slices->size();
    if(num_slices==0) {
      printf("Cannot find any slices, try changing the interval size.\n");
      exit(0);
    }
    if(KnobDebugPrints.Value())
      printf("[DEBUG] Content:\n%s\n",parser->dump_content().c_str());
    first = slices->front();
  }
  initializeCounters();
  delete parser;
  return first ? first->slice : 0;
}

VOID Image(IMG img, VOID * v)
{
  images->insert(make_pair(IMG_Name(img),img));
}



VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    numThreads++;
    thread_data_t* tdata = new thread_data_t(threadid);
    if (PIN_SetThreadData(tls_key, tdata, threadid) == FALSE)
    {
        cerr << "PIN_SetThreadData failed" << endl;
        PIN_ExitProcess(1);
    }
    tdata->cfg= Config(KnobConfigFile.Value().c_str());
    tdata->control=false; //this is used to check if the instrumented instruction is in the slice for recording the traces.
    printf("isize: %ld\n",KnobISize.Value());
    if(!KnobFastOption.Value() && strcmp(KnobCoverage.Value().c_str(),"")==0) {
      full_sim=true;
    }
    int slice_id=0;
    if(!full_sim && strcmp(KnobPinPoints.Value().c_str(),"")!=0) {
      slice_id = setSliceLimits();
    }

    std::ostringstream tracefilename;
    if(!slices->empty()){
      tracefilename<<tdata->filename << "." << slice_id ;
    }
    else{ //if we are running the full program
      tracefilename <<tdata->filename;
      tdata->trace.open(tracefilename.str().c_str());
    }
    std::list<CacheParams *> * c_list = tdata->cfg.get_caches();
    if(c_list->empty()) {
      tdata->firstcache=NULL;
      tdata->icache=NULL;
    }
    else {

    Cache * cur = NULL;
    for(std::list<CacheParams *>::iterator it = c_list->begin();it!=c_list->end();it++) {
      bool isItIC = false;
      int csize = (*it)->get_size();
      int cassoc = (*it)->get_assoc();
      int cblock = (*it)->get_block_size();
      Cache::Level lvl;
      //command line arguments override the config file values.
      switch ((*it)->get_level()) {
        case 1:
        lvl = Cache::Level::L1;
        if(KnobL1Size.Value()>0) csize = 2<<KnobL1Size.Value();
        if(KnobL1Assoc.Value()>0) cassoc = 2<<KnobL1Assoc.Value();
        if(KnobL1BlockSize.Value()>0) cblock = (2<<KnobL1BlockSize.Value());
        break;
        case 2:
        lvl = Cache::Level::L2;
        if(KnobL2Size.Value()>0) csize = (2<<KnobL2Size.Value());
        if(KnobL2Assoc.Value()>0) cassoc = (2<<KnobL2Assoc.Value());
        if(KnobL2BlockSize.Value()>0) cblock = (2<<KnobL2BlockSize.Value());
        break;
        case 3:
        lvl = Cache::Level::L3;
        if(KnobL3Size.Value()>0) csize = (2<<KnobL3Size.Value());
        if(KnobL3Assoc.Value()>0) cassoc = (2<<KnobL3Assoc.Value());
        if(KnobL3BlockSize.Value()>0) cblock =(2<<KnobL3BlockSize.Value());
        break;
        case -1:
        lvl = Cache::Level::ICache;
        isItIC = true;
        if(KnobICSize.Value()>0) csize = (2<<KnobICSize.Value());
        if(KnobICAssoc.Value()>0) cassoc = (2<<KnobICAssoc.Value());
        if(KnobICBlockSize.Value()>0) cblock = (2<<KnobICBlockSize.Value());
        break;
        default:
        printf("A caches level can't be out of the range [1,3]. (-1 for ICache)\n");
        exit(0);
      }
      if(isItIC) {
        tdata->icache = new Cache(csize,cassoc,cblock,lvl);
        //tdata->icache->set_next_cache(NULL);
        //tdata->icache->concatlower(NULL);
        tdata->icache->set_last_level();
      }
      else {
        Cache * c= new Cache(csize,cassoc,cblock,lvl);
        if(cur!=NULL)  {
	         //cur->set_next_cache(c);
           cur->concatlower(c);
	      }
	      else  {
          c->set_first_level();
          tdata->firstcache = c;
        }
        tdata->caches->push_back(c);
        cur = c;
      }
    }
    cur->set_last_level();
    }
    if(!KnobICEnable.Value()) {
      tdata->icache = NULL;
    }
    if(!KnobDCEnable.Value()) {
      tdata->firstcache = NULL;
    }
    if(KnobDebugPrints.Value()) {
      int i = 0;
      for (auto debug : *tdata->caches) {
        printf("[DEBUG Thread %d] Level: %d, next_cache: %lu, is_last_level: %d is_first_level: %d, time in loop: %d\n", threadid, debug->level, debug->higher_cache.size(),
        debug->is_llc(),debug->is_first(), i++);
      }
    }
}

// This function is called when the thread exits
VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    thread_data_t* tdata = static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadIndex));
    // *OutFile << "Count[" << decstr(threadIndex) << "] = " << tdata->_count << endl;
    
    //adding thread local counts to global counts
    total += tdata->t_total;
    recorded_instr += tdata->t_recorded_instr;
    recorded_instr_int += tdata->t_recorded_instr_int;
    mem_req += tdata->t_mem_req;
    filtered += tdata->t_filtered;
    num_ifetch += tdata->t_num_ifetch;
    filt_ifetch += tdata->t_filt_ifetch;
    // num_slices += tdata->t_num_slices;   
    //Close the files and 
    tdata->trace.close();
    for(std::list<Cache *>::iterator it=tdata->caches->begin();it!=tdata->caches->end();++it) {
      delete *it;
    }
    // delete tdata->cfg;
    delete tdata;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    // Initialize pin
    PIN_InitSymbols();
    if(PIN_Init(argc, argv)) 
      return Usage();



    // Obtain  a key for TLS storage.
    tls_key = PIN_CreateThreadDataKey(NULL);
    if (tls_key == INVALID_TLS_KEY)
    {
        cerr << "number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit" << endl;
        PIN_ExitProcess(1);
    }
   /*     if(KnobPhysicalAddress.Value()) {
            pagemap = fopen("/proc/self/", "rb");
    }*/


    //Image instrumentation  
    IMG_AddInstrumentFunction(Image, 0);
    
    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, NULL);

    // Register Fini to be called when thread exits.
    PIN_AddThreadFiniFunction(ThreadFini, NULL);

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
