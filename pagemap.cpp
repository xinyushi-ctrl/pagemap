#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <fstream>
#include <cassert>
#include <cstring>

#define PAGE_LENGTH 8
#define PAGE_SHIFT 12
using namespace std;

int main(int argc, char *argv[]){ // pid, single VA, pagesize

    string pid = argv[1];

    // Open the pagemap file for the current process
    int addr = atoi(argv[2]);
    int pagesize = atoi(argv[3]);
    FILE *pagemap;
    const string tmp1 = "/proc/";
    const string tmp2 = "/pagemap";
    char *path = NULL;
    string str;
    str += tmp1;
    str += pid;
    str += tmp2;
    strcpy (path, str.c_str());
    pagemap = fopen(path, "rb");
    
    // Seek to the page that the buffer is on

    unsigned long offset = addr / pagesize * PAGE_LENGTH;
    assert(fseek(pagemap, (unsigned long)offset, SEEK_SET) == 0 &&  "Failed to seek  to proper location");

    // The page frame number is in bits 0-54 so read the first 7 bytes and clear the 55th bit
    unsigned long page_frame_number = 0;
    fread(&page_frame_number, 1, PAGE_LENGTH-1, pagemap);

    page_frame_number &= 0x7FFFFFFFFFFFFF;

    unsigned long  distance_from_page_boundary_of_buffer = addr % pagesize;
    unsigned long physical_addr = (page_frame_number << PAGE_SHIFT) + distance_from_page_boundary_of_buffer;
    //fprintf(addr_file,"%lu %lu %lu %lu\n",(long)addr, (long)physical_addr,page_frame_number,offset);
    //assert(limit>=physical_addr && "oops");
    cout << physical_addr<<"\n";
    fclose(pagemap);

    //return physical_addr; // -> how to return value to calling program?
    
    return 0; 
}