#include <iostream>
#include <string> 
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <cassert>
#include <cstring>

#define PAGE_LENGTH 8
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096

using namespace std;

template <typename T>
std::string toString(T val)
{
    std::stringstream stream;
    stream << val;
    return stream.str();
}

unsigned long getPhysicalAddr(FILE *pagemap, long unsigned int addr){

   unsigned long offset = addr / PAGE_SIZE * PAGE_LENGTH;

   assert(fseek(pagemap, (unsigned long)offset, SEEK_SET) == 0 &&  "Failed to seek pagemap to proper location");

   // The page frame number is in bits 0-54 so read the first 7 bytes and clear the 55th bit
   unsigned long page_frame_number = 0;
   fread(&page_frame_number, 1, PAGE_LENGTH-1, pagemap);

   page_frame_number &= 0x7FFFFFFFFFFFFF;
	//cout << "frame" << page_frame_number; 

   unsigned long  distance_from_page_boundary_of_buffer = addr % PAGE_SIZE;
   unsigned long physical_addr = (page_frame_number << PAGE_SHIFT) + distance_from_page_boundary_of_buffer;

   return physical_addr;
}


int main(int argc, char *argv[]){

   if(argc!=2){
      printf("Argument number is not correct!");
      return -1;
   }

    string pid = argv[1];
    FILE *fp;
    string path = "/proc/"+pid+"/pagemap";
    fp = fopen(path.c_str(),"rb"); //pagetable file
    string line, item;
    string inputfile = "copy."+pid+".0";
    string outputfile = "copy."+pid+".txt";
    ifstream vtrace(inputfile.c_str()); // trace file
    ofstream ptrace("copy_p1.txt");
  //open trace
    while(!vtrace.eof()){	
      getline(vtrace, line);
	std::istringstream linestream(line);
	string num, v1, v2;
	linestream>>num>>v1>>v2;
	
	unsigned long int val1 =0 , val2; 
	string p1, p2;
	val1 = strtoul(v1.c_str(),NULL,0);
	p1 = toString(getPhysicalAddr(fp, val1));
	
      	val2 = strtoul(v2.c_str(),NULL,0) ;
	p2 = toString(getPhysicalAddr(fp, val2));
	//cout << "phy "<<p1<<" "<<p2<<endl;
	ptrace<<num<< " " << p1 << " "<<p2<<endl;


    }
    vtrace.clear();
    vtrace.close();
    ptrace.close();
    fclose(fp);

    return 0;

}



