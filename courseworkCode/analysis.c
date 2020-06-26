#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define CAPACITY 500   //Define CAPACITY as 500

//Initialises the locks
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

long pcount = 0;          //keep track of the tcp packets
int violations = 0;       //Count for Blacklist URL violation
int arpCounter = 0;       //Count the ARP responses
double uniqueCount = 1;   //Counts the number of Unique IP addresses
double time_interval;
double min_time;
double maxTime;
u_int32_t currUnique;    //Used to temporarily store IP address in sortIP
long size = 0;           //Size of the array
long capacity = CAPACITY;
struct IPtime * array;    //Initialising array pointer

//Functions declared here so that they can be available for the
//rest of the code
void sortIP(struct IPtime * arr);
int SYNcondition();

//struct stores the source IP address and the time at which the packet arrives
struct IPtime {
  u_int32_t sourceIP;
  double start_time;
};

//returns time in microseconds
double get_time() {
  struct timeval tv;
  gettimeofday(&tv,NULL);
  return tv.tv_sec*(double)1000000+tv.tv_usec;
}

//Dynamic array used for storing structs. This function is called
//everytime a struct is pushed onto the array.
void pushOntoArray(struct IPtime val){
  if(size == capacity){
    struct IPtime * tmp = (struct IPtime *) realloc(array, sizeof(struct IPtime) * capacity * 2);
    capacity = capacity * 2;
    if(tmp != NULL) array = tmp;
  }
  array[size] = val;
  size++;
}

//Captures Ctrl C in order to print the Intrusion Detection Report.
void sig_handler(int sig){
  if(sig == SIGINT){
    sortIP(array);
    printf("\nIntrusion Detection Report:");
    if(SYNcondition()){                        //if the SYN condtions are satisfied the SYN attck possible
      printf("\nSYN flood attack possible");
      printf("\n%lu SYN packets detected from %lf IP addresses in %lf seconds", size, uniqueCount, time_interval);
    }
    printf("\n%d ARP responses (cache poisoning)", arpCounter);
    printf("\n%d URL Blacklist violations", violations);
    free(array);                   //Frees the memory in the array
    pthread_mutex_destroy(&lock);  //Frees the lock so that the threads don't have to look at it anymore
    exit(0);
  }
}

//This is the main function which is used to parse the headers.
//First we parse the ethernet header. Then after if the ethernet type
//is the same as ETHERTYPE_IP then we know that the next header to parse
//is IP header. If the IP protocol equals 6 then we parse the TCP header.
//Now if either the TCP source prt of the Destination port equals 80,
//then check for Blacklist URL violations. If the ethernet type
//equals ETHERTYPE_ARP instead of ETHERTYPE_IP then parse the
//ARP header instead od IP headre and increment the ARP counter.
void analyse(struct pcap_pkthdr *header,
  const unsigned char *packet,
  int verbose) {

    signal(SIGINT, sig_handler);
    struct ether_header * eth_header = (struct ether_header *) (packet);  //Parsing the ethernet header

    unsigned short ethernet_type = ntohs(eth_header->ether_type);    //Using ntohs to convert the ethertype from Network Byte order to Host Byte order and assigning it to a variable

    if(ethernet_type == ETHERTYPE_IP){
      struct iphdr * ip_header = (struct iphdr *) (packet + ETH_HLEN);  //Parsing the ip header
      if(ip_header->protocol == 6){
        struct tcphdr * tcp_header = (struct tcphdr *) (packet + ETH_HLEN + ((ip_header->ihl) * 4));      //Parsing the tcp header
        if(tcp_header->syn == 1 && tcp_header->ack == 0 && tcp_header->psh == 0 && tcp_header->fin == 0 && tcp_header->urg == 0 && tcp_header->rst == 0){  //Checking if the syn flag is set to 1 and the other flags set to 0
          //  long store = ntohl(ip_header->saddr);
          double start = get_time();
          u_int32_t store = ip_header->saddr;
          struct IPtime my_time = {store, start};
          if(pcount == 0){
            array = malloc(CAPACITY * sizeof(struct IPtime));    //Just before the first packet is recieved assign memory to array
            min_time = start;                                    //Record the time when the first packet arrives
          }
          pthread_mutex_lock(&lock);
          pcount++;
          pthread_mutex_unlock(&lock);
          pushOntoArray(my_time);
        }

        if((ntohs(tcp_header->th_sport) == 80) || (ntohs(tcp_header->th_dport) == 80)){
          const char * payload = (char *) (packet + ETH_HLEN + ((ip_header->ihl) * 4) + (tcp_header->th_off * 4));
          char * telegraph = strstr(payload, "www.telegraph.co.uk");
          if(telegraph){
            pthread_mutex_lock(&lock);
            violations++;                             //Increase the counter is www.telegraph.co.uk is a substring of payload
            pthread_mutex_unlock(&lock);
          }
        }
      }
    } else if(ethernet_type == ETHERTYPE_ARP){
      pthread_mutex_lock(&lock);
      arpCounter++;                            //Increase the counter for any arp response
      pthread_mutex_unlock(&lock);

      struct ether_arp * arp_header = (struct ether_arp *) (packet + ETH_HLEN);    //Parsing the ARP header
    }
  }

//The function is a comparator used for sorting elements in quicksort
int cmpfunc(const void * a, const void * b){
  return (*(struct IPtime *) a).sourceIP > (*(struct IPtime *) b).sourceIP ;
}

//This function sorts the IP addresses using quick sort and finds
//the number of unique IP addresses along with recording the time
//for the last non-duplicate packet
void sortIP(struct IPtime * arr){
  qsort(arr, size, sizeof(struct IPtime), cmpfunc);
  for(int i = 0; i < size; i++){
    maxTime = arr[0].start_time;
    currUnique = arr[0].sourceIP;
    if(currUnique != arr[i].sourceIP){
      currUnique = arr[i].sourceIP;
      uniqueCount++;
      if(arr[i].start_time > maxTime){
        maxTime = arr[i].start_time;
      }
    }
  }
}

//This function returns 1 if both the conditions required for
//a SYN flooding attack are satisfied or else it returns 0
int SYNcondition(){
  time_interval = (maxTime - min_time) / 1000000;
  if(currUnique >= (0.9 * size) && (uniqueCount/(time_interval) > 100)){
    return 1;
  }else{
    return 0;
  }
}
