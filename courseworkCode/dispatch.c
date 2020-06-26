#include "dispatch.h"

#include <pcap.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include "analysis.h"

#define CAP 100

//This struct is passed to analyse
struct thread_args {
  struct pcap_pkthdr* header;
  const unsigned char* packet;
  int verbose;
};

pthread_mutex_t lock;
int sizeit = 0;             //keeps track of the size of the array
int capacityit = CAP;       //capacityit keeps track of the capacity of the array

pthread_t * threadArr;      //Array to store threads
int countOfThreads = 0;     //keeps track of the number of threads in the array

//Dynamic implementation of threadArr which stores all the threads.
void pushArray(pthread_t thread){
  pthread_mutex_lock(&lock);
  if(sizeit == 0){
    threadArr = malloc(CAP * sizeof(pthread_t));
  }
  if(sizeit == capacityit){
    pthread_t * tmp = (pthread_t *) realloc(threadArr, sizeof(pthread_t) * capacityit * 2);
    capacityit = capacityit * 2;
    if(tmp != NULL) threadArr = tmp;
  }
  threadArr[sizeit] = thread;
  sizeit++;
  pthread_mutex_unlock(&lock);
}

//Each time a thread is created, Run thread
void *thread_code(void *arg){
  struct thread_args * args = (struct thread_args *) arg;
  analyse(args->header, args->packet, args->verbose);
  free(arg);
  return NULL;
}

//This function captures the Ctrl C signal and goes through the array
//of threads and joins them. In the end it frees the memory of the
//thread array
void sigHandler(int sig){
  if(sig == SIGINT){
    for(int i = 0; i < countOfThreads; i++){
      pthread_join(threadArr[i], NULL);
    }
    free(threadArr);
    sig_handler(sig);
  }
}

//This function handles dispatching of work to threads.
//For multi-Threading I have used the One Thread per X Model.
void dispatch(struct pcap_pkthdr *header,const unsigned char *packet,int verbose) {
  signal(SIGINT, sig_handler);
  //Create sturct, assign variables
  struct thread_args *args = malloc(sizeof(struct thread_args));  //allocate memory to thread argument
  struct pcap_pkthdr *updated_header = malloc(sizeof(struct pcap_pkthdr)); //allocate memory to a new header
  memcpy(updated_header, header, sizeof(struct pcap_pkthdr)); //copy memory to the new header from the old header
  unsigned char *updated_packet = malloc(header->len); //allocate memory to new packet
  memcpy(updated_packet, packet, header->len); //copy memory to the new packet from the old one
  args->header = updated_header;
  args->packet = updated_packet;
  args->verbose = verbose;

  pthread_t * thread = malloc(sizeof(pthread_t));
  pthread_create(thread, NULL, &thread_code, (void *) args); //Create threads
  pushArray(*thread); //add threads to the thread array
  countOfThreads++; //Increment the Thread counter

}
