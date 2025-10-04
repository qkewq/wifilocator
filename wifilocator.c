#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#define RED "\e[31m"
#define YEL "\e[33m"
#define GRN "\e[32m"
#define NRM "\e[0m"

struct s_args{ // Command line arguments
  int list; // List flag set
  int mon; // Set monitor mode flag set
  int ind; // Index of interface
  int help; // Help flag set
  int targ_present; // Target flag set
  int ifc_present; // Interface flag set
  char targ[18]; // Target addr
  char ifc[IFNAMSIZ]; // Interface name
};

struct s_outops{ // Output options
  int max_addrs;
  int no_frame_counter;
};

int usage(){ // Usage statement
  printf("Tool for locating the source of a wifi signal\n");
  printf("Usage: wifilocator [ lmh ] [ i <iface> ] [ t <mac> ]\n");
  printf("Options:\n");
  printf("-l, --list\t\tList detected trasmitting addresses\n");
  printf("-i, --interface <iface>\tSpecifies the interface to use\n");
  printf("-m, --monitor\t\tPut the interface into monitor mode\n");
  printf("-t, --target <mac>\tThe MAC address to listen for\n");
  printf("\t\t\tUsing -l and -t together will only do -l\n");
  printf("-h, --help\t\tPrint this help message\n\n");
  printf("Output Options:\n");
  printf("--maximum-addresses <number>\tMaximum addresses in list scan\n");
  printf("--no-frame-counter\t\tDo not output frame counters\n");
  printf("\n");

  return 0;
}

int monitor(int fd, struct iwreq *iwr){ // Enables monitor mode
  iwr->u.mode = IW_MODE_MONITOR;
  if(ioctl(fd, SIOCSIWMODE, iwr) == -1){
    printf("Monitor Error: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

int parseaddr(uint8_t buffer[4096]){ // Get the tx addr offset in the frame
  uint16_t headlen;
  memcpy(&headlen, &buffer[2], 2);
  uint8_t type = buffer[headlen] & 0x0C;
  uint8_t subtype = buffer[headlen] & 0xF0;
  uint8_t ds = buffer[headlen + 1] & 0x03;
  // Checking for frame type and subtype to get addr offset
  if(type == 0x00){
    return headlen + 10;
  }
  else if(type == 0x04){
    switch(subtype){
      case 0x80:
        return headlen + 10;
      case 0x90:
        return headlen + 10;
      case 0xB0:
        return headlen + 10;
      case 0xF0:
        return headlen + 10;
      default:
        return -1;
    }
  }
  else if(type == 0x08){
    switch(ds){
      case 0x00:
        return headlen + 10;
      case 0x01:
        return headlen + 10;
      case 0x02:
        return headlen + 10;
      case 0x03:
        return headlen + 10;
      default:
        return -1;
    }
  }

  return -1;
}

int parsedbm(uint8_t buffer[4096]){ // Get the dbm offset in the frame
  // Checking for flags and adjusting the offset
  int offset = 0;
  if((buffer[4] & 0x32) == 0x00){
    return -1;
  }
  if((buffer[4] & 0x01) == 0x01){
    offset += 8;
  }
  if((buffer[4] & 0x02) == 0x02){
    offset += 1;
  }
  if((buffer[4] & 0x04) == 0x04){
    offset += 1;
  }
  if((buffer[4] & 0x08) == 0x08){
    offset += 4;
  }
  if((buffer[4] & 0x16) == 0x16){
    offset += 2;
  }
  return 8 + offset;
}

int bar(int8_t dbm){ // Print bar
  struct winsize ws;
  if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1){ // Get window size
    return -1;
  }
  int cols = ws.ws_col;
  int red = (cols - 10) / 3;
  int yel = ((cols - 10) / 3) * 2;
  int grn = cols - 10;
  int filled = (((cols - 10) * (100 - dbm * -1)) / 100);
  printf("%d dBm [", dbm);
  if(filled <= red){
    printf("%s", RED);
    for(int i = 0; i < filled; i++){
      printf("#");
    }
    printf("%s]", NRM);
  }
  else if(filled > red && filled <= yel){
    int i = 0;
    printf("%s", RED);
    for(i; i < red; i++){
      printf("#");
    }
    printf("%s", YEL);
    for(i; i < filled; i++){
      printf("#");
    }
    printf("%s]", NRM);
  }
  else{
    int i = 0;
    printf("%s", RED);
    for(i; i < red; i++){
      printf("#");
    }
    printf("%s", YEL);
    for(i; i < yel; i++){
      printf("#");
    }
    printf("%s", GRN);
    for(i; i < filled; i++){
      printf("#");
    }
    printf("%s]", NRM);
  }
  printf("\n");
  return 0;
}

int list(int fd, struct sockaddr_ll *sock, struct s_outops *outops){ // List recved addrs
  int ind = 0;
  int x = 0;
  uint8_t addrs[outops->max_addrs][6];
  int frames_recv[outops->max_addrs];
  memset(addrs, 0, sizeof(addrs));
  memset(frames_recv, 0, sizeof(frames_recv));
  while(1 == 1){
    uint8_t buffer[4096] = {0};
    uint8_t addr[6] = {0};
    if(recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL) == -1){
      printf("Recv Error: %s\n", strerror(errno));
      return -1;
    }
    ind = parseaddr(buffer);
    if(ind == -1){
      continue;
    }
    for(int i = 0; i < 6; i++){
      addr[i] = buffer[ind + i];
    }
    int duplicate = -1;
    for(int i = 0; i < x; i++){
      if(memcmp(addrs[i], addr, 6) == 0){
        duplicate = i;
        frames_recv[i] += 1;
        break;
      }
    }
    if(duplicate != -1){
      if(outops->no_frame_counter == 1){
        printf("\033[%dF", x - duplicate);
        printf("\033[2K");
        printf("%d) ", duplicate + 1);
        for(int i = 0; i < 5; i++){
          printf("%02X:", addrs[duplicate][i]);
        }
        printf("%02X", addrs[duplicate][5]);
        printf(" %d Frames Received", frames_recv[duplicate]);
        printf("\033[%dE", x - duplicate);
      }
      continue;
    }
    else{
      frames_recv[x] += 1;
    }
    for(int i = 0; i < 6; i++){
      addrs[x][i] = addr[i];
    }
    printf("%d) ", x + 1);
    for(int i = 0; i < 5; i++){
      printf("%02X:", addr[i]);
    }
    printf("%02X", addr[5]);
    if(outops->no_frame_counter == 1){
      printf(" 1 Frame Received\n");
    }
    x++;
    if(x == outops->max_addrs){
      printf("Maximum addresses reached\n");
      return -1;
    }
  }

  return 0;
}

int locate(int fd, struct sockaddr_ll *sock, struct s_args *args){
  for(int i = 0; i < 17; i++){ // Upper casing MAC addr
    if(args->targ[i] >= 97 && args->targ[i] <= 122){
      args->targ[i] = args->targ[i] - 32;
    }
  }
  uint8_t target[6] = {0};
  int x = 0;
  for(int i = 0; i < 6; i++){
    if(args->targ[i + x] >= 65 && args->targ[i + x] <= 90){
      target[i] += (args->targ[i + x] - 55) * 16;
      x++;
    }
    else if(args->targ[i + x] >= 48 && args->targ[i + x] <= 57){
      target[i] += (args->targ[i + x] - 48) * 16;
      x++;
    }
    if(args->targ[i + x] >= 65 && args->targ[i + x] <= 90){
      target[i] += (args->targ[i + x] - 55);
      x++;
    }
    else if(args->targ[i + x] >= 48 && args->targ[i + x] <= 57){
      target[i] += (args->targ[i + x] - 48);
      x++;
    }
  }
  int ind = 0;
  int dbmind = 0;
  int8_t dbm = 0;
  while(1 == 1){
    uint8_t buffer[4096] = {0};
    uint8_t addr[6] = {0};
    if(recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL) == -1){
      printf("Recv Error: %s\n", strerror(errno));
      return -1;
    }
    ind = parseaddr(buffer);
    if(ind == -1){
      continue;
    }
    for(int i = 0; i < 6; i++){
      addr[i] = buffer[ind + i];
    }
    if(memcmp(addr, target, 6) != 0){
      continue;
    }
    dbmind = parsedbm(buffer);
    if(dbmind == -1){
      continue;
    }
    dbm = buffer[dbmind];
    bar(dbm);
  }

  return 0;
}

int main(int argc, char *argv[]){ // Main
  if(argc == 1){ // No arguments
    usage();
    return 0;
  }

  static struct option long_options[] = { // Flags
    {"list", no_argument, 0, 'l'},
    {"interface", required_argument, 0, 'i'},
    {"monitor", no_argument, 0, 'm'},
    {"target", required_argument, 0, 't'},
    {"help", no_argument, 0, 'h'},
    {"maximum-addresses", required_argument, 0, 0},
    {"no-frame-counter", no_argument, 0, 0},
    {0,0,0,0}
  };

  struct s_outops outops;
  memset(&outops, 0, sizeof(outops));
  outops.max_addrs = 32;
  outops.no_frame_counter = 1;
  struct s_args args;
  memset(&args, 0, sizeof(args));
  args.list = 1;
  args.mon = 1;
  args.help = 1;
  args.ifc_present = 1;
  args.targ_present = 1;
  int option;
  while(1 == 1){ // Get flags and options
    int option_index = 0;
    option = getopt_long(argc, argv, "li:mt:h", long_options, &option_index);
    if(option == -1){
      break;
    } 
    switch(option){
      case 0:
        if(strcmp(long_options[option_index].name, "maximum-addresses") == 0){
          outops.max_addrs = atoi(optarg);
        }
        else if(strcmp(long_options[option_index].name, "no-frame-counter") == 0){
          outops.no_frame_counter = 0;
        }
      case 'l':
        args.list = 0;
        continue;
      case 'i':
        strncpy(args.ifc, optarg, strlen(optarg));
        args.ifc_present = 0;
        continue;
      case 'm':
        args.mon = 0;
        continue;
      case 't':
        strncpy(args.targ, optarg, strlen(optarg));
        args.targ_present = 0;
        continue;
      case 'h':
        args.help = 0;
        usage();
        continue;
      default:
        continue;
    }
  }

  if(args.ifc_present == 1){ // Check for interface argument
    if(args.targ_present == 0 || args.list == 0 || args.mon == 0){
      printf("Error: -i, --interface argument required\n");
      return 1;
    }
    else{
      return 0;
    }
  }

  if(args.targ_present == 0){ // Check MAC addr format
    if(strlen(args.targ) != 17){
      printf("Error: MAC address should be 17 characters, ");
      printf("xx:xx:xx:xx:xx:xx\n");
      return 1;
    }
  }

  struct iwreq iwr;
  memset(&iwr, 0, sizeof(iwr));
  strncpy(iwr.ifr_ifrn.ifrn_name, args.ifc, IFNAMSIZ);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, args.ifc, IFNAMSIZ);

  struct sockaddr_ll sock; // Create raw socket
  memset(&sock, 0, sizeof(sock));
  int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(sockfd == -1){
    printf("Socket Creation Error: %s\n", strerror(errno));
    return 1;
  }

  if(args.mon == 0){ // Set monitor mode
    if(monitor(sockfd, &iwr) == -1){
      close(sockfd);
      return 1;
    }
  }

  if(args.list == 1 && args.targ_present == 1){ // Exit if done
    close(sockfd);
    return 0;
  }

  if(ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1){ // Get index of interface
    printf("Index Error: %s\n", strerror(errno));
    close(sockfd);
    return 1;
  }
  args.ind = ifr.ifr_ifindex;

  iwr.u.mode = 0;
  if(ioctl(sockfd, SIOCGIWMODE, &iwr) == -1){ // Check mode
    printf("Mode Check Error: %s\n", strerror(errno));
    close(sockfd);
    return 1;
  }
  if(iwr.u.mode != 6){ // Check for monitor mode
    printf("Error: Interface must be in monitor mode\n");
    printf("Use -m option to put the interface into monitor mode\n");
    close(sockfd);
    return 1;
  }

  sock.sll_family = AF_PACKET;
  sock.sll_protocol = htons(ETH_P_ALL);
  sock.sll_ifindex = args.ind;

  if(bind(sockfd, (struct sockaddr *)&sock, sizeof(sock)) == -1){ // Bind raw socket to index
    printf("Socket Bind Error: %s\n", strerror(errno));
    close(sockfd);
    return 1;
  }

  if(args.list == 0){ // Call list and close
    list(sockfd, &sock, &outops);
    close(sockfd);
    return 0;
  }

  if(args.targ_present == 0){ // Call locate and close
    locate(sockfd, &sock, &args);
    close(sockfd);
    return 0;
  }

  close(sockfd);
  return 0;
}
