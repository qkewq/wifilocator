#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <signal.h>

#define RED "\e[31m"
#define YEL "\e[33m"
#define GRN "\e[32m"
#define BLK "\e[30m"
#define WTBCKGRND_HI "\e[100m"
#define NRM "\e[0m"

// Note: I was very stupid when I started this, 0 is a set bit and 1 is an unset bit

time_t last_sigint = 0; // time() called in first line of main()

struct termios ogattr, stattr; // Set in second line of main()

static void sigint_handler(int signum){ // Handle ctrl C "properly"
  time_t sigint_time = time(NULL);
  if(sigint_time - last_sigint <= 3){ // Less than 3 seconds
    write(STDOUT_FILENO, "\033[0m\033[?1049l", 12);
    tcsetattr(STDIN_FILENO, TCSANOW, &ogattr);
    _exit(0);
  }
  else{
    last_sigint = sigint_time;
    write(STDOUT_FILENO, "Press ctrl + C again to quit...\n", 32);
  }
}

struct s_args{ // Command line arguments
  int list; // List flag set
  int mon; // Set monitor mode flag set
  int ind; // Index of interface
  int help; // Help flag set
  int targ_present; // Target flag set
  int ifc_present; // Interface flag set
  int channel; // Specify channel
  char targ[18]; // Target addr
  char ifc[IFNAMSIZ]; // Interface name
};

struct s_outops{ // Output options
  int max_addrs; // Maximum addresses to print
  int no_frame_counter; // Do not display frame counter
  int no_channel; // Do not display channel
  int no_bar_in_place; // Do not keep dBm bar on one line
  int no_aging; // Do not age out addrs
  int bssid_only; // Only scan for BSSIDs
};

struct s_data{ // Struct for addr data
  uint8_t addr[6]; // The tx address
  int frames_recv; // The number of frames received
  uint8_t channel; // The channel number
  time_t last_frame; // Time of last frame
  uint8_t empty; // Is struct considered empty
};

const uint8_t channel_nums[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,32,36,40,44,48,52,56,60,64,68,
  72,76,80,84,88,92,96,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165,169,173,177};

const uint16_t channel_freq[] = {2412,2417,2422,2427,2432,2437,2442,2447,2452,2457,2462,2467,2472,
  2484,5160,5180,5200,5220,5240,5260,5280,5300,5320,5340,5360,5380,5400,5420,5440,5460,5480,5500,
  5520,5540,5560,5580,5600,5620,5640,5660,5680,5700,5720,5745,5765,5785,5805,5825,5845,5865,5885};

int usage(){ // Usage statement
  printf("\nA tool for locating the source of a wireless signal\n"
  "or for listing detected transmitting addresses\n\n"
  "Usage: wifilocator [ OPTIONS... ]\n\n"
  "Options:\n"
  "-l, --list\t\t\tList detected transmitting addresses\n"
  "-i, --interface <interface>\tSpecifies the interface to use\n"
  "-m, --monitor\t\t\tPut the interface into monitor mode\n"
  "-t, --target <mac address>\tThe MAC address to listen for\n"
  "-c, --channel <channel>\t\tSpecifies the channel to use\n"
  "-h, --help\t\t\tDisplay this help message\n\n"
  "Output options:\n"
  "--bssid-only\t\t\tOnly scan for access points\n"
  "--maximum-addresses <num>\tThe maximum number of addresses" 
  "to be\n\t\t\t\tlisted by the --list option, defaul 32\n"
  "--no-frame-counter\t\tDo not output frame counters\n"
  "--no-bar-in-place\t\tOutput dBm bar on consecutive lines\n"
  "--no-aging\t\t\tDo not age out addresses\n"
  "--no-channel\t\t\tDo not display channel\n\n"
  "Notes:\n"
  "The interface must be in monitor mode to operate\n"
  "If --list and --target are used together, "
  "--target will be ignored\nThe MAC address should be six groups "
  "of seperated hex digits, any case\n\n"
  "Examples:\n"
  "wifilocator -i wlan0 -m -i\n"
  "wifilocator -i wlan0 -t xx:xx:xx:xx:xx:xx\n"
  "wifilocator --interface --list --no-frame-counter\n\n");

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

int parseaddr(uint8_t buffer[4096], int bssid_only){ // Get the tx addr offset in the frame
  // Fuck 802.11 addressing
  uint16_t headlen;
  memcpy(&headlen, &buffer[2], 2); // Radiotap header length
  uint8_t type = buffer[headlen] & 0x0C; // Frame type
  uint8_t subtype = buffer[headlen] & 0xF0; // Frame subtype
  uint8_t ds = buffer[headlen + 1] & 0x03; // DS bits
  int bssid = 1; // Addr is a bssid
  int index = 0; // Index of addr
  // Checking for frame type and subtype to get addr offset
  if(type == 0x00){ // Management Frame
    if(memcmp(&buffer[headlen + 10], &buffer[headlen + 16], 6) == 0){
      bssid = 0;
    }
    index = headlen + 10;
  }
  else if(type == 0x04){ // Control Frame
    switch(subtype){
      case 0x40: // Beamforming
        bssid = 0;
        index = headlen + 10;
        break;
      case 0x50: // NDP Announcement
        index = headlen + 10;
        break;
      case 0x80: // Block Ack Request
        index = headlen + 10;
        break;
      case 0x90: // Block Ack
        bssid = 0;
        index = headlen + 10;
        break;
      case 0xA0: // PS-Poll
        index = headlen + 10;
        break;
      case 0xB0: // RTS
        index = headlen + 10;
        break;
      case 0xE0: // CF-End
        bssid = 0;
        index = headlen + 10;
        break;
      case 0xF0: // CF-End+CF-Ack
        bssid = 0;
        index = headlen + 10;
        break;
      default:
        return -1;
    }
  }
  else if(type == 0x08){ // Data Frame
    switch(ds){ // To DS, From DS
      case 0x00:
        if(memcmp(&buffer[headlen + 10], &buffer[headlen + 16], 6) == 0){
          bssid = 0;
        }
        index = headlen + 10;
        break;
      case 0x01:
        bssid = 0;
        index = headlen + 10;
        break;
      case 0x02:
        index = headlen + 10;
        break;
      case 0x03:
        bssid = 0;
        index = headlen + 10;
        break;
      default:
        return -1;
    }
  }
  else{
    return -1;
  }
  if(bssid_only == 1){
    return index;
  }
  else if(bssid_only == 0 && bssid == 0){
    return index;
  }

  return -1;
}

int parsedbm(uint8_t buffer[4096]){ // Get the dbm offset in the frame
  // Checking for flags and adjusting the offset
  int offset = 0;
  if((buffer[4] & 0x20) == 0x00){ // Signal Present
    return -1;
  }
  if((buffer[4] & 0x01) == 0x01){ // TSFT
    offset += 8;
  }
  if((buffer[4] & 0x02) == 0x02){ // Flags
    offset += 1;
  }
  if((buffer[4] & 0x04) == 0x04){ // Rate
    offset += 1;
  }
  if((buffer[4] & 0x08) == 0x08){ // Channel
    offset += 4;
  }
  if((buffer[4] & 0x16) == 0x10){ // FHSS
    offset += 2;
  }
  return 8 + offset;
}

int parsechannel(uint8_t buffer[4096]){ // Get channel offset in frame
  int offset = 0;
  if((buffer[4] & 0x08) == 0x00){ // Channel Present
    return -1;
  }
  if((buffer[4] & 0x01) == 0x01){ // TSFT
    offset += 8;
  }
  if((buffer[4] & 0x02) == 0x02){ // Flags
    offset += 1;
  }
  if((buffer[4] & 0x04) == 0x04){ // Rate
    offset += 1;
  }
  return 8 + offset;
}

int bar(int8_t dbm, int no_bar_in_place){ // Print bar
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
  if(no_bar_in_place == 0){
    printf("\n\n");
  }
  return 0;
}

int list(int fd, struct sockaddr_ll *sock, struct s_args *args, struct s_outops *outops){ // List recved addrs
  if(outops->max_addrs <= 0){ // Zero max addrs edge case
    printf("Maximum addresses reached\n");
    return -1;
  }
  struct s_data data[outops->max_addrs] = {};
  for(int i = 0; i < outops->max_addrs; i++){ // Set initial struct to empty
    data[i].empty = 1;
  }
  int selected = 1;
  int numaddrs = 0;
  while(1 == 1){ // Main loop
    uint8_t buffer[4096] = {0};
    uint8_t addr[6] = {0};
    uint16_t freq = 0;
    int recvn = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL); // Recv
    if(recvn == -1){
      if(errno == EAGAIN || errno == EWOULDBLOCK){
        continue;
      }
      else{
        printf("Recv Error: %s\n", strerror(errno));
        return -1;
      }
    }
    int ind = parseaddr(buffer, outops->bssid_only); // Get the address in the frame
    if(ind == -1){
      continue;
    }
    for(int i = 0; i < 6; i++){
      addr[i] = buffer[ind + i];
    }
    int channel_index = parsechannel(buffer); // Get the freq in the frame
    if(channel_index == -1){
      continue;
    }
    freq = (buffer[channel_index + 1] * 0x100) + buffer[channel_index];
    uint8_t channel = 0;
    for(int i = 0; i < 51; i++){ // Convert freq to channel number
      if(channel_freq[i] == freq){
        channel = channel_nums[i];
        break;
      }
    }
    int duplicate = -1;
    for(int i = 0; i < outops->max_addrs; i++){ // Check if addr is already in data
      if(memcmp(data[i].addr, addr, 6) == 0 && data[i].empty == 0){
        duplicate = i;
        break;
      }
    }
    if(duplicate != -1){ // Update frame counter and time
      data[duplicate].frames_recv += 1;
      data[duplicate].last_frame = time(NULL);
      data[duplicate].channel = channel;
      data[duplicate].empty = 0;
    }
    else{ // Add new addr to first empty
      for(int i = 0; i < outops->max_addrs; i++){
        if(data[i].empty == 1){
          memcpy(data[i].addr, addr, 6);
          data[i].frames_recv = 1;
          data[i].last_frame = time(NULL);
          data[i].channel = channel;
          data[i].empty = 0;
          break;
        }
      }
      numaddrs += 1;
    }
    if(outops->no_aging == 1){
      time_t current_time = time(NULL);
      for(int i = 0; i < outops->max_addrs; i++){ // Aging out inactive addresses
        if(data[i].empty == 0){
          if(current_time - data[i].last_frame <= 5){
            continue;
          }
          else{ // The chopping block
            if(data[i].frames_recv <= 5){
              data[i].empty = 1;
              numaddrs -= 1;
            }
            else if(data[i].frames_recv <= 100){
              if(current_time - data[i].last_frame >= 30){
                data[i].empty = 1;
                numaddrs -= 1;
              }
            }
            else if(data[i].frames_recv <= 1000){
              if(current_time - data[i].last_frame >= 60){
                data[i].empty = 1;
                numaddrs -= 1;
              }
            }
            else{
              if(current_time - data[i].last_frame >= 180){
                data[i].empty = 1;
                numaddrs -= 1;
              }
            }
          }
        }
      }
      printf("\033[2J");
    }
    char input[3] = {0};
    int readn = read(STDIN_FILENO, &input, 3);
    if(readn > 0){
      switch(input[2]){
        case 'A':
          selected -= 1;
          break;
        case 'B':
          selected += 1;
          break;
      }
    }
    if(selected > numaddrs){
      selected = 1;
    }
    else if(selected < 1){
      selected = numaddrs;
    }
    printf("\033[H"); // Move cursor home
    int inc = 1;
    for(int i = 0; i < outops->max_addrs; i++){ // Print everything
      if(data[i].empty == 0){
        if(selected == inc){
          printf("%s%s", BLK, WTBCKGRND_HI);
        }
        printf("%d) %02X:%02X:%02X:%02X:%02X:%02X",
        inc, data[i].addr[0], data[i].addr[1],
        data[i].addr[2], data[i].addr[3], data[i].addr[4],
        data[i].addr[5]);
        if(outops->no_frame_counter == 1){
          printf(" %d Frames Received", data[i].frames_recv);
        }
        if(outops->no_channel == 1){
          printf(" Channel %d", data[i].channel);
        }
        if(selected == inc){
          printf("%s", NRM);
        }
        printf("\n");
        inc += 1;
      }
    }
  }
  return 0;
}

int locate(int fd, struct sockaddr_ll *sock, struct s_args *args, struct s_outops *outops){ // Display dBm of tx
  printf("\n0 Frames Received");
  for(int i = 0; i < 17; i++){ // Upper casing MAC addr
    if(args->targ[i] >= 97 && args->targ[i] <= 122){
      args->targ[i] = args->targ[i] - 32;
    }
  }
  uint8_t target[6] = {0};
  int x = 0;
  for(int i = 0; i < 6; i++){ // Converting MAC to integer
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
  int frames_received = 0;
  while(1 == 1){
    uint8_t buffer[4096] = {0};
    uint8_t addr[6] = {0};
    int n = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL); // Recv
    if(n == -1){
      if(errno == EAGAIN || errno == EWOULDBLOCK){
        continue;
      }
      else{
        printf("Recv Error: %s\n", strerror(errno));
        return -1;
      }
    }
    ind = parseaddr(buffer, 1);
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
    frames_received += 1;
    dbm = buffer[dbmind];
    printf("\033[1F\033[2K");
    bar(dbm, outops->no_bar_in_place);
    printf("\033[1E\033[2K");
    if(outops->no_frame_counter == 1){
      printf("%d Frames Received", frames_received);
    }
  }

  return 0;
}

int main(int argc, char *argv[]){ // Main
  last_sigint = time(NULL);
  tcgetattr(STDIN_FILENO, &ogattr); // Non-canonical mode
  stattr = ogattr;
  stattr.c_lflag &= ~(ICANON | ECHO);
  fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK); // stdin nonblock
  if(argc == 1){ // No arguments
    usage();
    return 0;
  }
  struct sigaction sa; // Signal handler struct
  sa.sa_handler = sigint_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGINT, &sa, NULL);

  static struct option long_options[] = { // Flags
    {"list", no_argument, 0, 'l'},
    {"interface", required_argument, 0, 'i'},
    {"monitor", no_argument, 0, 'm'},
    {"target", required_argument, 0, 't'},
    {"channel", required_argument, 0, 'c'},
    {"help", no_argument, 0, 'h'},
    {"maximum-addresses", required_argument, 0, 0},
    {"no-frame-counter", no_argument, 0, 0},
    {"no-channel", no_argument,0, 0},
    {"no-bar-in-place", no_argument, 0, 0},
    {"no-aging", no_argument, 0, 0},
    {"bssid-only", no_argument, 0, 0},
    {0,0,0,0}
  };

  struct s_outops outops; // Initialize outops with default values
  memset(&outops, 0, sizeof(outops));
  outops.max_addrs = 32;
  outops.no_frame_counter = 1;
  outops.no_channel = 1;
  outops.no_bar_in_place = 1;
  outops.no_aging = 1;
  outops.bssid_only = 1;
  struct s_args args; // Initialize args with default values
  memset(&args, 0, sizeof(args));
  args.list = 1;
  args.mon = 1;
  args.help = 1;
  args.ifc_present = 1;
  args.targ_present = 1;
  args.channel = -1;
  int option;
  while(1 == 1){ // Get flags and options
    int option_index = 0;
    option = getopt_long(argc, argv, "li:mt:c:h", long_options, &option_index);
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
        else if(strcmp(long_options[option_index].name, "no-channel") == 0){
          outops.no_channel = 0;
        }
        else if(strcmp(long_options[option_index].name, "no-bar-in-place") == 0){
          outops.no_bar_in_place = 0;
        }
        else if(strcmp(long_options[option_index].name, "no-aging") == 0){
          outops.no_aging = 0;
        }
        else if(strcmp(long_options[option_index].name, "bssid-only") == 0){
          outops.bssid_only = 0;
        }
        continue;
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
      case 'c':
        args.channel = atoi(optarg);
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

  struct iwreq iwr; // Struct for IOCTLs
  memset(&iwr, 0, sizeof(iwr));
  strncpy(iwr.ifr_ifrn.ifrn_name, args.ifc, IFNAMSIZ);

  struct ifreq ifr; // Struct for IOCTLs
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

  if(args.channel != -1){ // Change channel if set
    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_ifrn.ifrn_name, args.ifc, IFNAMSIZ);
    int freq = 0;
    for(int i = 0; i < 51; i++){
      if(channel_nums[i] == args.channel){
        freq = channel_freq[i];
        break;
      }
    }
    iwr.u.freq.m = freq;
    iwr.u.freq.e = 6;
    iwr.u.freq.i = 0;
    iwr.u.freq.flags = 0;
    if(ioctl(sockfd, SIOCSIWFREQ, &iwr) == -1){
      printf("Channel Error: %s\n", strerror(errno));
      close(sockfd);
      return 1;
    }
  }

  fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK); // Nonblocking socket

  printf("\n");
  if(args.list == 0){ // Call list and close
    printf("\033[?1049h\033[H");
    tcsetattr(STDIN_FILENO, TCSANOW, &stattr);
    list(sockfd, &sock, &args, &outops);
    tcsetattr(STDIN_FILENO, TCSANOW, &ogattr);
    printf("\033[0m\033[?1049l");
    close(sockfd);
    return 0;
  }

  if(args.targ_present == 0){ // Call locate and close
    printf("\033[?1049h\033[H");
    tcsetattr(STDIN_FILENO, TCSANOW, &stattr);
    locate(sockfd, &sock, &args, &outops);
    tcsetattr(STDIN_FILENO, TCSANOW, &ogattr);
    printf("\033[0m\033[?1049l");
    close(sockfd);
    return 0;
  }

  close(sockfd);
  return 0;
}
