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

#define OUI_SIZE 20000
#define BUF_SIZE 4096
#define DEFAULT_MAX_ADDR 32

#define RED "\e[31m"
#define YEL "\e[33m"
#define GRN "\e[32m"
#define BLK "\e[30m"
#define WTBCKGRND_HI "\e[107m"
#define NRM "\e[0m"

#define CLS "\e[2J"
#define HME "\e[H"
#define ALTBUF "\e[?1049h"
#define NRMBUF "\e[?1049l"
#define UPONE "\e[1F"

time_t last_sigint = 0; // time() called in first line of main()
volatile sig_atomic_t sigint_set = 0; // Was ctrl C pressed

struct termios ogattr, stattr; // Set in second line of main()

static void sigint_handler(int signum){ // Handle ctrl C "properly"
    time_t sigint_time = time(NULL);
    if(sigint_time - last_sigint <= 3){ // Less than 3 seconds
        sigint_set = 2;
    }
    else{
        last_sigint = sigint_time;
        sigint_set = 1;
    }
}

struct s_args{ // Command line arguments
    int list; // List flag set
    int mon; // Set monitor mode flag set
    int ind; // Index of interface
    int scan; // Scan flag set
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
    int no_org; // Do not resolve OUI's
    int bssid_only; // Only scan for BSSIDs
    int verbose; // Verbose output
};

struct ll_list_head{ // Head for linked list in list function
    struct ll_list *next; // Pointer to first node
    struct ll_list *last; // pointer to last node
};

struct ll_list{ // Nodes for linked list in list function
    struct ll_list *next; // Pointer to next
    struct ll_list *prev; // Pointer to previous
    uint8_t addr[6]; // The tx address
    int frames_recv; // Number of frames received
    uint8_t channel; // Channel number
    time_t last_frame; // Time of last frame
    char *org; // Pointer to org name
};

struct ll_scan{ // Struct for linked list nodes
    struct ll_scan *next; //Next in linked list
    char ssid[33]; // SSID
    int freq; // Associated freq
    uint8_t active; // Is channel active
};

struct hm_oui{ // Struct for hashmap nodes
    struct hm_oui *next; // Pointer to next
    uint8_t oui[3]; // The OUI of the entry
    char org[13]; // The assigned organization
};

const uint8_t channel_nums[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,32,36,40,44,48,52,56,60,64,68,
    72,76,80,84,88,92,96,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165,169,173,177};

const uint16_t channel_freq[] = {2412,2417,2422,2427,2432,2437,2442,2447,2452,2457,2462,2467,2472,
    2484,5160,5180,5200,5220,5240,5260,5280,5300,5320,5340,5360,5380,5400,5420,5440,5460,5480,5500,
    5520,5540,5560,5580,5600,5620,5640,5660,5680,5700,5720,5745,5765,5785,5805,5825,5845,5865,5885};

uint32_t mhash(uint8_t *key, size_t len){ // Murmurhash function
        uint32_t h = 0x9747b28c;
        uint32_t c1 = 0xcc9e2d51;
        uint32_t c2 = 0x1b873593;

        while (len >= 4) {
                uint32_t k = *(uint32_t*)key;

                k *= c1;
                k = (k << 15) | (k >> 17);
                k *= c2;

                h ^= k;
                h = (h << 13) | (h >> 19);
                h = h * 5 + 0xe6546b64;

                key += 4;
                len -= 4;
        }

        uint32_t k = 0;
        if (len >= 3) k ^= key[2] << 16;
        if (len >= 2) k ^= key[1] << 8;
        if (len >= 1) k ^= key[0];

        if (len) {
                k *= c1;
                k = (k << 15) | (k >> 17);
                k *= c2;
                h ^= k;
        }

        h ^= h >> 16;
        h *= 0x85ebca6b;
        h ^= h >> 13;
        h *= 0xc2b2ae35;
        h ^= h >> 16;

        return h;
}

struct hm_oui **hm_gen(int verbose){ // Generate oui hashmap
    if(verbose == 1){
        printf("Opening oui24.txt and creating hashmap\n");
    }
    FILE *fdoui = fopen("oui24.txt", "r");
    struct hm_oui **hm_arr = malloc(OUI_SIZE * sizeof(struct hm_oui *)); // Allocate map
    for(int i = 0; i < OUI_SIZE; i++){ // Set inital array to null pointers
        hm_arr[i] = NULL;
    }

    while(1 == 1){
        char line[32] = {0};
        char *ret = fgets(line, sizeof(line), fdoui); // Get line from file
        if(ret == NULL || line[0] == '\n'){
            break;
        }

        uint8_t oui[3] = {0};
        char org[13] = {0};
        int x = 0;
        for(int i = 0; i < 3; i++){ // Ascii oui to hex
            if(line[i + x] >= 65 && line[i + x] <= 90){
                oui[i] += (line[i + x] - 55) * 16;
                x++;
            }
            else if(line[i + x] >= 48 && line[i + x] <= 57){
                oui[i] += (line[i + x] - 48) * 16;
                x++;
            }
            if(line[i + x] >= 65 && line[i + x] <= 90){
                oui[i] += (line[i + x] - 55);
            }
            else if(line[i + x] >= 48 && line[i + x] <= 57){
                oui[i] += (line[i + x] - 48);
            }
        }
        for(int i = 0; i < 13; i++){ // Grab organization name from file
            org[i] = line[i + 6];
            if(org[i] == '\n' || org[i] == '\r'){
                org[i] = '\0';
                break;
            }
        }

        int hm_index = mhash(&oui[0], 3) % OUI_SIZE; // Hash the oui
        struct hm_oui *newnode = malloc(sizeof(struct hm_oui));
        newnode->oui[0] = oui[0];
        newnode->oui[1] = oui[1];
        newnode->oui[2] = oui[2];
        strncpy(newnode->org, org, sizeof(newnode->org));
        newnode->next = hm_arr[hm_index];
        hm_arr[hm_index] = newnode;
    }
    if(verbose == 1){
        printf("Closeing oui24.txt\n");
    }

    fclose(fdoui);
    return hm_arr;
}

int hm_free(struct hm_oui **hm_arr){ // Free oui hashmap
    for(int i = 0; i < OUI_SIZE; i++){
        struct hm_oui *current = hm_arr[i];
        struct hm_oui *nextnode = NULL;
        while(current != NULL){
            nextnode = current->next;
            free(current);
            current = nextnode;
        }
    }

    free(hm_arr);
    return 0;
}

char *hm_lookup(uint8_t p_oui[3], struct hm_oui **hm_arr){ // Resolve oui to org name
    uint8_t oui[3] = {p_oui[0], p_oui[1], p_oui[2]};
    int hash = mhash(&oui[0], 3) % OUI_SIZE;
    struct hm_oui *current = hm_arr[hash];
    while(current != NULL){
        if(current->oui[0] == oui[0] && current->oui[1] == oui[1] && current->oui[2] == oui[2]){
            return current->org;
            break;
        }
        else{
            current = current->next;
        }
    }

    return NULL;
}

int pop_ll_list(struct ll_list_head *head, struct ll_list *current){ // Delete node from list linked list
    if(current->prev != NULL){
        current->prev->next = current->next;
    }
    else{
        head->next = current->next;
    }
    if(current->next != NULL){
        current->next->prev = current->prev;
    }
    else{
        head->last = current->prev;
    }

    free(current);
    return 0;
}

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
    "\t\t\t\tValue < 1000 denotes channel, value > 1000 denotes Mhz\n"
    "-v, --verbose\t\t\tOutput verbose information\n"
    "-h, --help\t\t\tDisplay this help message\n\n"
    "Output options:\n"
    "--bssid-only\t\t\tOnly scan for access points\n"
    "--maximum-addresses <num>\tThe maximum number of addresses" 
    "to be\n\t\t\t\tlisted by the --list option, defaul 32\n"
    "--no-frame-counter\t\tDo not output frame counters\n"
    "--no-aging\t\t\tDo not age out addresses\n"
    "--no-channel\t\t\tDo not display channel\n"
    "--no-org\t\t\tDo not resolve address OUI's\n\n"
    "Notes:\n"
    "The interface must be in monitor mode to operate\n"
    "If --list and --target are used together, "
    "--target will be ignored\nThe MAC address should be six groups "
    "of seperated hex digits, any case\n\n"
    "Examples:\n"
    "wifilocator -i wlan0 -m -i\n"
    "wifilocator -i wlan0 -t xx:xx:xx:xx:xx:xx\n"
    "wifilocator --interface wlan0 --list --no-frame-counter\n\n");

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

uint8_t freq_to_channel(int freq){ // Turn frequency into channel number
    for(int i = 0; i < 51; i++){
        if(channel_freq[i] == freq){
            return channel_nums[i];
        }
    }

    return 0;
}

int parseaddr(uint8_t buffer[BUF_SIZE], int bssid_only){ // Get the tx addr offset in the frame
    // Fuck 802.11 addressing
    uint16_t headlen;
    memcpy(&headlen, &buffer[2], 2); // Radiotap header length
    uint8_t type = buffer[headlen] & 0x0C; // Frame type
    uint8_t subtype = buffer[headlen] & 0xF0; // Frame subtype
    uint8_t ds = buffer[headlen + 1] & 0x03; // DS bits
    int bssid = 0; // Addr is a bssid
    int index = 0; // Index of addr
    // Checking for frame type and subtype to get addr offset
    if(type == 0x00){ // Management Frame
        if(memcmp(&buffer[headlen + 10], &buffer[headlen + 16], 6) == 0){
            bssid = 1;
        }
        index = headlen + 10;
    }
    else if(type == 0x04){ // Control Frame
        switch(subtype){
            case 0x40: // Beamforming
                bssid = 1;
                index = headlen + 10;
                break;
            case 0x50: // NDP Announcement
                index = headlen + 10;
                break;
            case 0x80: // Block Ack Request
                index = headlen + 10;
                break;
            case 0x90: // Block Ack
                bssid = 1;
                index = headlen + 10;
                break;
            case 0xA0: // PS-Poll
                index = headlen + 10;
                break;
            case 0xB0: // RTS
                index = headlen + 10;
                break;
            case 0xE0: // CF-End
                bssid = 1;
                index = headlen + 10;
                break;
            case 0xF0: // CF-End+CF-Ack
                bssid = 1;
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
                    bssid = 1;
                }
                index = headlen + 10;
                break;
            case 0x01:
                bssid = 1;
                index = headlen + 10;
                break;
            case 0x02:
                index = headlen + 10;
                break;
            case 0x03:
                bssid = 1;
                index = headlen + 10;
                break;
            default:
                return -1;
        }
    }
    else{
        return -1;
    }

    if(bssid_only == 0){
        return index;
    }
    else if(bssid_only == 1 && bssid == 1){
        return index;
    }

    return -1;
}

int parsedbm(uint8_t buffer[BUF_SIZE]){ // Get the dbm offset in the frame
    // Checking for flags and adjusting the offset
    int offset = 0;
    int present = 0;
    while(1 == 1){ // Multiple flag fields
        if((buffer[7 + present] & 0x20) == 0x00)
            break;
        else{
            offset += 4;
            present += 4;
        }
    }

    while(buffer[offset + 8] == 0x00){ // fuck padding
        offset += 1;
    }
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

int parsechannel(uint8_t buffer[BUF_SIZE]){ // Get channel offset in frame
    int offset = 0;
    int present = 0;
    while(1 == 1){ // Multiple flag fields
        if((buffer[7 + present] & 0x20) == 0x00)
            break;
        else{
            offset += 4;
            present += 4;
        }
    }

    while(buffer[offset + 8] == 0x00){ // fuck padding
        offset += 1;
    }
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

int parsessid(uint8_t buffer[BUF_SIZE], int recvn){ // Get the ssid offset in frame
    uint16_t headlen;
    memcpy(&headlen, &buffer[2], 2); // Radiotap header length
    uint8_t type = buffer[headlen] & 0x0C; // Frame type
    uint8_t subtype = buffer[headlen] & 0xF0; // Frame subtype
    if(type != 0x00){
        return -1;
    }

    if(subtype == 0x80 || subtype == 0x50){
        int ssidind = headlen + 36;
        while(ssidind < recvn){ // !!!!! POSSIBLE MEMORY SHIT !!!!!
            switch(buffer[ssidind]){
                case 0x00:
                    if(buffer[ssidind + 1] > 32){
                        return -1;
                    }
                    return ssidind;
                    break;
                default:
                    ssidind += (buffer[ssidind + 1] + 2);
                    break;
            }
        }
    }

    return -1;
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
    int filled = (((cols - 10) * (100 - dbm * -1)) / 100); // Convert to percent
    int empty = cols - filled - 10;
    printf("%d dBm [", dbm);
    if(filled <= red){
        printf("%s", RED);
        for(int i = 0; i < filled; i++){
            printf("#");
        }
        printf("%s", NRM);
        for(int i = 0; i < empty; i++){
            printf("#");
        }
        printf("]");
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
        printf("%s", NRM);
        for(int i = 0; i < empty; i++){
            printf("#");
        }
        printf("]");
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
        printf("%s", NRM);
        for(int i = 0; i < empty; i++){
            printf("#");
        }
        printf("]");
    }
    printf("\n");

    return 0;
}

int locate(int fd, struct sockaddr_ll *sock, struct s_args *args, struct s_outops *outops, struct hm_oui **hm_arr){ // Display dBm of tx
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
    char *org = hm_lookup(&target[0], hm_arr);
    while(1 == 1){
        if(sigint_set == 2){
            return 0;
        }
        char l_input = 0;
        int l_readn = read(STDIN_FILENO, &l_input, 1);
        if(l_readn > 0){
            switch(l_input){
                case 'q': // User pressed 'q'
                    printf("%s%s", CLS, HME);
                    return 0;
                    break;
            }
        }

        uint8_t buffer[BUF_SIZE] = {0};
        uint8_t addr[6] = {0};
        int l_recvn = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL); // Recv
        if(l_recvn == -1){
            if(errno == EAGAIN || errno == EWOULDBLOCK){
                continue;
            }
            else{
                printf("Recv Error: %s\n", strerror(errno));
                return -1;
            }
        }
        else if(l_recvn > 0){
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

            bar(dbm); // Print bar
            if(outops->no_org == 0){
                printf("Listening for %s_", org);
            }
            else{
                printf("Listening for ");
            }
            printf("%02X:%02X:%02X:%02X:%02X:%02X",
                target[0], target[1], target[2], target[3],
                target[4], target[5]);
            if(outops->no_frame_counter == 0){
                printf(" | %d Frames Received", frames_received);
            }
            if(outops->no_channel == 0){
                printf(" on channel %d", args->channel);
            }
            printf(" | Press 'q' to return...");
            if(sigint_set == 1){
                printf(" Press ctrl + C again to quit");
                if(time(NULL) - last_sigint > 3){
                    sigint_set = 0;
                }
            }
            printf("\n%s", UPONE);
        }
    }

    return 0;
}

int list(int fd, struct sockaddr_ll *sock, struct s_args *args, struct s_outops *outops, struct hm_oui **hm_arr){ // List recved addrs
    if(outops->max_addrs <= 0){ // Zero max addrs edge case
        printf("Maximum addresses reached\n");
        return -1;
    }

    struct ll_list_head *head = malloc(sizeof(struct ll_list_head)); // Head of linked list
    head->next = NULL;
    head->last = NULL;
    int selected = 1;
    int numaddrs = 0;
    int change = 1;
    while(1 == 1){ // Main loop
        if(sigint_set == 2){
            return 0;
        }
        uint8_t buffer[BUF_SIZE] = {0};
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
        else if(recvn > 0){
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

            struct ll_list *duplicate = head->next;
            while(duplicate != NULL){
                if(memcmp(duplicate->addr, addr, 6) == 0){
                    break;
                }
                duplicate = duplicate->next;
            }

            if(duplicate != NULL){ // Check if addr is already in list
                duplicate->frames_recv += 1;
                duplicate->last_frame = time(NULL);
                duplicate->channel = channel;
            }
            else{ // Add new addr to list
                if(numaddrs > outops->max_addrs){
                    continue;
                }

                struct ll_list *new_node = malloc(sizeof(struct ll_list));
                memcpy(new_node->addr, addr, 6);
                new_node->frames_recv = 1;
                new_node->last_frame = time(NULL);
                new_node->channel = channel;
                new_node->org = hm_lookup(&addr[0], hm_arr);
                new_node->next = NULL;
                new_node->prev = head->last;
                if(new_node->prev != NULL){
                    new_node->prev->next = new_node;
                }
                else{
                    head->next = new_node;
                }
                head->last = new_node;
                numaddrs += 1;
            }
            change = 1;
        }

        if(outops->no_aging == 0){
            time_t current_time = time(NULL);
            struct ll_list *current = head->next;
            while(current != NULL){ // Agin out inactive addresses
                if(current_time - current->last_frame <= 5){ // 5 second grace period
                    current = current->next;
                    continue;
                }
                else{ // The chopping block
                    struct ll_list *next = current->next;
                    if(current->frames_recv <= 5){
                        pop_ll_list(head, current); // 5 seconds inactive less than 5 frames
                        numaddrs -= 1;
                    }
                    else if(current->frames_recv <= 100 && current_time - current->last_frame >= 30){
                        pop_ll_list(head, current); // 30 seconds inactive less than 100 frames
                        numaddrs -= 1;
                    }
                    else if(current->frames_recv <= 1000 && current_time - current->last_frame >= 60){
                        pop_ll_list(head, current); // 6 seconds inactive less than 1000 frames
                        numaddrs -= 1;
                    }
                    else if(current_time - current->last_frame >= 180){
                        pop_ll_list(head, current); // 3 minutes inactive regardless of frames
                        numaddrs -= 1;
                    }
                    current = next;
                }
            }
            printf("%s", CLS);
        }

        char input[3] = {0};
        int readn = read(STDIN_FILENO, &input, 3); // Reading user input
        if(readn > 0){ // Moving selector up or down
            switch(input[2]){
                case 'A':
                    selected -= 1;
                    break;
                case 'B':
                    selected += 1;
                    break;
            }
            switch(input[0]){ // Locate selected addr
                case 10: // LF
                    struct ll_list *addrselected = head->next;
                    for(int i = 1; i != selected; i++){
                        addrselected = addrselected->next;
                    }
                    snprintf(args->targ, 17, "%02X:%02X:%02X:%02X:%02X:%02X",
                        addrselected->addr[0], addrselected->addr[1],
                        addrselected->addr[2], addrselected->addr[3],
                        addrselected->addr[4], addrselected->addr[5]);
                    printf("%s%s", CLS, HME);
                    locate(fd, sock, args, outops, hm_arr);
                    break;
            }
            change = 1;
        }
        if(selected > numaddrs){ // Wrap selector
            selected = 1;
        }
        else if(selected < 1){ // Wrap selector
            selected = numaddrs;
        }

        if(change == 1){ // Print everything
            printf("%s", HME); // Move cursor home
            struct ll_list *current = head->next;
            int inc = 1;
            while(current != NULL){
                if(selected == inc){
                    printf("%s%S", BLK, WTBCKGRND_HI);
                }
                printf("%d) ", inc);
                if(outops->no_org == 0 && current->org != NULL){
                    printf("%s_", current->org);
                }
                printf("%02X:%02X:%02X:%02X:%02X:%02X",
                current->addr[0], current->addr[1], current->addr[2], 
                current->addr[3], current->addr[4], current->addr[5]); 
                if(outops->no_frame_counter == 0){
                    printf(" %d Frames Received", current->frames_recv);
                }
                if(outops->no_channel == 0){
                    printf(" Channel %d", current->channel);
                }
                if(selected == inc){
                    printf("%s", NRM);
                }
                printf("\n");
                inc += 1;
                current = current->next;
            }
            printf("Use Arrow Keys and Enter to select address\n");
            if(sigint_set == 1){
                printf(" Press ctrl + C again to quit\n");
                if(time(NULL) - last_sigint > 3){
                    sigint_set = 0;
                }
            }
            change = 0;
        }
    }

    struct ll_list *current = head->next; // Free linked list
    head->next = NULL;
    head->last = NULL;
    free(head);
    while(current != NULL){
        struct ll_list *next_node = current->next;
        free(current);
        current = next_node;
    }

    return 0;
}

int channel_scan(int fd, struct iwreq *iwr, struct s_args *args, struct s_outops *s_outops, struct iw_range *range){ // Scan channels
    time_t scantime = time(NULL);
    uint16_t num_channels = range->num_channels;
    struct ll_scan *heads[num_channels];
    for(int i = 0; i < num_channels; i++){
        heads[i] = NULL;
    }

    int channel_index = 0;
    while(1 == 1){
        if(sigint_set == 2){
            return 0;
        }

        if(time(NULL) - scantime > 1){
            channel_index += 1;
            if(channel_index >= num_channels){
                channel_index = 0;
            }
            memset(iwr, 0, sizeof(*iwr));
            strncpy(iwr->ifr_ifrn.ifrn_name, args->ifc, IFNAMSIZ);
            iwr->u.freq.m = range->freq[channel_index].m;
            iwr->u.freq.e = 6;
            iwr->u.freq.i = 0;
            iwr->u.freq.flags = 0;
            if(ioctl(fd, SIOCSIWFREQ, iwr) == -1){ // Channel change
                printf("Channel Error: %s\n", strerror(errno));
                return -1;
            }
            scantime = time(NULL);
        }

        uint8_t buffer[BUF_SIZE] = {0};
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
        else if(recvn > 0){
            int ssidind = parsessid(buffer, recvn);
            int frequency = ((buffer[parsechannel(buffer) + 1] * 0x100) + buffer[parsechannel(buffer)]);
            if(ssidind <= 0){
                continue;
            }

            struct ll_scan *current = heads[channel_index];
            int duplicate = 0;
            while(current != NULL){
                if(memcmp(&buffer[ssidind + 2], current->ssid, buffer[ssidind + 1]) == 0){
                    duplicate = 1;
                    break;
                }
                current = current->next;
            }
            if(duplicate == 1){
                continue;
            }

            struct ll_scan *new_node = malloc(sizeof(struct ll_scan));
            new_node->active = 1;
            new_node->freq = frequency;
            new_node->next = NULL;
            if(buffer[ssidind + 1] == 0){
                memcpy(new_node->ssid, "Hidden Network\0", 15);
            }
            else if(buffer[ssidind + 1] > 0){
                memcpy(new_node->ssid, &buffer[ssidind + 2], buffer[ssidind + 1]);
                new_node->ssid[buffer[ssidind + 1]] = '\0';
            }
            current = heads[channel_index];
            if(current == NULL){
                heads[channel_index] = new_node;
            }
            else{
                while(current->next != NULL){
                    current = current->next;
                }
                current->next = new_node;
            }
        }

        printf("%s%s", CLS, HME);
        for(int i = 0; i < num_channels; i++){
            struct ll_scan *current = heads[i];
            if(i == channel_index){
                printf("--->");
            }
            printf("Channel %d (%d Mhz): ", freq_to_channel(range->freq[i].m), range->freq[i].m);
            if(current == NULL){
                printf("%sIn-Active%s\n\tSSID:\n", RED, NRM);
            }
            else{
                printf("%sActive%s\n\tSSID:\n", GRN, NRM);
                while(current != NULL){
                    printf("\t%s\n", current->ssid);
                    current = current->next;
                }
            }
        }
        if(sigint_set == 2){
            printf(" Press ctrl + C again to quit\n");
            if(time(NULL) - last_sigint > 3){
                sigint_set = 0;
            }
        }
    }

    for(int i = 0; i < num_channels; i++){
        struct ll_scan *current = heads[i];
        while(current != NULL){
            struct ll_scan *next = current->next;
            free(current);
            current = next;
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
        {"scan", no_argument, 0, 's'},
        {"channel", required_argument, 0, 'c'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"maximum-addresses", required_argument, 0, 0},
        {"no-frame-counter", no_argument, 0, 0},
        {"no-channel", no_argument,0, 0},
        {"no-bar-in-place", no_argument, 0, 0},
        {"no-aging", no_argument, 0, 0},
        {"no-org", no_argument, 0, 0},
        {"bssid-only", no_argument, 0, 0},
        {0,0,0,0}
    };

    struct s_outops outops; // Initialize outops with default values
    memset(&outops, 0, sizeof(outops));
    outops.max_addrs = DEFAULT_MAX_ADDR;
    struct s_args args; // Initialize args with default values
    memset(&args, 0, sizeof(args));
    args.channel = -1;
    int option;
    while(1 == 1){ // Get flags and options
        int option_index = 0;
        option = getopt_long(argc, argv, "li:mt:sc:vh", long_options, &option_index);
        if(option == -1){
            break;
        }
        switch(option){
            case 0:
                if(strcmp(long_options[option_index].name, "maximum-addresses") == 0){
                    outops.max_addrs = atoi(optarg);
                }
                else if(strcmp(long_options[option_index].name, "no-frame-counter") == 0){
                    outops.no_frame_counter = 1;
                }
                else if(strcmp(long_options[option_index].name, "no-channel") == 0){
                    outops.no_channel = 1;
                }
                else if(strcmp(long_options[option_index].name, "no-bar-in-place") == 0){
                    outops.no_bar_in_place = 1;
                }
                else if(strcmp(long_options[option_index].name, "no-aging") == 0){
                    outops.no_aging = 1;
                }
                else if(strcmp(long_options[option_index].name, "no-org") == 0){
                    outops.no_org = 1;
                }
                else if(strcmp(long_options[option_index].name, "bssid-only") == 0){
                    outops.bssid_only = 1;
                }
                continue;
            case 'l':
                args.list = 1;
                continue;
            case 'i':
                strncpy(args.ifc, optarg, strlen(optarg));
                args.ifc_present = 1;
                continue;
            case 'm':
                args.mon = 1;
                continue;
            case 't':
                strncpy(args.targ, optarg, strlen(optarg));
                args.targ_present = 1;
                continue;
            case 's':
                args.scan = 1;
                continue;
            case 'c':
                args.channel = atoi(optarg);
                continue;
            case 'v':
                outops.verbose = 1;
                continue;
            case 'h':
                args.help = 1;
                usage();
                continue;
            default:
                continue;
        }
    }

    if(outops.verbose == 1){
        printf("Starting...\nChecking arguments\n");
    }
    if(args.ifc_present == 0){ // Check for interface argument
        if(args.targ_present == 1 || args.list == 1 || args.mon == 1 || args.channel != -1 || args.scan == 1){
            printf("Error: -i, --interface argument required\n");
            return 1;
        }
        else{
            return 0;
        }
    }

    if(args.targ_present == 1){ // Check MAC addr format
        if(outops.verbose == 1){
            printf("Checking target address format\n");
        }
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

    if(outops.verbose == 1){
        printf("Attempting to create raw socket\n");
    }
    struct sockaddr_ll sock; // Create raw socket
    memset(&sock, 0, sizeof(sock));
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd == -1){
        printf("Socket Creation Error: %s\n", strerror(errno));
        return 1;
    }
    if(outops.verbose == 1){
        printf("Socket created, FD=%d\n", sockfd);
    }

    if(args.mon == 1){ // Set monitor mode
        if(outops.verbose == 1){
            printf("Attempting to set monitor mode on %s\n", args.ifc);
        }
        if(monitor(sockfd, &iwr) == -1){
            close(sockfd);
            return 1;
        }
        if(outops.verbose == 1){
            printf("Monitor mode set\n");
        }
    }

    if(args.list == 0 && args.targ_present == 0 && args.scan == 0 && args.channel == -1){ // Exit if done
        if(outops.verbose == 1){
            printf("Exiting\n");
        }
        close(sockfd);
        return 0;
    }

    if(outops.verbose == 1){
        printf("Retrieving interface index\n");
    }
    if(ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1){ // Get index of interface
        printf("Index Error: %s\n", strerror(errno));
        close(sockfd);
        return 1;
    }
    args.ind = ifr.ifr_ifindex;
    if(outops.verbose == 1){
        printf("Interface found at index %d\n", args.ind);
    }

    if(outops.verbose == 1){
        printf("Checking interface mode\n");
    }
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
    if(outops.verbose == 1){
        printf("Interface in monitor mode\n");
    }

    sock.sll_family = AF_PACKET;
    sock.sll_protocol = htons(ETH_P_ALL);
    sock.sll_ifindex = args.ind;

    if(outops.verbose == 1){
        printf("Binding raw socket to interface %s\n", args.ifc);
    }
    if(bind(sockfd, (struct sockaddr *)&sock, sizeof(sock)) == -1){ // Bind raw socket to index
        printf("Socket Bind Error: %s\n", strerror(errno));
        close(sockfd);
        return 1;
    }
    if(outops.verbose == 1){
        printf("Socket bound\n");
    }

    if(args.channel != -1){ // Change channel if set
        if(outops.verbose == 1){
            printf("Channel argument detected\n"
            "Attempting to set channel\n");
        }
        memset(&iwr, 0, sizeof(iwr));
        strncpy(iwr.ifr_ifrn.ifrn_name, args.ifc, IFNAMSIZ);
        int freq = 0;
        if(args.channel < 1000){
            for(int i = 0; i < 51; i++){
                if(channel_nums[i] == args.channel){
                    freq = channel_freq[i];
                    break;
                }
            }
        }
        else if(args.channel >= 1000){
            freq = args.channel;
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
        if(outops.verbose == 1){
            printf("Interface operating at %d MHz\n", freq);
        }
    }

    if(outops.verbose == 1){
        printf("Making socket non-blocking\n");
    }
    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK); // Nonblocking socket

    struct hm_oui **hm_arr = hm_gen(outops.verbose);

    if(args.scan == 1){ // Call channel_scan and close
        if(outops.verbose){
            printf("Getting available channels\n");
        }
        memset(&iwr, 0, sizeof(iwr));
        strncpy(iwr.ifr_ifrn.ifrn_name, args.ifc, IFNAMSIZ);
        struct iw_range range; // Data from driver
        memset(&range, 0, sizeof(range));
        iwr.u.data.pointer = &range;
        iwr.u.data.length = sizeof(range);
        if(ioctl(sockfd, SIOCGIWRANGE, &iwr) == -1){
            printf("Error: %s\n", strerror(errno));
            close(sockfd);
            return 1;
        }
        if(range.num_channels <= 0){
            printf("Channel Error: Zero channels returned\n");
            close(sockfd);
            return 1;
        }
        if(outops.verbose == 1){
            printf("Available channels: %d\n", range.num_channels);
            for(int i = 0; i < range.num_channels; i++){
                printf("%d Mhz\n", range.freq[i].m);
            }
            printf("Enabling non-canonical mode\n"
            "Entering channel scan mode\n");
        }

        printf("%s%s\n", ALTBUF, HME);
        tcsetattr(STDIN_FILENO, TCSANOW, &stattr);
        channel_scan(sockfd, &iwr, &args, &outops, &range);
        tcsetattr(STDIN_FILENO, TCSANOW, &ogattr);
        printf("%s%s", NRM, NRMBUF);
        close(sockfd);
        if(outops.verbose == 1){
            printf("Exiting\n");
        }
    
        return 0;
    }

    if(args.list == 1){ // Call list and close
        if(outops.verbose == 1){
            printf("Enabling non-canonical mode\n"
            "Entering list mode\n");
        }

        printf("%s%s\n", ALTBUF, HME);
        tcsetattr(STDIN_FILENO, TCSANOW, &stattr);
        list(sockfd, &sock, &args, &outops, hm_arr);
        tcsetattr(STDIN_FILENO, TCSANOW, &ogattr);
        printf("%s%s", NRM, NRMBUF);
        close(sockfd);
        if(outops.verbose == 1){
            printf("Exiting\n");
        }
    
        return 0;
    }

    if(args.targ_present == 1){ // Call locate and close
        if(outops.verbose == 1){
            printf("Enabling non-canonical mode\n"
            "Entering locate mode\n");
        }

        printf("%s%s\n", ALTBUF, HME);
        tcsetattr(STDIN_FILENO, TCSANOW, &stattr);
        locate(sockfd, &sock, &args, &outops, hm_arr);
        tcsetattr(STDIN_FILENO, TCSANOW, &ogattr);
        printf("%s%s", NRM, NRMBUF);
        close(sockfd);
        if(outops.verbose == 1){
            printf("Exiting\n");
        }
    
        return 0;
    }

    hm_free(hm_arr);
    close(sockfd);
    return 0;
}
