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

struct s_args{
    int list;
    int mon;
    int ind;
    int help;
    int targ_present;
    int ifc_present;
    char targ[18];
    char ifc[IFNAMSIZ];
};

int usage(){
    printf("Tool for locating the source of a wifi signal\n");
    printf("Usage: wifilocator [ lmh ] [ i <iface> ] [ t <mac> ]\n");
    printf("Options:\n");
    printf("-l, --list\t\tList detected trasmitting addresses\n");
    printf("-i, --interface <iface>\tSpecifies the interface to use\n");
    printf("-m, --monitor\t\tPut the interface into monitor mode\n");
    printf("-t, --target <mac>\tThe MAC address to listen for\n");
    printf("\t\t\tUsing -l and -t together will only do -l\n");
    printf("-h, --help\t\tPrint this help message\n\n");

    return 0;
}

int monitor(int fd, struct iwreq *iwr){
    iwr->u.mode = IW_MODE_MONITOR;
    if(ioctl(fd, SIOCSIWMODE, iwr) == -1){
        printf("Monitor Error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int parseaddr(uint8_t buffer[4096]){
    uint16_t headlen;
    memcpy(&headlen, &buffer[2], 2);
    uint8_t type = buffer[headlen] & 0x0C;
    uint8_t subtype = buffer[headlen] & 0xF0;
    uint8_t ds = buffer[headlen + 1] & 0x03;
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

int parsedbm(uint8_t buffer[4096]){
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

int bar(int8_t dbm){
    struct winsize ws;
    if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1){
        return -1;
    }
    int cols = ws.ws_col;
    int red = (cols - 10) / 3;
    int yel = ((cols - 10) / 3) * 2;
    int grn = cols - 10;
    int filled = 100 - (((cols - 10) * (dbm * -1)) / 100);
    printf("%d dBm [", dbm);
    if(filled <= red){
        printf("%s", RED);
        for(int i = 0; i < filled; i++){
            printf("#");
        }
        printf("%s]\r", NRM);
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
        printf("%s]\r", NRM);
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
        printf("%s]\r", NRM);
    }
    return 0;
}

int list(int fd, struct sockaddr_ll *sock){
    int ind = 0;
    int x = 0;
    uint8_t addrs[255][6] = {0};
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
        int con = 1;
        for(int i = 0; i < x; i++){
            if(memcmp(addrs[i], addr, 6) == 0){
                con = 0;
                break;
            }
        }
        if(con == 0){
            continue;
        }
        for(int i = 0; i < 6; i++){
            addrs[x][i] = buffer[ind + i];
        }
        printf("%d) ", x + 1);
        for(int i = 0; i < 5; i++){
            printf("%02X:", addr[i]);
        }
        printf("%02X\n", addr[5]);
        x++;
        if(x == 255){
            printf("Maximum addresses reached\n");
            return -1;
        }
    }

    return 0;
}

int locate(int fd, struct sockaddr_ll *sock, struct s_args *args){
    for(int i = 0; i < 17; i++){
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

int main(int argc, char *argv[]){
    if(argc == 1){
        usage();
        return 0;
    }

    static struct option long_options[] = {
        {"list", no_argument, 0, 'l'},
        {"interface", required_argument, 0, 'i'},
        {"monitor", no_argument, 0, 'm'},
        {"target", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0,0,0,0}
    };

    struct s_args args;
    memset(&args, 0, sizeof(args));
    args.list = 1;
    args.mon = 1;
    args.help = 1;
    args.ifc_present = 1;
    args.targ_present = 1;
    int option;
    while(1 == 1){
        option = getopt_long(argc, argv, "li:mt:h", long_options, NULL);
        if(option == -1){
            break;
        }
        switch(option){
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

    if(args.ifc_present == 1){
        if(args.targ_present == 0 || args.list == 0 || args.mon == 0){
            printf("Error: -i, --interface argument required\n");
            return 1;
        }
        else{
            return 0;
        }
    }

    if(args.targ_present == 0){
        if(strlen(args.targ) != 17){
            printf("Error: MAC address should be 17 characters\n");
            return 1;
        }
    }

    struct iwreq iwr;
    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_ifrn.ifrn_name, args.ifc, IFNAMSIZ);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, args.ifc, IFNAMSIZ);

    struct sockaddr_ll sock;
    memset(&sock, 0, sizeof(sock));
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd == -1){
        printf("Socket Creation Error: %s\n", strerror(errno));
        return 1;
    }

    if(args.mon == 0){
        if(monitor(sockfd, &iwr) == -1){
            close(sockfd);
            return 1;
        }
    }

    if(args.list == 1 && args.targ_present == 1){
        close(sockfd);
        return 0;
    }

    if(ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1){
        printf("Index Error: %s\n", strerror(errno));
        close(sockfd);
        return 1;
    }
    args.ind = ifr.ifr_ifindex;

    iwr.u.mode = 0;
    if(ioctl(sockfd, SIOCGIWMODE, &iwr) == -1){
        printf("Mode Check Error: %s\n", strerror(errno));
        close(sockfd);
        return 1;
    }
    if(iwr.u.mode != 6){
        printf("Error: Interface must be in monitor mode\n");
        printf("Use -m option to put the interface into monitor mode\n");
        close(sockfd);
        return 1;
    }

    sock.sll_family = AF_PACKET;
    sock.sll_protocol = htons(ETH_P_ALL);
    sock.sll_ifindex = args.ind;

    if(bind(sockfd, (struct sockaddr *)&sock, sizeof(sock)) == -1){
        printf("Socket Bind Error: %s\n", strerror(errno));
        close(sockfd);
        return 1;
    }

    if(args.list == 0){
        list(sockfd, &sock);
        close(sockfd);
        return 0;
    }

    if(args.targ_present == 0){
        locate(sockfd, &sock, &args);
        close(sockfd);
        return 0;
    }

    close(sockfd);
    return 0;
}
