#ifndef UIDATA_H
#define UIDATA_H

#define ALTBUFF     "\e[?1049h"
#define NRMBUFF     "\e[?1049l"

#define HOME        "\e[H"
#define CLEAR       "\e[2J"
#define CLEARLINE   "\e[2K"
#define HIDE        "\e[?25l"
#define SHOW        "\e[?25h"

#define BLACK       "\e[0;30m"
#define RED         "\e[0;31m"
#define GREEN       "\e[0;32m"
#define YELLOW      "\e[0;33m"
#define BLUE        "\e[0;34m"
#define PURPLE      "\e[0;35m"
#define CYAN        "\e[0;36m"
#define WHITE       "\e[0;37m"

#define BLACKBG     "\e[40m"
#define REDBG       "\e[41m"
#define GREENBG     "\e[42m"
#define YELLOWBG    "\e[43m"
#define BLUEBG      "\e[44m"
#define PURPLEBG    "\e[45m"
#define CYANBG      "\e[46m"
#define WHITEBG     "\e[47m"

#define NORMAL      "\e[0;37m \e[40m"
#define HIGHLIGHT   "\e[0;30m \e[47m"

typedef struct Devices Devices;

int drawdevices(Devices *devices, int selected, int start);

#endif
