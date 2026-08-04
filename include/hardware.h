#ifndef HARDWARE_H
#define HARDWARE_H

int nl_genetlink_socket();
int nl_ismonitor(int nlfd);
int nl_setmonitor(int nlfd);
int nl_setchannel(int nlfd);

#endif
