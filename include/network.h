#ifndef NETWORK_H
#define NETWORK_H

int openbindraw(char *if_name);
int ismonitor(int fd, char *if_name);
int setmonitor(int fd, char *if_name);
int setchannel(int fd, char *if_name, Channels *channels);

#endif
