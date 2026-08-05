#ifndef HARDWARE_H
#define HARDWARE_H

typedef struct nl80211_t{
	int fd;
	uint16_t fam_id;
	uint32_t if_index;
} nl80211_t;

int nl_init_80211(int if_index, nl80211_t *ret);
int nl_ismonitor(nl80211_t *nlfd);
int nl_setmonitor(nl80211_t *nlfd);
int nl_getchannels(nl80211_t *nlfd);
int nl_setchannel(nl80211_t *nlfd, uint32_t freq);

#endif
