#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cipher.c"

typedef enum {
	MSG_PUNCH = 0x41,
	MSG_P2P_RDY = 0x042,
	MSG_DRW = 0xd0,
	MSG_DRW_ACK = 0xd1,
	MSG_ALIVE = 0xe0,
	MSG_ALIVE_ACK = 0xe1,
	MSG_CLOSE = 0xf0
} MsgType;

char *MsgTypeText[256];

#define MsgSlot(a)	MsgTypeText[a] = #a
static void init_MsgTypeText() {
	MsgSlot(MSG_PUNCH);
	MsgSlot(MSG_P2P_RDY);
	MsgSlot(MSG_DRW);
	MsgSlot(MSG_DRW_ACK);
	MsgSlot(MSG_ALIVE);
	MsgSlot(MSG_ALIVE_ACK);
	MsgSlot(MSG_CLOSE);
}

int udp;
int http;
int client;

int sendvideo;

struct sockaddr local, bcast;
struct sockaddr camera;

struct sockaddr_in *ilocal = (struct sockaddr_in *)&local;
struct sockaddr_in *ibcast = (struct sockaddr_in *)&bcast;
struct sockaddr_in *icamera = (struct sockaddr_in *)&camera;

#define DEBUG(x, ...)	fprintf(stderr, (x), __VA_ARGS__)

static char probe[] = {0x2c, 0xba, 0x5f, 0x5d};	/* MSG_LAN_SEARCH, encrypted */
#define PROBE_PORT	32108
#define HTTP_PORT	8080

int timeread(int fd, myval *val)
{
	fd_set infds;
	struct timeval tv;
	int i;

	tv.tv_sec = 0;
	tv.tv_usec = 100000;	/* 100msec */
	FD_ZERO(&infds);
	FD_SET(fd, &infds);
	i = select(fd+1, &infds, NULL, NULL, &tv);
	if (!i)
		return 0;
	return read(fd, val->mv_data, val->mv_size);
}

int timerecv(int fd, myval *val, struct sockaddr *from, socklen_t *fromlen)
{
	fd_set infds;
	struct timeval tv;
	int i;

	tv.tv_sec = 0;
	tv.tv_usec = 100000;	/* 100msec */
	FD_ZERO(&infds);
	FD_SET(fd, &infds);
	i = select(fd+1, &infds, NULL, NULL, &tv);
	if (!i)
		return 0;
	return recvfrom(fd, val->mv_data, val->mv_size, 0, from, fromlen);
}

int connect_camera()
{
	int i;
	if ((udp = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
		perror("udp socket");
		exit(1);
	}

	i = 1;
	if (setsockopt(udp, SOL_SOCKET, SO_BROADCAST, (char *)&i, sizeof(i)) < 0) {
		perror("udp setsockopt BROADCAST");
		exit(1);
	}
	ilocal->sin_port = 0;
	if (bind(udp, &local, sizeof(*ilocal)) < 0) {
		perror("udp bind");
		exit(1);
	}
	ibcast->sin_port = htons(PROBE_PORT);
	for (i=0; i<5; i++) {
		char pktbuf[128], pkt2[128];
		myval pktval = {sizeof(pktbuf), pktbuf};
		socklen_t slen = sizeof(camera);
		int len;

		if (sendto(udp, probe, sizeof(probe), 0, &bcast, sizeof(*ibcast)) != sizeof(probe)) {
			perror("udp send broadcast");
			exit(1);
		}
		DEBUG("sent MSG_LAN_SEARCH to %s:%d\n", inet_ntoa(ibcast->sin_addr), ntohs(ibcast->sin_port));
		if ((len = timerecv(udp, &pktval, &camera, &slen)) == 0) {
			DEBUG("%s", "timed out\n");
			continue;
		}
		pktval.mv_size = len;
		memcpy(pkt2, pktbuf, len);
		decode(&pktval);
		if (pktbuf[1] != MSG_PUNCH)
			continue;
		DEBUG("got MSG_PUNCH from %s:%d\n", inet_ntoa(icamera->sin_addr), ntohs(icamera->sin_port));
		if (sendto(udp, pkt2, len, 0, &camera, slen) != len) {
			perror("udp send MSG_PUNCH");
			exit(1);
		}
	}


	return 0;
}

char hinbuf[1024];

char http200[] =
	"HTTP/1.0 200 OK\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: 77\r\n"
	"\r\n"
	"<!DOCTYPE html>\r\n"
	"<html><head></head><body><img src=\"/v.mjpg\"></body></html>\r\n";

int startup()
{
	struct timeval tv;
	struct sockaddr clientip;
	socklen_t clientiplen;
	int len;
	char inbuf[1024];

	if ((http = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("http socket");
		exit(1);
	}
	ilocal->sin_family = AF_INET;
	ilocal->sin_port = htons(HTTP_PORT);
	ilocal->sin_addr.s_addr = INADDR_ANY;
	if (bind(http, &local, sizeof(*ilocal)) < 0) {
		perror("http bind");
		exit(1);
	}
	if (listen(http, 1) < 0) {
		perror("http listen");
		exit(1);
	}
again:
	client = accept(http, &clientip, &clientiplen);
	while (1) {
		len = read(client, inbuf, sizeof(inbuf));
		if (len < 7) {
			close(client);
			goto again;
		}
		if (strncasecmp(inbuf, "GET ", 4)) {
			close(client);
			goto again;
		}
		if (!strncmp(inbuf+4, "/v.mjpg ", 8)) {
			sendvideo = 1;
		} else
		if (!strncmp(inbuf+4, "/ ", 2)) {
			write(client, http200, sizeof(http200));
			connect_camera(&local, &bcast);
			continue;
		}
	}
}

static void usage(char *prog)
{
	fprintf(stderr, "usage: %s [-b <broadcast addr>] [-l <local addr>]\n", prog);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int i;

	ibcast->sin_family = AF_INET;
	ibcast->sin_addr.s_addr = INADDR_BROADCAST;
	ilocal->sin_family = AF_INET;

	while ((i = getopt(argc, argv, "b:l:")) != EOF) {
		switch(i) {
		case 'b':
			if (!inet_aton(optarg, &ibcast->sin_addr)) {
				fprintf(stderr, "invalid broadcast address %s\n", optarg);
				exit(1);
			}
			break;
		case 'l':
			if (!inet_aton(optarg, &ilocal->sin_addr)) {
				fprintf(stderr, "invalid local address %s\n", optarg);
				exit(1);
			}
		default:
			usage(argv[0]);
		}
	}
	if (optind != argc-1)
		usage(argv[0]);
	startup();
}
