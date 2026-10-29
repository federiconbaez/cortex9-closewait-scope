// Carga de conexiones en loopback para el experimento C del pre-registro.
// Uso: connload <conn_por_s> <segundos> <hilos_cliente>
// El servidor cierra primero (shutdown SHUT_WR): cada conexión del cliente pasa por
// CLOSE_WAIT y después cierra con RST (SO_LINGER 0).
// Imprime JSON con conexiones logradas y CPU (usuario+sistema) del proceso.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define NDST 200  // 200 destinos 127.0.0.x: evita colisiones de 4-tupla con TIME_WAIT a 10k/s
static int lfd;
static int port;
static double rate_per_thread, seconds;
static atomic_long done, errs;
static atomic_int stop;

static double now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}

static void *server(void *a) {
  (void)a;
  while (!atomic_load(&stop)) {
    int c = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
    if (c < 0) continue;
    // FIN al cliente (pasa a CLOSE_WAIT); el cliente responde con RST y ninguno de
    // los dos lados queda en TIME_WAIT (a 10k/s el TIME_WAIT agota la tabla de puertos).
    shutdown(c, SHUT_WR);
    char b[16];
    while (read(c, b, sizeof b) > 0) {}
    close(c);
  }
  return NULL;
}

static void *client(void *a) {
  long id = (long)a;
  double t0 = now(), next = t0;
  long i = 0;
  char buf[64];
  while (now() - t0 < seconds) {
    struct sockaddr_in d = {.sin_family = AF_INET, .sin_port = htons(port)};
    d.sin_addr.s_addr = htonl(0x7f000001 + (uint32_t)((id + i) % NDST));
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0 || connect(s, (struct sockaddr *)&d, sizeof d) < 0) {
      atomic_fetch_add(&errs, 1);
      if (s >= 0) close(s);
    } else {
      while (read(s, buf, sizeof buf) > 0) {}
      struct linger lg = {1, 0};
      setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
      close(s);
      atomic_fetch_add(&done, 1);
    }
    i++;
    next += 1.0 / rate_per_thread;
    double w = next - now();
    if (w > 0) {
      struct timespec ts = {(time_t)w, (long)((w - (time_t)w) * 1e9)};
      nanosleep(&ts, NULL);
    }
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc != 4) { fprintf(stderr, "uso: connload rate seconds threads\n"); return 2; }
  double rate = atof(argv[1]);
  seconds = atof(argv[2]);
  int nt = atoi(argv[3]);
  rate_per_thread = rate / nt;
  lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  int one = 1;
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY)};
  if (bind(lfd, (struct sockaddr *)&a, sizeof a) < 0 || listen(lfd, 4096) < 0) { perror("bind"); return 1; }
  socklen_t l = sizeof a;
  getsockname(lfd, (struct sockaddr *)&a, &l);
  port = ntohs(a.sin_port);
  pthread_t sv[4], *cl = calloc(nt, sizeof *cl);
  for (int i = 0; i < 4; i++) pthread_create(&sv[i], NULL, server, NULL);
  double t0 = now();
  for (long i = 0; i < nt; i++) pthread_create(&cl[i], NULL, client, (void *)i);
  for (int i = 0; i < nt; i++) pthread_join(cl[i], NULL);
  double wall = now() - t0;
  atomic_store(&stop, 1);
  shutdown(lfd, SHUT_RDWR);
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  double cpu = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6 + ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
  printf("{\"conns\": %ld, \"errors\": %ld, \"wall_s\": %.3f, \"conn_per_s\": %.1f, \"cpu_s\": %.3f}\n",
         atomic_load(&done), atomic_load(&errs), wall, atomic_load(&done) / wall, cpu);
  fflush(stdout);
  _exit(0);
}
