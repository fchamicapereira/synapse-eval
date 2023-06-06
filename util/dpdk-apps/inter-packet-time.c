#include <assert.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>

#define time_t int64_t

time_t current_time(void) {
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return tp.tv_sec * 1000000000ul + tp.tv_nsec;
}

bool nf_init(void);
int nf_process(uint16_t device, uint8_t *buffer, uint16_t packet_length,
               time_t now);

#define BATCH_SIZE 32

static const uint16_t RX_QUEUE_SIZE = 1024;
static const uint16_t TX_QUEUE_SIZE = 1024;

// Buffer count for mempools
static const unsigned MEMPOOL_BUFFER_COUNT = 2048;

// Initializes the given device using the given memory pool
static int nf_init_device(uint16_t device, struct rte_mempool *mbuf_pool) {
  int retval;

  // device_conf passed to rte_eth_dev_configure cannot be NULL
  struct rte_eth_conf device_conf = {0};
  // device_conf.rxmode.hw_strip_crc = 1;

  // Configure the device (1, 1 == number of RX/TX queues)
  retval = rte_eth_dev_configure(device, 1, 1, &device_conf);
  if (retval != 0) {
    return retval;
  }

  // Allocate and set up a TX queue (NULL == default config)
  retval = rte_eth_tx_queue_setup(device, 0, TX_QUEUE_SIZE,
                                  rte_eth_dev_socket_id(device), NULL);
  if (retval != 0) {
    return retval;
  }

  // Allocate and set up RX queues (NULL == default config)
  retval = rte_eth_rx_queue_setup(
      device, 0, RX_QUEUE_SIZE, rte_eth_dev_socket_id(device), NULL, mbuf_pool);
  if (retval != 0) {
    return retval;
  }

  // Start the device
  retval = rte_eth_dev_start(device);
  if (retval != 0) {
    return retval;
  }

  // Enable RX in promiscuous mode, just in case
  rte_eth_promiscuous_enable(device);
  if (rte_eth_promiscuous_get(device) != 1) {
    return retval;
  }

  return 0;
}

// Main worker method (for now used on a single thread...)
static void worker_main(void) {
  if (!nf_init()) {
    rte_exit(EXIT_FAILURE, "Error initializing NF");
  }

  printf("Core %u forwarding packets.\n", rte_lcore_id());

  if (rte_eth_dev_count_avail() != 2) {
    printf(
        "We assume there will be exactly 2 devices for our simple batching "
        "implementation.\n");
    exit(1);
  }
  printf("Running with batches, this code is unverified!\n");

  while (1) {
    unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();
    for (uint16_t VIGOR_DEVICE = 0; VIGOR_DEVICE < VIGOR_DEVICES_COUNT;
         VIGOR_DEVICE++) {
      struct rte_mbuf *mbufs[BATCH_SIZE];
      uint16_t rx_count = rte_eth_rx_burst(VIGOR_DEVICE, 0, mbufs, BATCH_SIZE);

      struct rte_mbuf *mbufs_to_send[BATCH_SIZE];
      uint16_t tx_count = 0;
      for (uint16_t n = 0; n < rx_count; n++) {
        uint8_t *data = rte_pktmbuf_mtod(mbufs[n], uint8_t *);
        time_t VIGOR_NOW = current_time();
        uint16_t dst_device =
            nf_process(mbufs[n]->port, data, mbufs[n]->pkt_len, VIGOR_NOW);

        if (dst_device == VIGOR_DEVICE) {
          rte_pktmbuf_free(mbufs[n]);
        } else {  // includes flood when 2 devices, which is equivalent to just
                  // a
                  // send
          mbufs_to_send[tx_count] = mbufs[n];
          tx_count++;
        }
      }

      uint16_t sent_count =
          rte_eth_tx_burst(1 - VIGOR_DEVICE, 0, mbufs_to_send, tx_count);
      for (uint16_t n = sent_count; n < tx_count; n++) {
        rte_pktmbuf_free(mbufs[n]);  // should not happen, but we're in the
                                     // unverified case anyway
      }
    }
  }
}

uint64_t counter;
uint64_t last_time;
uint64_t sum_dt;
uint64_t max_dt;
uint64_t min_dt;

static void catch_function(int signo) {
  uint64_t dt_avg = (uint64_t)(sum_dt / counter);

  printf("\n");
  printf("counter: %ld\n", counter);
  printf("avg dt:  %ld ns\n", dt_avg);
  printf("max dt:  %ld ns\n", max_dt);
  printf("min dt:  %ld ns\n", min_dt);

  exit(0);
}

// Entry point
int main(int argc, char **argv) {
  if (signal(SIGINT, catch_function) == SIG_ERR) {
    rte_exit(EXIT_FAILURE, "An error occurred while setting a signal handler.");
  }

  // Initialize the DPDK Environment Abstraction Layer (EAL)
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization, ret=%d\n", ret);
  }
  argc -= ret;
  argv += ret;

  // Create a memory pool
  unsigned nb_devices = rte_eth_dev_count_avail();
  struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
      "MEMPOOL",                          // name
      MEMPOOL_BUFFER_COUNT * nb_devices,  // #elements
      0,  // cache size (per-core, not useful in a single-threaded app)
      0,  // application private area size
      RTE_MBUF_DEFAULT_BUF_SIZE,  // data buffer size
      rte_socket_id()             // socket ID
  );
  if (mbuf_pool == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot create pool: %s\n", rte_strerror(rte_errno));
  }

  // Initialize all devices
  for (uint16_t device = 0; device < nb_devices; device++) {
    ret = nf_init_device(device, mbuf_pool);
    if (ret == 0) {
      printf("Initialized device %" PRIu16 ".\n", device);
    } else {
      rte_exit(EXIT_FAILURE, "Cannot init device %" PRIu16 ": %d", device, ret);
    }
  }

  // Run!
  worker_main();

  return 0;
}

bool nf_init() {
  counter = 0;
  last_time = 0;
  sum_dt = 0;
  max_dt = 0;
  min_dt = 0;
  return 1;
}

int nf_process(uint16_t device, uint8_t *packet, uint16_t packet_length,
               int64_t now) {
  if (likely(counter > 0)) {
    uint64_t dt = now - last_time;

    sum_dt += dt;

    if (dt > max_dt) {
      max_dt = dt;
    }

    if (min_dt == 0 || dt < min_dt) {
      min_dt = dt;
    }
  }

  last_time = now;
  counter++;

  // test000003
  if (device) {
    return 0;
  }

  // test000005
  else {
    return 1;
  }  // !device
}
