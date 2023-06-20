#include <arpa/inet.h>
#include <assert.h>
#include <bits/stdc++.h>
#include <math.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "util.h"

#define SIZE_DIST_DUMP ".sizes.tsv"

struct pkt_hdr_t {
  ether_header eth_hdr;
  iphdr ip_hdr;
  udphdr udp_hdr;
} __attribute__((packed));

struct flow_t {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;

  flow_t() : src_ip(0), dst_ip(0), src_port(0), dst_port(0) {}

  flow_t(const flow_t &flow)
      : src_ip(flow.src_ip),
        dst_ip(flow.dst_ip),
        src_port(flow.src_port),
        dst_port(flow.dst_port) {}

  flow_t(uint32_t _src_ip, uint32_t _dst_ip, uint16_t _src_port,
         uint16_t _dst_port)
      : src_ip(_src_ip),
        dst_ip(_dst_ip),
        src_port(_src_port),
        dst_port(_dst_port) {}

  bool operator==(const flow_t &other) const {
    return other.src_ip == src_ip && dst_ip == other.dst_ip &&
           src_port == other.src_port && dst_port == other.dst_port;
  }

  struct flow_hash_t {
    std::size_t operator()(const flow_t &flow) const {
      return std::hash<in_addr_t>()(flow.src_ip) ^
             std::hash<in_addr_t>()(flow.dst_ip) ^
             std::hash<uint16_t>()(flow.src_port) ^
             std::hash<uint16_t>()(flow.dst_port);
    }
  };
};

struct pkt_data_t {
  std::unordered_set<flow_t, flow_t::flow_hash_t> unique_flows;
  std::unordered_set<uint32_t> unique_src_ips;
  std::unordered_set<uint32_t> unique_dst_ips;
  std::unordered_map<flow_t, unsigned, flow_t::flow_hash_t> flow_counter;
  std::vector<flow_t> flows;
  std::vector<uint16_t> pkt_sizes;

  uint64_t total_sz;
  uint64_t n_pkts;
  time_ns_t time;

  pkt_data_t() : total_sz(0), n_pkts(0), time(0) {}

  void add(const pkt_hdr_t *pkt_hdr, uint16_t sz) {
    auto flow = flow_t(pkt_hdr->ip_hdr.saddr, pkt_hdr->ip_hdr.daddr,
                       pkt_hdr->udp_hdr.uh_sport, pkt_hdr->udp_hdr.uh_dport);
    if (unique_flows.count(flow) == 0) {
      unique_flows.insert(flow);
    }

    if (unique_src_ips.count(flow.src_ip) == 0) {
      unique_src_ips.insert(flow.src_ip);
    }

    if (unique_dst_ips.count(flow.dst_ip) == 0) {
      unique_dst_ips.insert(flow.dst_ip);
    }

    flows.push_back(flow);
    flow_counter[flow]++;
    pkt_sizes.push_back(sz);
    total_sz += sz;
    n_pkts++;
    time +=
        (time_ns_t)(byte_to_bit(sz) / (double)(MAX_THROUGHPUT_GIGABIT_PER_SEC));
  }

  std::vector<flow_t> get_elephants() const {
    std::vector<std::pair<flow_t, unsigned>> flow_instance_counter;

    flow_instance_counter.assign(flow_counter.begin(), flow_counter.end());

    std::sort(
        flow_instance_counter.begin(), flow_instance_counter.end(),
        [](std::pair<flow_t, unsigned> lhs, std::pair<flow_t, unsigned> rhs) {
          return lhs.second > rhs.second;
        });

    std::vector<flow_t> elephants;
    auto counter = 0;
    for (auto flow_instances : flow_instance_counter) {
      auto flow = flow_instances.first;
      auto instances = flow_instances.second;

      elephants.push_back(flow);
      counter += instances;

      auto ratio = (double)counter / (double)n_pkts;

      if (ratio >= 0.8) {
        break;
      }
    }

    return elephants;
  }
};

pkt_data_t get_pkts(const char *pcap_fname) {
  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_t *pcap = pcap_open_offline(pcap_fname, errbuff);

  if (pcap == nullptr) {
    std::cerr << errbuff << "\n";
    exit(1);
  }

  pcap_pkthdr *header;
  const u_char *data;

  pkt_data_t pkt_data;

  while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {
    auto pkt_hdr = reinterpret_cast<const pkt_hdr_t *>(data);
    pkt_data.add(pkt_hdr, header->len);
    if (pkt_data.n_pkts % 10000 == 0) {
      std::cerr << ".";
    }
  }
  std::cerr << "done\n";

  return pkt_data;
}

uint16_t avg(const std::vector<uint16_t> &values) {
  uint64_t res = 0;
  for (const auto &v : values) {
    res += v;
  }
  return (uint16_t)(res / values.size());
}

uint16_t std_dev(const std::vector<uint16_t> &values, uint16_t avg) {
  uint64_t res = 0;
  for (const auto &v : values) {
    res += (v - avg) * (v - avg);
  }
  return (uint16_t)(sqrt((double)res / values.size()));
}

void dump_sizes(const std::vector<uint16_t> &sizes) {
  std::unordered_map<uint16_t, uint64_t> sizes_counter;

  for (auto s : sizes) {
    sizes_counter[s]++;
  }

  std::ofstream out;
  out.open(SIZE_DIST_DUMP, std::ios::out);
  for (auto size_counter = sizes_counter.begin();
       size_counter != sizes_counter.end(); size_counter++) {
    auto size = size_counter->first;
    auto counter = size_counter->second;

    out << size << "\t" << counter << "\n";
  }
  out.close();
}

void get_stats(const pkt_data_t &pkt_data) {
  auto pkt_size_avg = avg(pkt_data.pkt_sizes);
  auto pkt_size_std_dev = std_dev(pkt_data.pkt_sizes, pkt_size_avg);
  auto elephants = pkt_data.get_elephants();

  printf("Packets      %s\n", fmt(pkt_data.flows.size()).c_str());
  printf("Flows        %s\n", fmt(pkt_data.unique_flows.size()).c_str());
  printf("Sources      %s\n", fmt(pkt_data.unique_src_ips.size()).c_str());
  printf("Destinations %s\n", fmt(pkt_data.unique_dst_ips.size()).c_str());
  printf("Elephants    %s (%.2lf%% flows => >80%% traffic)\n",
         fmt(elephants.size()).c_str(),
         100.0 * elephants.size() / pkt_data.unique_flows.size());
  printf("Size         %u +- %u B\n", pkt_size_avg, pkt_size_std_dev);
  printf("Replay time  %s ns\n", fmt(pkt_data.time).c_str());

  dump_sizes(pkt_data.pkt_sizes);
}

int main(int argc, char *argv[]) {
  if (argc < 2 || std::string(argv[1]) == "-h" ||
      std::string(argv[1]) == "--help") {
    printf("Usage: %s [input pcap] \n", argv[0]);
    return 1;
  }

  auto input = argv[1];
  auto pkt_data = get_pkts(input);

  get_stats(pkt_data);

  return 0;
}
