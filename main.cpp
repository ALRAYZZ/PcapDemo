#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <string>
#include <winsock2.h>
#include <unordered_map>
#include <chrono>
#include <iomanip>

using namespace std;

// Ensures no padding in structures
#pragma pack(push, 1)
struct EthHeader
{
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t ethertype; // network byte order
};

struct IPv4Header
{
	uint8_t ver_ihl; // Version (4 bits) + Internet header length (4 bits)
	uint8_t dscp_ecn; // DSCP (6 bits) + ECN (2 bits)
	uint16_t total_length; // Total length
	uint16_t identification; // Identification
	uint16_t flags_frag; // Flags (3 bits) + Fragment offset (13 bits)
	uint8_t ttl; // Time to live
	uint8_t protocol; // Protocol
	uint16_t hdr_checksum; // Header checksum
	uint32_t src_addr; // Source address
	uint32_t dst_addr; // Destination address
};

struct TCPHeader
{
	uint16_t src_port; // Source port
	uint16_t dst_port; // Destination port
	uint32_t seq_num; // Sequence number
	uint32_t ack_num; // Acknowledgment number
	uint8_t data_offset; // Data offset (4 bits) + Reserved (4 bits)
	uint8_t flags; // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
	uint16_t window; // Window size
	uint16_t checksum; // Checksum
	uint16_t urgent_ptr; // Urgent pointer
};

struct UDPHeader
{
	uint16_t src_port; // Source port
	uint16_t dst_port; // Destination port
	uint16_t length; // Length
	uint16_t checksum; // Checksum (digital fingerprint to check if packet data is intact)
};
#pragma pack(pop)

struct FlowKey
{
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;

	bool operator==(const FlowKey& other) const
	{
		return src_ip == other.src_ip &&
			dst_ip == other.dst_ip &&
			src_port == other.src_port &&
			dst_port == other.dst_port &&
			protocol == other.protocol;
	}
};

struct FlowKeyHash
{
	size_t operator()(const FlowKey& key) const
	{
		return hash<uint32_t>()(key.src_ip) ^
			hash<uint32_t>()(key.dst_ip) ^
			hash<uint16_t>()(key.src_port) ^
			hash<uint16_t>()(key.dst_port) ^
			hash<uint8_t>()(key.protocol);
	}
};

struct FlowStats
{
	uint64_t packet_count = 0;
	uint64_t byte_count = 0;
	timeval last_ts{}; // timestamp of last packet
};

unordered_map<FlowKey, FlowStats, FlowKeyHash> flow_table;
bool show_all_packets = false; // show every packet if true
double delta_threshold_ms = 0.0; // threshold for inter-arrival time display
uint16_t watch_port = 0; // port to watch for special logging

auto last_summary_time = chrono::steady_clock::now();
const int summary_interval_sec = 2; // print summary every X seconds

// helper: format MAC
// Input: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
// Output: "AA:BB:CC:DD:EE:FF" 
string mac_to_string(const uint8_t mac[6])
{
	char buf[32];
	sprintf_s(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return string(buf);
}

// helper: format IPv4
// Input: 0x7F000001 (network byte order)  -- represents 127.0.0.1
// Output: "127.0.0.1"
string ipv4_to_string(uint32_t addr_be)
{
	uint32_t a = ntohl(addr_be);
	uint8_t b1 = (a >> 24) & 0xFF;
	uint8_t b2 = (a >> 16) & 0xFF;
	uint8_t b3 = (a >> 8) & 0xFF;
	uint8_t b4 = a & 0xFF;
	char buf[32];
	sprintf_s(buf, sizeof(buf), "%u.%u.%u.%u", b1, b2, b3, b4);
	return string(buf);
}

// print timestamp helper
string ts_to_string(const pcap_pkthdr* h)
{
	time_t secs = h->ts.tv_sec;
	tm local_tm;
	localtime_s(&local_tm, &secs);
	char timebuf[64];
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &local_tm);
	char out[128];
	sprintf_s(out, sizeof(out), "%s.%06ld", timebuf, (unsigned)h->ts.tv_usec);
	return string(out);
}

void print_error_and_exit(const string& msg, const char* err = nullptr)
{
	cerr << msg;
	if (err) cerr << ": " << err;
	cerr << endl;
	exit(1);
}

// Input: Raw binary data from network
// Output: Parsed and printed packet info human readable
void packet_handler(u_char* user, const pcap_pkthdr* h, const u_char* bytes)
{
	// Basic checks
	if (!h || !bytes) return;

	size_t caplen = h->caplen; // captured length
	if (caplen < sizeof(EthHeader))
	{
		cout << "[" << ts_to_string(h) << "] Packet too short for Ethernet header\n";
		return;
	}

	const EthHeader* eth = reinterpret_cast<const EthHeader*>(bytes);
	uint16_t ethertype = ntohs(eth->ethertype); // ntohs/ntohl: convert network byte order to host byte order.

	string src_mac = mac_to_string(eth->src);
	string dst_mac = mac_to_string(eth->dst);

	// Start output line with timestamp + linkinfo
	cout << "[" << ts_to_string(h) << "]" << src_mac << " -> " << dst_mac << " ethertype=0x" << hex << ethertype << dec;

	// Move pointer to L3
	const u_char* l3 = bytes + sizeof(EthHeader);
	size_t l3_len = (caplen >= sizeof(EthHeader)) ? (caplen - sizeof(EthHeader)) : 0;

	if (ethertype == 0x0800 /* IPv4 */)
	{
		if (l3_len < sizeof(IPv4Header))
		{
			cout << " | truncated IPv4\n";
			return;
		}

		const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(l3);

		int ihl = (ip->ver_ihl & 0x0F); // Internet Header Length in 32-bit words
		size_t ip_header_bytes = ihl * 4;
		if (ip_header_bytes < 20) ip_header_bytes = 20; // minimum size

		if (l3_len < ip_header_bytes)
		{
			cout << " | truncated IPv4 header\n";
			return;
		}

		uint16_t total_length = ntohs(ip->total_length);
		string src_ip = ipv4_to_string(ip->src_addr);
		string dst_ip = ipv4_to_string(ip->dst_addr);
		uint8_t protocol = ip->protocol;

		cout << " | IPv4 " << src_ip << " -> " << dst_ip << " protocol=" << (unsigned)protocol << " tot_len=" << total_length;

		// point to l4 (start of transport header)
		const u_char* l4 = l3 + ip_header_bytes;
		size_t l4_len = (l3_len >= ip_header_bytes) ? (l3_len - ip_header_bytes) : 0;

		if (protocol == 6 /* TCP */)
		{
			if (l4_len < sizeof(TCPHeader))
			{
				cout << " | truncated TCP\n";
				return;
			}

			const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(l4);

			uint16_t src_port = ntohs(tcp->src_port);
			uint16_t dst_port = ntohs(tcp->dst_port);
			uint32_t seq = ntohl(tcp->seq_num);
			uint32_t ack = ntohl(tcp->ack_num);
			int data_offset = (tcp->data_offset >> 4) & 0x0F; // in 32-bit words
			size_t tcp_header_bytes = data_offset * 4;
			if (tcp_header_bytes < 20) tcp_header_bytes = 20; // minimum size

			// FLOW TRACKING
			FlowKey key{ ip->src_addr, ip->dst_addr, tcp->src_port, tcp->dst_port, protocol };
			auto& stats = flow_table[key];

			stats.packet_count++;
			stats.byte_count += h->len;

			double delta_ms = 0.0;
			if (stats.packet_count > 1)
			{
				delta_ms = (h->ts.tv_sec - stats.last_ts.tv_sec) * 1000.0 +
					(h->ts.tv_usec - stats.last_ts.tv_usec) / 1000.0;
			}
			stats.last_ts = h->ts;

			// Print inter-arrival info
			bool should_print = show_all_packets;
			
			if (delta_ms > delta_threshold_ms)
			{
				should_print = true;
			}
			if (watch_port && (src_port == watch_port || dst_port == watch_port))
			{
				should_print = true;
			}

			if (should_print)
			{
				cout << " | flow_pkt=" << stats.packet_count
					<< " flow_bytes=" << stats.byte_count;

				if (stats.packet_count > 1)
				{
					cout << " Δt=" << delta_ms << " ms";
				}
				cout << "\n";
			}


			// flags
			uint8_t flags = tcp->flags;
			bool f_fin = flags & 0x01;
			bool f_syn = flags & 0x02;
			bool f_rst = flags & 0x04;
			bool f_psh = flags & 0x08;
			bool f_ack = flags & 0x10;
			bool f_urg = flags & 0x20;
			bool f_ece = flags & 0x40;
			bool f_cwr = flags & 0x80;

			cout << " | TCP " << src_port << " -> " << dst_port
				<< " seq=" << seq << " ack=" << ack
				<< " flags=["
				<< (f_fin ? "FIN " : "")
				<< (f_syn ? "SYN " : "")
				<< (f_rst ? "RST " : "")
				<< (f_psh ? "PSH " : "")
				<< (f_ack ? "ACK " : "")
				<< (f_urg ? "URG " : "")
				<< (f_ece ? "ECE " : "")
				<< (f_cwr ? "CWR " : "")
				<< "]";

			// application palyoad length (from IP total_length - IP header - TCP header)
			int payload_len = (int)total_length - (int)ip_header_bytes - (int)tcp_header_bytes;
			if (payload_len < 0) payload_len = 0;
			cout << " payload_len=" << payload_len << "\n";
		}
		else if (protocol == 17 /* UDP */)
		{
			if (l4_len < sizeof(UDPHeader))
			{
				cout << " | truncated UDP\n";
				return;
			}
			const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(l4);
			uint16_t src_port = ntohs(udp->src_port);
			uint16_t dst_port = ntohs(udp->dst_port);
			uint16_t udplen = ntohs(udp->length); // UDP length includes header

			// FLOW TRACKING
			FlowKey key{ ip->src_addr, ip->dst_addr, udp->src_port, udp->dst_port, protocol };
			auto& stats = flow_table[key];

			stats.packet_count++;
			stats.byte_count += h->len;

			double delta_ms = 0.0;
			if (stats.packet_count > 1)
			{
				delta_ms = (h->ts.tv_sec - stats.last_ts.tv_sec) * 1000.0 +
					(h->ts.tv_usec - stats.last_ts.tv_usec) / 1000.0;
			}
			stats.last_ts = h->ts;
			
			// Print inter-arrival info
			bool should_print = show_all_packets;

			if (delta_ms > delta_threshold_ms)
			{
				should_print = true;
			}
			if (watch_port && (src_port == watch_port || dst_port == watch_port))
			{
				should_print = true;
			}

			if (should_print)
			{
				cout << " | flow_pkt=" << stats.packet_count
					<< " flow_bytes=" << stats.byte_count;

				if (stats.packet_count > 1)
				{
					cout << " Δt=" << delta_ms << " ms";
				}
				cout << "\n";
			}
		}
		else
		{
			cout << " | L4 protocol " << unsigned(protocol) << " not parsed\n";
		}
	}
	else if (ethertype == 0x86DD /* IPv6 */)
	{
		cout << " | IPv6 packet (parsing not implemented)\n";
	}
	else
	{
		cout << " | Non-IP packet\n";
	}

	// Periodic summary every few seconds
	auto now = chrono::steady_clock::now();
	auto elapsed = chrono::duration_cast<chrono::seconds>(now - last_summary_time).count();

	if (elapsed >= summary_interval_sec)
	{
		system("cls"); // clear console (Windows-specific)
		cout << "[Flow Summary @ " << ts_to_string(h) << "]\n";

		cout << left << setw(20) << "SrcIP:Port"
			<< setw(25) << "DstIP:Port"
			<< setw(6) << "Proto"
			<< setw(8) << "Pkts"
			<< setw(10) << "Bytes"
			<< setw(10) << "Last Δt(ms)"
			<< "\n-------------------------------------------------------------------------\n";

		for (const auto& kv : flow_table)
		{
			const FlowKey& key = kv.first;
			const FlowStats& stats = kv.second;

			string src = ipv4_to_string(key.src_ip) + ":" + to_string(ntohs(key.src_port));
			string dst = ipv4_to_string(key.dst_ip) + ":" + to_string(ntohs(key.dst_port));
			string proto = (key.protocol == 6) ? "TCP" : (key.protocol == 17) ? "UDP" : to_string(key.protocol);

			cout << left << setw(20) << src
				<< setw(25) << dst
				<< setw(6) << proto
				<< setw(8) << stats.packet_count
				<< setw(10) << stats.byte_count
				<< setw(10) << fixed << setprecision(1) << 0.0
				<< "\n";
		}

		cout.flush();
		last_summary_time = now;
	}

}

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];

	// 1 Find all devices
	pcap_if_t* alldevs = nullptr;
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		print_error_and_exit("Error finding devices", errbuf);
	}

	if (!alldevs)
	{
		print_error_and_exit("No devices found");
	}

	// List all devices
	cout << "Available devices:\n";
	int idx = 0;
	for (pcap_if_t* d = alldevs; d; d = d->next)
	{
		cout << ++idx << ": " << (d->name ? d->name : "No name");
		if (d->description) cout << " - " << d->description;
		cout << "\n";
	}

	cout << "\nSelect interface number to capture (number): ";
	int choice = 0;
	cin >> choice;

	if (choice < 1 || choice > idx)
	{
		pcap_freealldevs(alldevs);
		print_error_and_exit("Invalid interface number");
	}

	// Find chosen device
	pcap_if_t* dev = alldevs;
	for (int i = 1; i < choice; ++i)
	{
		dev = dev->next;
	}
	cout << "\nOpening device: " << dev->name << "\n";


	// Open live capture on selected device (promiscuous mode, 65536 bytes, 1000ms timeout)
	pcap_t* handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	if (!handle)
	{
		pcap_freealldevs(alldevs);
		print_error_and_exit("Could not open device", errbuf);
	}
	pcap_freealldevs(alldevs);

	// Compile and set filter
	// Filters: "tcp", "udp", "icmp", "port 80", etc.
	cout << "Enter a BPF filter (or press enter for none): ";
	cin.ignore(); // clear newline from previous input

	// Get filter string
	string filter_str;
	getline(cin, filter_str);

	if (!filter_str.empty())
	{
		bpf_program fp;
		if (pcap_compile(handle, &fp, filter_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1)
		{
			cerr << "Warning: Could not parse filter. Capturing all packets.\n";
		}
		else
		{
			if (pcap_setfilter(handle, &fp) == -1)
			{
				cerr << "Warning: Could not install filter. Capturing all packets.\n";
			}
			pcap_freecode(&fp);
		}
	}

	cout << "Starting packet capture... Press Ctrl+C to stop.\n";

	// Main loop receiving packets and calling packet_handler to print info
	if (pcap_loop(handle, 0, packet_handler, nullptr) < 0)
	{
		pcap_close(handle);
		print_error_and_exit("Error during packet capture", pcap_geterr(handle));
	}

	pcap_close(handle);
	return 0;
}