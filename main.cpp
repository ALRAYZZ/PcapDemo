#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <string>

using namespace std;

void print_error_and_exit(const string& msg, const char* err = nullptr)
{
	cerr << msg;
	if (err) cerr << ": " << err;
	cerr << endl;
	exit(1);
}

void packet_handler(u_char* user, const pcap_pkthdr* h, const u_char* bytes)
{
	// header-> ts is timeval struct (seconds + microseconds)
	// Convert to readable time format
	time_t secs = h->ts.tv_sec;
	tm local_tm;
	localtime_s(&local_tm, &secs);
	char timebuf[64];
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &local_tm);

	// Microseconds part
	long usec = h->ts.tv_usec;

	cout << "[" << timebuf << "." << setw(6) << setfill('0') << usec << "] "
		 << "Captured Length: " << h->caplen << " bytes, "
		<< "Original Length: " << h->len << " bytes" << endl;
	// dont print packet bytes for readability
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

	// Start capture loop
	if (pcap_loop(handle, 0, packet_handler, nullptr) < 0)
	{
		pcap_close(handle);
		print_error_and_exit("Error during packet capture", pcap_geterr(handle));
	}

	pcap_close(handle);
	return 0;
}