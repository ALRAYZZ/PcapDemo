#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>

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


	// 3 Open live capture (promiscuous mode, 65536 bytes, 1000ms timeout)
	pcap_t* handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	if (!handle)
	{
		pcap_freealldevs(alldevs);
		print_error_and_exit("Could not open device", errbuf);
	}

	// Show link layer type
	int linktype = pcap_datalink(handle);
	cout << "Link layer type: " << linktype << "\n";

	// 4 Start capture loop (0 = forever). Ctrl+C to stop.
	cout << "Starting packet capture... Press Ctrl+C to stop.\n";
	pcap_freealldevs(alldevs);
	if (pcap_loop(handle, 0, packet_handler, nullptr) < 0)
	{
		pcap_close(handle);
		print_error_and_exit("Error during packet capture", pcap_geterr(handle));
	}

	pcap_close(handle);
	return 0;
}