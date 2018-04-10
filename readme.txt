Project Name: Secure protocol analysis with Wireshark protocol analyzer
 
1.	Run Wireshark at the background and ping or visit different URL’s. All network traffic will be monitored by Wireshark. 
2. Save the file in Wireshark/tcpdump i.e. *.pcap format. 
3. The algorithm designed performs below actions, 
	i. Detect the interface such as ‘eth1’ and its IP Address and Network Mask. The format is as below, 
		Interface: eth1 
		IP Address of Interface: 10.0.2.0 
		Network Mask of Interface: 255.255.255.0 
	ii. Prompt user to enter the full path of pcap extracted file from step 1, 
		Enter the input file: /home/shivanshu/from_host/test1.pcap 
	iii. Prompt user to enter the full path of output file, where detailed extracted data would be stored as below, 
		Enter the output file: /home/shivanshu/from_host/test1_output.txt 
		In case file does not exist in defined path, the program would create new file with same filename and write data. Otherwise it would overwrite the data. 
	iv. The input file is opened using pcap_open_offline(), which is a subroutine that opens a previously saved packet capture data file. 
	v. Whereas ‘outFile’ is the pointer to store all data in output file. 
	vi. We further sniff all the packets fetched from input file using ‘pcap_next_ex’, this	 subroutine reads the next packet and returns a success/failure indication. 
	vii. We print Packet Count, Packet Size, and Timestamp when packet fetched, Source/Destination Port Number, Source/Destination IP Address, Sequence Number and Acknowledgement Number. 
	viii. Then we extract payload from the packet using offset value. This value if calculated from TCP header information. 
	ix. The two functions defined perform below tasks, 
		a. void display_payload(const u_char *payload, int len) : Calculate the offset using header length information and passes the offset value to below function. 
		b. void display_ascii_line(ch, line_len, offset) : This function traverses through whole payload only prints the ASCII values and we skip hexadecimal and offset information. 
	x. The payload prints below format, 
		Payload Size 125 bytes: 
		* HTTP/1.1..Host:239.255.255.250:1900..ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1..Man:"ssdp:discover"..MX:3.....
