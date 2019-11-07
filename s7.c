#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <stdlib.h>


void s7_analysis(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *packet, const int total_headers_size);
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


int main(int argc, char *argv[]) {
	char *fname = argv[1];
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline(fname, error_buffer);
    // Store
    pcap_dumper_t *dumpfile;
    dumpfile = pcap_dump_open(handle, argv[2]);
    if(dumpfile==NULL)
    {
        fprintf(stderr,"\nError opening output file\n");
        return -1;
    }

    pcap_loop(handle, 0, my_packet_handler, (unsigned char *)dumpfile);    
    return 0;
}

void my_packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;
    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;
    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        return;
    }
    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;   
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    s7_analysis(dumpfile, header, packet, total_headers_size);
}


void setup_comm_packet(const u_char *packet, const int param_offset){
    int j;
    printf("Function code:\tSetup configuration\n");
    char* strarray[] = {"Function code\t", "Reserved\t", "Max AMQ Caller i", "Max AMQ Caller ii", "Max AMQ Callee i", "Max AMQ Callee ii", "PDU Length i\t", "PDU Length ii\t"};
    for(j=0;j<8;j++) {
        printf("%s:\t0x%02X \n", strarray[j], packet[param_offset+j]);
    }
}


void read_var_packet_job(const u_char *packet, const int param_offset, const int s7_param_len){
    int j, k;
    printf("Function code:\tRead variable\n");
    char* strarray[] = {"Spec Type:", "Length:\t", "Syntax ID:", "Variable Type:", "Count: ", "\t", "DB Number:", "\t", "Area:\t", "Address:", "\t", "\t"};
    printf("%s:\t0x%02X \n", "Function code", packet[param_offset]);
    int item_count = packet[param_offset+1];
    printf("%s:\t%d \n", "Item count", item_count);
    printf("-----------------------------------------------------------------------------------------------------------------------------------------------\n");
    printf(" SpecType  |  Length   | Syntax ID | Var. Type |         Count         |        DB Number      |    Area   |              Address              \n");
    printf("-----------------------------------------------------------------------------------------------------------------------------------------------"); 
    // 0x12
    for(j=0;j<s7_param_len;j++) {
        if (packet[param_offset + 2 + j] == 18){
            printf("\n");
        }
        printf("   0x%02X    ", packet[param_offset + 2 + j]);
    }
    printf("\n");
    printf("-----------------------------------------------------------------------------------------------------------------------------------------------\n\n");
}


// Read var - ack data
void read_var_packet_ackdata(const u_char *packet, const int param_offset, const int s7_data_len){
    int j, k;
    printf("Function code:\tRead variable\n");
    int item_count = packet[param_offset + 1];
    printf("%s:\t%d \n", "Item count", item_count);
    printf("-----------------------------------------------------------------------------------------------\n");
    printf(" Error Code |  Var Type |          Count        |                  Data                        \n");
    printf("-----------------------------------------------------------------------------------------------\n");
    for(j=0;j<s7_data_len;j++) {
        if (packet[param_offset + 2 + j] == 255){
            printf("\n");
        }
        printf("   0x%02X    ", packet[param_offset + 2 + j]);
    }
    printf("\n");
    printf("-----------------------------------------------------------------------------------------------\n");
}


void write_var_packet_job(const u_char *packet, const int param_offset, const int data_offset, const int data_len){
    int j, k;
    printf("Function code:\tWrite variable\n");
    char* strarray[] = {"Spec Type:", "Length:\t", "Syntax ID:", "Variable Type:", "Count: ", "\t", "DB Number:", "\t", "Area:\t", "Address:", "\t", "\t"};
    int item_count = packet[param_offset+1];
    printf("%s:\t%d \n", "Item count", item_count);
    for(j=0;j<(item_count);j++) {
        printf("\nItem number %d \n", (j+1));
        for(k=0;k<12;k++) {
            printf("%s \t0x%02X \n", strarray[k], packet[param_offset+2+12*j+k]);
        }        
    }
    printf("Data: \n");
    for(j=0;j<data_len;j++) {
        printf("0x%02X ", packet[data_offset+j]);
    }
    printf("\n\n");
}



void s7_analysis(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *packet, const int total_headers_size){
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      vrsn     |    reserved   |          packet length        |

    if(packet[total_headers_size] != 3){
    	return;
    }else{
	    int j;
	    int counter = 0;   
    	
    	if (packet[total_headers_size+4] <= 0){
    		return;
    	}
    	else{

            int cotp_len = packet[total_headers_size+4]+1;
            int s7_offset = total_headers_size + 4 + packet[total_headers_size+4]+1;
            int cotp_flag = packet[s7_offset-1];
            int s7comm_flag = packet[s7_offset];
            int s7_msg_type = packet[s7_offset+1];
            int s7_param_len = packet[s7_offset+6]*256+packet[s7_offset+7];
            int s7_data_len = packet[s7_offset+8]*256+packet[s7_offset+9];
            if (s7comm_flag == 50 && cotp_flag==128){
                pcap_dump(dumpfile, header, packet);
                // Debug               
                int debug = 0;
                if (debug){                  
                    printf("S7 Packet\n");
                    printf("TPKT:\t\t");
                    for(j=0;j<4;j++) { 
                        printf("0x%02X ",packet[total_headers_size+j]);
                    }
                    printf("\nCOTP:\t\t");
                    for(j=0; j<cotp_len; j++) { 
                        printf("0x%02X ",packet[total_headers_size+4+j]);
                    }   
                    printf("\nType:\t\t");
                    int param_offset;
                    int data_offset;
                    switch (s7_msg_type){
                        case 1:
                        printf("Job Request\n");
                        param_offset = s7_offset + 10;
                        data_offset = param_offset + s7_param_len;
                        // 0xf0 - Setup comm packets
                        if (packet[param_offset] == 240){
                            setup_comm_packet(packet, param_offset);
                        }
                        // 0x04 - Read var packets
                        if (packet[param_offset] == 4){
                            read_var_packet_job(packet, param_offset, s7_param_len);
                        }
                        // 0x04 - Write var packets
                        if (packet[param_offset] == 5){
                            write_var_packet_job(packet, param_offset, data_offset, s7_data_len);
                        }
                        break;
                        case 2:
                        printf("Ack\n");
                        param_offset = s7_offset + 10;
                        data_offset = param_offset + s7_param_len;
                        break;
                        case 3:
                        printf("Ack-Data\n");
                        param_offset = s7_offset + 12;
                        data_offset = param_offset + s7_param_len;
                        // 0x04 - Read var packets
                        if (packet[param_offset] == 4){
                            read_var_packet_ackdata(packet, param_offset, s7_data_len);
                        }
                        break;
                        case 7:
                        printf("Userdata\n");
                        param_offset = s7_offset + 10;
                        data_offset = param_offset + s7_param_len;
                        break;
                    }
                    printf("Param length:\t%d \n", s7_param_len);
                    printf("Parameters:\t");
                    for(j=param_offset;j<data_offset;j++) {
                        printf("0x%02X ",packet[j]);      
                    }
                    printf("\nData length:\t%d \n", s7_data_len);
                    printf("Data:\t\t");
                    counter = 0;
                    for(j=data_offset;j<header->len;j++) {
                        printf("0x%02X ",packet[j]);      
                    }
                    printf("\nAll payload:\t");
                    counter = 0;
                     // Print payload           
                    for(j=s7_offset;j<header->len;j++) {
                        printf("0x%02X ",packet[j]);      
                    }
                    printf("\n\n---------------\n\n");
                }
            }
    	}
    }
    return;
}
