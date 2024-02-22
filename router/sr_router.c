/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void sr_handlearp(struct sr_instance* sr, uint8_t* arp_buffer, char* interface, unsigned int len);
void send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_packet, char* interface);
void sr_handle_ip(struct sr_instance* sr, uint8_t* packet, char* ip_interface, unsigned int ip_len, unsigned int packet_len);
int send_icmp_exception(struct sr_instance* sr, uint8_t type, uint8_t code, sr_ip_hdr_t* packet, uint8_t* buf, struct sr_if* interface);
int send_icmp_reply(struct sr_instance* sr, uint8_t type, uint8_t code, uint8_t* packet, struct sr_if* interface);
struct sr_rt* search_rt(struct sr_instance* sr, struct in_addr addr);
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

/* Pseudocode for sr_handlepacket:
check etherheader for if IP or ARP
uint16_t ethertype (utils)
 break into ip and arp methods*/


void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  if (len < sizeof(sr_ethernet_hdr_t)) {
	  printf("Incoming packet too small.\n");
	  return;
  }
  print_hdrs(packet, len);
  /* Determine if IP or ARP packet from ethertype. (found in sr_protocol.h) */
  switch (ethertype(packet)) {
  case ethertype_ip:
	  printf("Packet is IP..\n");
	  sr_handle_ip(sr, packet, interface, len-sizeof(sr_ethernet_hdr_t), len);
	  break;
  case ethertype_arp:
	  printf("Packet is ARP.\n");
	  sr_handlearp(sr, packet + sizeof(sr_ethernet_hdr_t), interface, len - sizeof(sr_ethernet_hdr_t));
	  break;
  default:
	  printf("Unknown ethertype.\n");
	  return;
  } /* end switch */
} /* end sr_handlepacket */

  /* ARP PSEUDOCODE:
  //ARP
    //check request or reply using ar_op
    //if request
      //send a reply


    //if reply
      //update the cache

  // sr_handlearp(sr_instance, buffer, interface, length)
    // Takes in the ARP packet. AKA the incoming packet ahead of the ethernet header.
  */
  void sr_handlearp(struct sr_instance* sr, uint8_t* arp_buffer, char* interface, unsigned int len) {

	  
    
	  /* Cast buffer to arp header struct type. */
	  sr_arp_hdr_t* arp_packet = (sr_arp_hdr_t*) arp_buffer;
	  enum sr_arp_opcode opcode = (enum sr_arp_opcode)ntohs(arp_packet->ar_op);
	  /* Determine if request or reply. */
	  switch (opcode) {
	  case arp_op_request:
		  printf("ARP request.\n");
		  send_arp_reply(sr, arp_packet, interface); /* DONE */
		  break;
	  case arp_op_reply:
		  printf("ARP reply.\n");
		  
		  struct sr_arpreq* request = sr_arpcache_insert(&(sr->cache), arp_packet->ar_sha, arp_packet->ar_sip);
		  printf("Checking if in queue...\n");
		  if (request) {
			  printf("Sending packets waiting in queue.\n");
			  struct sr_packet* packets = request->packets;
			 
			  struct sr_arpentry* cache_entry;
			  while (packets) {
				  printf("Sending packet.\n");
				  cache_entry = sr_arpcache_lookup(&(sr->cache), request->ip);
				  if (cache_entry) {
					  printf("Found cache entry.\n");
					  printf("Sending ICMP packet:\n");
					  sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packets->buf;
					  memcpy(ether_hdr->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN); 
					  struct sr_if* iface = sr_get_interface(sr, interface);
					  memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
					  /*
					  struct sr_ip_hdr_t* ip_hdr = (struct sr_ip_hdr_t*) (packets+sizeof(sr_ethernet_hdr_t))->buf; 
					  
					  uint32_t test = ip_hdr->ip_dst;
					  ip_hdr->ip_dst = ip_hdr->ip_src;
					  ip_hdr->ip_src = test; 
					  print_hdrs(packets->buf, packets->len);
					  */
					  
					  /* error happening here */
					  /*sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)(packets->buf);
					  memcpy(ethernet_header->ether_dhost, cache_entry->mac, ETHER_ADDR_LEN);
					  memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);*/
					  int success = sr_send_packet(sr, packets->buf, packets->len, packets->iface);
					  if (success!= 0) {
						  printf("Error in sending packet.\n");
					  } else {
						  printf("Sent packet.\n");
						  
					  }
					  packets=packets->next;
				  } else {
					  printf("Queueing the request again.\n");
					  
				  }
				  free(cache_entry);
			  }
			  sr_arpreq_destroy(&sr->cache, request);
			  
		  }
		  printf("No requests found matching arp reply.\n");
		  /* what to do here*/
		  break;
	  default:
		  printf("Unknown ARP opcode: %hx\n", arp_packet->ar_op);
		  /* put into cache */
		  sr_arpcache_insert(&sr->cache, arp_packet->ar_sha, arp_packet->ar_sip);
		  return;
	  } /* end switch */
  } /* end handle arp */

void send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_packet, char* interface) {
	/* Malloc header space. */
	printf("Sending arp reply...\n");
	uint8_t* mem_block = (uint8_t*) malloc(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));
	sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(mem_block+sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)mem_block;
	struct sr_if* ifacestruct = (struct sr_if*) interface;
	struct sr_if* iface = sr_get_interface(sr, ifacestruct->name);
	/* ARP header: */
	arp_header->ar_op = htons(arp_op_reply); /* arp reply optype */
	arp_header->ar_hrd = htons(arp_hrd_ethernet); /*  ethernet hardware */
	arp_header->ar_hln = ETHER_ADDR_LEN; /* hardware address length */
	arp_header->ar_pro = htons(0x0800); /* protocol type (IPv4) */
	arp_header->ar_pln = sizeof(uint32_t); /* IPv4 length is 32 bits */
	arp_header->ar_sip = iface->ip; /* put own ip into source ip */
	arp_header->ar_tip = arp_packet->ar_sip; /* put source ip from request into target ip */
	memcpy(arp_header->ar_sha, iface->addr, ETHER_ADDR_LEN); /* put source ethernet address */
	memcpy(arp_header->ar_tha, arp_packet->ar_sha, ETHER_ADDR_LEN); /* put target ethernet address */

	/* Ethernet header: */
	memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN); /* Put in ethernet source and target MAC. */
	memcpy(ethernet_header->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);
	ethernet_header->ether_type = htons(ethertype_arp);
	/* print source and dest */
	

	/* Try to send packet. */
	printf("Trying to send...\n");
	int success = sr_send_packet(sr, mem_block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t), iface->name);
	printf("ARP Sent.\n");
	print_hdrs(mem_block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
	if (success!=0) {
		printf("sr_send_packet error when trying to send ARP reply.\n");
	} 
	free(mem_block);

} /* end send arp reply */

/*
  //DORIZ TO-DO: IP 

  //check min length (if length is less than the size of the sr_protocols struct) 
    //checksum validation cksum from header (ip sum field) 
    //decrement the ttl by 1 then recompute the packet cksum over the modified header 
      //discard if checksum does not match 
    //check if ttl is less than one 
      //if <= 1 -> send ICMP packet "Time Exceeded"
      // if >1, decrement ttl then cksum  
      //obtain destination id then check if its in our local interface 
        //if in local interface <- check if ICMP or not 
          //if ckcsum is valid, send echo request (ping)
          //else ignore the packet then send ICMP "Port Unreachable" 
        //else
          //check routing table for longest prefix match 
            //if no match, ICMP "Destination net unreachable"
            //else: check the cache 
              //if not in the cache then send ARP request
                //if no response, send "Destination host unreachable"
*/

struct sr_if* sr_match_interface(struct sr_instance* sr, uint32_t ip) {
	struct sr_if* interface_match = sr->if_list;
	while(interface_match) {
		if (interface_match->ip == ip) {
			return interface_match;
		}
		interface_match = interface_match->next;
	}
	return 0;
}
  void sr_handle_ip(struct sr_instance* sr, uint8_t* packet, char* ip_interface, unsigned int ip_len, unsigned int packet_len) {

  
  uint8_t* ip_buffer = packet+sizeof(sr_ethernet_hdr_t);
  sr_ip_hdr_t* ip_packet = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  
  
  /* check length */
  if (ip_len < sizeof(sr_ip_hdr_t)) {
	  printf("Packet length too small. Discarding.\n");
	  return;
  }
  
  
  /* check checksum */
  uint16_t incoming_checksum = ntohs(ip_packet-> ip_sum);
  ip_packet->ip_sum = 0; /* checksum not included */
  uint16_t calculated_checksum = ntohs(cksum(ip_packet, sizeof(sr_ip_hdr_t)));
  
  if (incoming_checksum != calculated_checksum) {
	  printf("Checksum is invalid. Discarding packet.\n");
	  return;
  } else {
	  printf("IP checksum valid.\n");
  }
  
  /* check ttl */
    if (ip_packet->ip_ttl <= 1) {
  	  printf("Packet timed out. TTL <= 1. \n");
  	  send_icmp_exception(sr, 11, 9, ip_packet, ip_buffer, (struct sr_if *)ip_interface); /*time exceeded*/
  	  return;
    } else {
    	printf("IP TTL valid.\n");
  	  uint16_t TTL = ip_packet->ip_ttl; /*decrement the ttl by 1*/
  	  ip_packet->ip_sum = ntohs(cksum(ip_packet, sizeof(sr_ip_hdr_t))); /*recalculate checksum*/
  	  ip_packet->ip_ttl = TTL - 1; /*decrement the ttl by 1*/
    }
  
  /* check if address is within network (sr_if.c/h) <- instance at member if_list */
  /*struct sr_if* interface_check = sr_get_interface(sr, ip_interface->name);*/
  
  
  
  struct sr_if* interface_check = sr_match_interface(sr, ip_packet->ip_dst);
  

  if (interface_check) { /*in local interface*/
    
    
    
    if (ip_packet->ip_p == ip_protocol_icmp) { /*TO-DO: if ICMP echo request, checksum, then echo reply to the sending host */
    	
    	printf("IP is echo request.\n");
    	
    	send_icmp_reply(sr, 0, 9, packet, (struct sr_if*)ip_interface);
    }
    else { 
    	printf("Is TCP/UDP, sending exception.\n");
      send_icmp_exception(sr, 3, 3, ip_packet, ip_buffer, (struct sr_if*)ip_interface); /*send an exception is UDP or TCP payload is sent to one of the interfaces*/
    } 
  } 
  /*if not within network/destined elsewhere*/
  else {

      /*find out which entry in the routing table has the longest prefix match with the destination IP address*/
      printf("Loading routing table from server.\n");
      struct in_addr ip_check;
      ip_check.s_addr = ip_packet->ip_dst;
      struct sr_rt* next_hop_ip = search_rt(sr, ip_check);
      struct sr_if* next_hop_interface = sr_get_interface(sr, next_hop_ip->interface);
      if (next_hop_ip == 0) {
        printf("Next hop not found.\n");
        send_icmp_exception(sr, 3, 0, ip_packet, ip_buffer, (struct sr_if*)ip_interface); /*port unreachable*/
        return; /*discard packet*/
      }
      /*check arp cache for the next MAC address corresponding to the next-hop IP */
      printf("Searching for next hop MAC address.\n");
      uint32_t nh_addr = next_hop_ip->dest.s_addr;
      struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, nh_addr);
      if (entry) { /* found entry */
    	  printf("Entry found. Forwarding packet.\n");
    	  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;
    	  memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    	  memcpy(ethernet_header->ether_shost, next_hop_interface->addr, ETHER_ADDR_LEN);
    	  
    	  int success = sr_send_packet(sr, packet, packet_len, next_hop_ip->interface);
    	  printf("FORWARDING ICMP PACKET\n\n\n");
    	  print_hdrs(packet, packet_len);
    	  if (success == 0) {
    		  printf("Forwarded successfully.");
    	  } else {
    		  printf("Error in forwarding packet.");
    	  }
      } else {
    	  printf("No entry found. Adding this packet to queue:\n");
    	  print_hdr_ip((uint8_t*)ip_packet);
    	  sr_arpcache_queuereq(&(sr->cache), nh_addr, (uint8_t*)ip_packet, ip_len, ip_interface); /*i'm assuming that sr_arpcache_sweepreqs handles everything */ 
      }
      
      
      /*TO-DO: Need to figure out how to accomodate type 3, code 1*/
    	
  	
  } 
} 





/*struct to search through routing table*/
struct sr_rt* search_rt(struct sr_instance* sr, struct in_addr addr) {

  struct sr_rt* walker = sr->routing_table;
  struct sr_rt* best_match = NULL;
  uint32_t match_check = 0;

  while (walker != 0) { /*check if match*/
    if ((addr.s_addr & walker->mask.s_addr) == (walker->dest.s_addr & walker->mask.s_addr)) { /*check network address and destination address are a match*/
      if(!best_match || walker->mask.s_addr >= match_check) {
        match_check = walker->mask.s_addr;
        best_match = walker;
      }
    }
    walker = walker->next;
  }
  return best_match;
}


/*Note to Alex: If anything breaks or cannot compile correctly, I guareentee it's from the ICMP protocols <3*/
/*
//copy the contents of the ip packet 
  //modify the header in the packet
  //add the destination once again
  //include icmp header after the ip protcol number

  //icmp packet: type->code->checksum ; pointer to the problem ; original ip header

*/
/*generate icmpp echo reply*/
int send_icmp_reply(struct sr_instance* sr, uint8_t type, uint8_t code, uint8_t* packet, struct sr_if* interface) {
	
	sr_ip_hdr_t* incoming_ip_hdr = (sr_ip_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
	
	unsigned int icmp_len = 0;
	switch (type) {
	case(3):
			printf("ICMP is Type 3.\n");
			icmp_len = sizeof(sr_icmp_t3_hdr_t);
			break;
	
	default:
			printf("ICMP is NOT Type 3.\n");
			icmp_len = sizeof(sr_icmp_hdr_t);
			break;
	}
	
	uint8_t* client_memory = (uint8_t*) malloc(ntohs(incoming_ip_hdr->ip_len)+sizeof(sr_ethernet_hdr_t)+icmp_len);
	
	sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)client_memory;
	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(client_memory+sizeof(sr_ethernet_hdr_t));
	/* populate ethernet header */
	struct in_addr ip_check;
	ip_check.s_addr = incoming_ip_hdr->ip_src;
	struct sr_rt* routing_table_entry = search_rt(sr, ip_check);
	struct sr_if* iface = sr_get_interface(sr, routing_table_entry->interface);
	
	memcpy(ip_header, incoming_ip_hdr, ntohs(incoming_ip_hdr->ip_len));
	
	if (type == 3) {
		sr_icmp_t3_hdr_t* icmp_t3_hdr = (sr_icmp_t3_hdr_t*) (client_memory + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_t3_hdr->icmp_type = type;
		icmp_t3_hdr->icmp_code = code;
		icmp_t3_hdr->next_mtu = 0;
		icmp_t3_hdr->unused = 0;
		memcpy(icmp_t3_hdr->data, packet, ICMP_DATA_SIZE);
		icmp_t3_hdr->icmp_sum = 0;
		icmp_t3_hdr->icmp_sum = cksum((uint8_t*) icmp_t3_hdr, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
		
	} else {
		
		sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) (client_memory + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_hdr->icmp_type = type;
		icmp_hdr->icmp_code = code;
		icmp_hdr->icmp_sum = 0;
		icmp_hdr->icmp_sum = cksum((uint8_t*)icmp_hdr, sizeof(sr_icmp_hdr_t));
	}
	
  /*populate ip header*/
	
	
	
	
	ip_header->ip_ttl = 64;
	ip_header->ip_p = ip_protocol_icmp;
	ip_header->ip_src = iface->ip;
	ip_header->ip_dst = incoming_ip_hdr->ip_src;
	ip_header->ip_sum = 0;
	ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl * sizeof(unsigned int));

	/* populate ethernet header */
	
	ethernet_header->ether_type = htons(ethertype_ip);
	struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, routing_table_entry->gw.s_addr);
	struct sr_if* iface2 = sr_get_interface(sr, iface->name);
	
	      if (entry) { /* found entry */
	    	  
	    	  printf("Forwarding MAC address found. Forwarding packet.\n");
	    	  memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
	    	  memcpy(ethernet_header->ether_shost, iface2->addr, ETHER_ADDR_LEN);
	    	  printf("ICMP packet attempting to send:\n\n");
	    	  print_hdrs(client_memory, sizeof(sr_ethernet_hdr_t)+ntohs(incoming_ip_hdr->ip_len));
	    	  int success = sr_send_packet(sr, client_memory, sizeof(sr_ethernet_hdr_t)+ntohs(incoming_ip_hdr->ip_len), iface->name);
			  if (success!=0) {
				printf("ICMP reply failed to send.\n");
			  } else {
				printf("ICMP reply successfully sent.\n");
			  }
	      } else {
	    	  
	    	  printf("No forwarding MAC entry found. Adding to queue.\n");
	    	  printf("ICMP packet adding to queue:\n\n");
	    	  print_hdrs(client_memory, sizeof(sr_ethernet_hdr_t)+ntohs(incoming_ip_hdr->ip_len));
	    	  sr_arpcache_queuereq(&(sr->cache), routing_table_entry->gw.s_addr, client_memory, sizeof(sr_ethernet_hdr_t)+ntohs(incoming_ip_hdr->ip_len), iface2->name); /*i'm assuming that sr_arpcache_sweepreqs handles everything */ 
	}
	      
	


	
	
	/*free(icmp_header);*/
	

	return 0;



}

int send_icmp_exception(struct sr_instance* sr, uint8_t type, uint8_t code, sr_ip_hdr_t* packet, uint8_t* buf, struct sr_if* interface) {

  uint8_t* client_memory = (uint8_t*) malloc(sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(client_memory+sizeof(sr_ip_hdr_t));


   /*populate ip header*/
	ip_header->ip_tos = 0x0000;
	ip_header->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	ip_header->ip_id = 4;
	ip_header->ip_off = IP_RF;
	ip_header->ip_ttl = IP_TTL;
	ip_header->ip_p = ip_protocol_icmp;
	ip_header->ip_src = packet->ip_src;
	ip_header->ip_dst = packet->ip_dst;
	ip_header->ip_sum = 0;
	ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  /*populate icmp header*/
  sr_icmp_t3_hdr_t* icmp_error = (sr_icmp_t3_hdr_t*)client_memory;
	uint32_t icmp_hlen = sizeof(sr_icmp_hdr_t);
	icmp_error = malloc(icmp_hlen);
	icmp_error->unused = 0;
	memcpy(icmp_error->data, buf, ICMP_DATA_SIZE);
	icmp_error->icmp_sum = 0;
	icmp_error->icmp_sum = cksum(icmp_error, icmp_hlen);
	
  switch (type) {
  case (3): /*the unreachable*/
    
    icmp_error->icmp_type = 3;
    if (code ==  0) {
      printf("Destination net unreachable");
      icmp_error->icmp_code = 0;
    }
    if (code == 1) {
      printf("Destination host unreachable");
      icmp_error->icmp_code = 1;
    }
    if (code == 3) {
      printf("Port unreachable");
      icmp_error->icmp_code = 3;
    }
    break;

  case (11):
    printf("Time exceeded");
    icmp_error->icmp_type = 11;
    icmp_error->icmp_code = 0;
    break;

  default:
    /*Nothing should happen <- Error*/
    break;
  }
  uint32_t len = sizeof(sr_ip_hdr_t) + icmp_hlen;
	buf = malloc(len);
	memcpy(buf, ip_header, sizeof(sr_ip_hdr_t));
	memcpy(buf + sizeof(sr_ip_hdr_t), icmp_error, icmp_hlen);

  int serror = sr_send_packet(sr, client_memory, sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t), interface->name);
	if (serror != 0 ) {
    printf("sr_send_packet error when trying to send ARP reply.\n");
  }

	free(icmp_error);
	free(ip_header);

	return serror;
  
}

/*
// Echo reply (type 0) Sent in response to an echo request (ping) to one of the router's interfaces. (This is only for echo requests to any of the router's IPs. An echo request sent elsewhere should be forwarded to the next hop address as usual.)
// Destination net unreachable (type 3, code 0) ** Sent if there is a non-existent route to the destination IP (no matching entry in routing table when forwarding an IP packet).
// Destination host unreachable (type 3, code 1) ** Sent if five ARP requests were sent to the next-hop IP without a response.
// Port unreachable (type 3, code 3) ** Sent if an IP packet containing a UDP or TCP payload is sent to one of the router's interfaces. This is needed for traceroute to work.
// Time exceeded (type 11, code 0) ** Sent if an IP packet is discarded during processing because the TTL field is 0. 
// This is also needed for traceroute to work. The source address of an ICMP message can be the source address of any of the incoming interfaces, as specified in RFC 792. 
// As mentioned above, the only incoming ICMP message destined towards the router's IPs that you have to explicitly process are ICMP echo requests. You may want to create additional structs for ICMP messages for convenience, but make sure to use the packed attribute so that the compiler doesn't try to align the fields in the struct to word boundaries:
*/






/* end sr_ForwardPacket */



