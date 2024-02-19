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
void sr_handle_ip(struct sr_instance* sr, uint8_t* ip_buffer, char* ip_interface, unsigned int ip_len);
int send_icmp_exception(struct sr_instance* sr, uint8_t type, uint8_t code, sr_ip_hdr_t* packet, uint8_t* buf, struct sr_if* interface);
int send_icmp_reply(struct sr_instance* sr, uint8_t type, uint8_t code, sr_ip_hdr_t* packet, uint8_t* buf, struct sr_if* interface);
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
  printf("Ethertype: %hx\n", ethertype(packet));
  /* Determine if IP or ARP packet from ethertype. (found in sr_protocol.h) */
  switch (ethertype(packet)) {
  case ethertype_ip:
	  printf("IP packet.\n");
	  sr_handle_ip(sr, packet + sizeof(sr_ethernet_hdr_t), interface, len - sizeof(sr_ethernet_hdr_t));
	  break;
  case ethertype_arp:
	  printf("ARP packet.\n");
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

	  printf("Handling ARP...\n");

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
		  sr_arpcache_insert(&sr->cache, arp_packet->ar_sha, arp_packet->ar_sip);
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
	printf("Sending arp reply...");
	uint8_t* mem_block = (uint8_t*) malloc(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));
	sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(mem_block+sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)mem_block;
	struct sr_if* iface = (struct sr_if*) interface;
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
	printf("Trying to send...");
	int success = sr_send_packet(sr, mem_block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t), iface->name);
	printf("Tried to send.");
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
  void sr_handle_ip(struct sr_instance* sr, uint8_t* ip_buffer, char* ip_interface, unsigned int ip_len) {

  printf("Handling IP...\n");
    
  sr_ip_hdr_t* ip_packet = (sr_ip_hdr_t*) ip_buffer;
  uint32_t dest_addr = ntohs(ip_packet->ip_dst);

  /* check if address is within network (sr_if.c/h) <- instance at member if_list */
  struct sr_if* interface_check = sr->if_list;
  if (interface_check != 0 && dest_addr != interface_check->ip) { 
    interface_check = interface_check->next;
  } /* end if */
  if (interface_check != 0) { /*in local interface*/
    if (ip_packet->ip_p == ip_protocol_icmp) { /*TO-DO: if ICMP echo request, checksum, then echo reply to the sending host */

      uint16_t chksum_icmp = ntohs(cksum(ip_packet, sizeof(sr_arp_hdr_t)));
      if (chksum_icmp != ntohs(ip_packet->ip_sum)) {
        printf("Checksum invalid. Sending error.\n");
        return;
      }  
      else {
        send_icmp_reply(sr, 0, 9, ip_packet, ip_buffer, (struct sr_if*)ip_interface);
      }
    }
    else { 
        send_icmp_exception(sr, 3, 3, ip_packet, ip_buffer, (struct sr_if*)ip_interface); /*send an exception is UDP or TCP payload is sent to one of the interfaces*/
      } 
  } 
  /*if not within network/destined elsewhere*/
  else {
  if (ip_len < sizeof(sr_ip_hdr_t)) { /*check min length and checksum of the packet*/
    printf("Packet length not valid\n");
    return; /*discard packet */
  } 
  /*calculate checksum and check if it matches checksum from header*/
  uint16_t chksum_calc = ntohs(cksum(ip_packet, sizeof(sr_ip_hdr_t)));

  if (chksum_calc != ntohs(ip_packet->ip_sum)) {
    printf("Packet checksum incorrect.\n");
    return; /*discard packet*/
  } 
  else { /*checksum matched*/
    uint16_t TTL = ip_packet->ip_ttl; /*decrement the ttl by 1*/
    if (TTL <= 1) { /*if the TTL field is zero, then discard packet */
      send_icmp_exception(sr, 11, 9, ip_packet, ip_buffer, (struct sr_if *)ip_interface); /*time exceeded*/
      return;
    } 
    /*if TTL != zero */
    else {
      ip_packet->ip_sum = ntohs(cksum(ip_packet, sizeof(sr_ip_hdr_t))); /*recalculate checksum*/
      ip_packet->ip_ttl = TTL - 1; /*decrement the ttl by 1*/

      /*find out which entry in the routing table has the longest prefix match with the destination IP address*/
      printf("Loading routing table from server.\n");
      struct in_addr ip_check;
      ip_check.s_addr = ip_packet->ip_dst;
      struct sr_rt* next_hop_ip = search_rt(sr, ip_check);
      if (next_hop_ip == 0) {
        printf("Next hop not found.\n");
        send_icmp_exception(sr, 3, 0, ip_packet, ip_buffer, (struct sr_if*)ip_interface); /*port unreachable*/
        return; /*discard packet*/
      } 
      /*check arp cache for the next MAC address corresponding to the next-hop IP */
      printf("Searching for next hop MAC address.\n");
      uint32_t nh_addr = next_hop_ip->dest.s_addr;
      struct sr_arpreq* cache_req = sr_arpcache_queuereq(&(sr->cache), nh_addr, (uint8_t*)ip_packet, ip_len, ip_interface); /*i'm assuming that sr_arpcache_sweepreqs handles everything */
      
      /*TO-DO: Need to figure out how to accomodate type 3, code 1*/
    	}
  	} 
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
int send_icmp_reply(struct sr_instance* sr, uint8_t type, uint8_t code, sr_ip_hdr_t* packet, uint8_t* buf, struct sr_if* interface) {
  uint8_t* client_memory = (uint8_t*) malloc(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t));
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
  sr_icmp_t3_hdr_t* icmp_header = (sr_icmp_t3_hdr_t*)client_memory;
	uint32_t icmp_hlen = sizeof(sr_icmp_hdr_t);
	icmp_header = malloc(icmp_hlen);
	icmp_header->icmp_type = 0;
	icmp_header->icmp_code = 0;
	icmp_header->unused = 0;
	memcpy(icmp_header->data, buf, ICMP_DATA_SIZE);
	icmp_header->icmp_sum = 0;
	icmp_header->icmp_sum = cksum(icmp_header, icmp_hlen);

	uint32_t len = sizeof(sr_ip_hdr_t) + icmp_hlen;
	buf = malloc(len);
	memcpy(buf, ip_header, sizeof(sr_ip_hdr_t));
	memcpy(buf + sizeof(sr_ip_hdr_t), icmp_header, icmp_hlen);

	int sreply = sr_send_packet(sr, client_memory, sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t), interface->name);
	
	free(icmp_header);
	free(ip_header);

	return sreply;



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



