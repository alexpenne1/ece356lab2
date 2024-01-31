#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
	printf("Sweeping requests...");
    // Get list of requests.
	struct sr_arpreq* current_requests = sr->cache.requests;
	// Go through linked list of requests.
	while (current_requests != 0) {
		// Check if has a MAC address yet in the cache. Must free this if not NULL.
		struct sr_arpentry* request_entry = sr_arpcache_lookup(&sr->cache, current_requests->ip);
		// Check if entry is null.
		if (request_entry != NULL) {
			printf("Cache hit on IP %d", current_requests->ip);
			// Get packets in the queue.
			struct sr_packet* current_packets = current_requests->packets;
			// Go through linked list of packets.
			while (current_packets != 0) {
				// Make packet IP header.
				sr_ip_hdr_t* current_ip = (sr_ip_hdr_t*) current_packets->buf;
				// Malloc space for ethernet header.
				uint8_t* current_mem_block = malloc(current_ip->ip_len + sizeof(sr_ethernet_hdr_t));
				// Place IP header inside ethernet header.
				memcpy(current_mem_block+sizeof(sr_ethernet_hdr_t), current_ip, current_ip->ip_len);
				// Cast to ethernet header.
				sr_ethernet_hdr_t* current_ethernet = (sr_ethernet_hdr_t*)current_mem_block;
				// Set ethernet header up.
				current_ethernet->ether_type = htons(ethertype_ip);
				memcpy(current_ethernet->ether_dhost, request_entry->mac, ETHER_ADDR_LEN);
				// Need receiving interface to set source MAC.
				struct sr_if* receiving_interface = sr_get_interface(sr, current_packets->iface);
				memcpy(current_ethernet->ether_shost, receiving_interface->addr, ETHER_ADDR_LEN);
				// Send the packet.
				sr_send_packet(sr, current_mem_block, current_ip->ip_len+sizeof(sr_ethernet_hdr_t), receiving_interface);
				// Go to next packet.
				current_packets = current_packets->next;
			}
			// All packets sent. Need to destroy request.
			sr_arpreq_destroy(&sr->cache, current_requests);
		} else {
			// Cache miss. Need to resend ARP.
			if (difftime(time(0), current_requests->sent)>1) {
				// Been longer than a second.
				// Check times sent.
				if (current_requests->times_sent > 4) {
					// Sent the max times.
					// TODO: send icmp packet
					// Destory request.
					sr_arpreq_destroy(&sr->cache, current_requests);
					printf("Request timed out.");
				} else {
					current_requests->times_sent++;
					current_requests->sent = time(0);
					// Send ARP request.
					sr_send_arp_request(sr, current_requests);
					// Get next request.
					current_requests = current_requests->next;
                    
				}
			}
		}
	}
}

void sr_send_arp_request(struct sr_instance* sr, struct sr_arpreq* arp_request) {
	printf("Sending ARP request...\n");
	// Malloc space for request.
	uint8_t* mem_block = malloc(sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
	// Cast ARP and ethernet header.
	sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(mem_block+sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)mem_block;
	// Add values to headers.
	arp_header->ar_hln = ETHER_ADDR_LEN;
	arp_header->ar_hrd = htons(arp_hrd_ethernet);
	arp_header->ar_pln = sizeof(uint32_t);
	arp_header->ar_pro = htons(0x0800);
	arp_header->ar_op = htons(arp_op_request);
	// Need source interface.
	struct sr_if* source_interface = sr_get_interface(sr,  arp_request->packets->iface);
	memcpy(arp_header->ar_sha, source_interface->addr, ETHER_ADDR_LEN);
	arp_header->ar_sip = source_interface->ip;
	arp_header->ar_tha = 255;
	arp_header->ar_tip = arp_request->ip;

	ethernet_header->ether_dhost = 255;
	ethernet_header->ether_shost = source_interface->addr;
	ethernet_header->ether_type = htons(ethertype_arp);
	// Send the packet.
	int success = sr_send_packet(sr, mem_block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t), source_interface->name);
	if (success != 0) {
		printf("Failed to send ARP request.");
	}
	free(mem_block);
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

