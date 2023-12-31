/**
 * \file server/process_packet.c
 *
 * \brief Packet parser/decoder for spad server.
 *
 *          Takes the raw packet
 *          data from libpcap and parses/extracts the packet data payload,
 *          then creates an ZTN context with that data.  If the context
 *          creation is successful, it is queued for processing.
 */

/*  Spa is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 spa developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/

#include "spad_common.h"
#include "netinet_common.h"
#include "process_packet.h"
#include "incoming_spa.h"
#include "utils.h"
#include "log_msg.h"
#include "netinet/ether.h"

void
process_packet(PROCESS_PKT_ARGS_TYPE *args, PACKET_HEADER_META,
               const unsigned char *packet)
{
    struct ether_header *eth_p;
    struct iphdr        *iph_p;
    struct tcphdr       *tcph_p;
    struct udphdr       *udph_p;
    struct icmphdr      *icmph_p;

    unsigned char       *pkt_data;
    unsigned short      pkt_data_len;
    unsigned char       *pkt_end;
    unsigned char       *fr_end;

    unsigned int        ip_hdr_words;

    unsigned char       proto;
    unsigned int        src_ip;
    unsigned int        dst_ip;

    unsigned short      src_port = 0;
    unsigned short      dst_port = 0;

    unsigned short      eth_type;

    ztn_srv_options_t   *opts = (ztn_srv_options_t *)args;

    int                 offset = opts->data_link_offset;

#if USE_LIBPCAP
    unsigned short      pkt_len = packet_header->len;

    /* Gotta have a complete ethernet header.
    */
    if (packet_header->caplen < ETHER_HDR_LEN)
        return;

    /* Determine packet end.
    */
    fr_end = (unsigned char *) packet + packet_header->caplen;
#else
    /* This is coming from NFQ and we get the packet lentgh as an arg.
    */
    if (pkt_len < ETHER_HDR_LEN)
        return;
    fr_end = (unsigned char *) packet + pkt_len;
#endif

    /* This is a hack to determine if we are using the linux cooked
     * interface.  We base it on the offset being 16 which is the
     * value it would be if the datalink is DLT_LINUX_SLL.  I don't
     * know if this is the correct way to do this, but it seems to work.
    */
    unsigned char       assume_cooked = (offset == 16 ? 1 : 0);

    /* The ethernet header.
    */
    eth_p = (struct ether_header*) packet;

    eth_type = ntohs(*((unsigned short*)&eth_p->ether_type));

    if(eth_type == 0x8100) /* 802.1q encapsulated */
    {
        offset += 4;
        eth_type = ntohs(*(((unsigned short*)&eth_p->ether_type)+2));
    }

    /* When using libpcap, pkthdr->len for 802.3 frames include CRC_LEN,
     * but Ethenet_II frames do not.
    */
    if (eth_type > 1500 || assume_cooked == 1)
    {
        pkt_len += ETHER_CRC_LEN;

        if(eth_type == 0xAAAA)      /* 802.2 SNAP */
            offset += 5;
    }
    else /* 802.3 Frame */
        offset += 3;

    /* Make sure the packet length is still valid.
    */
    if (! ETHER_IS_VALID_LEN(pkt_len) )
        return;

    /* Pull the IP header.
    */
    iph_p = (struct iphdr*)(packet + offset);

    /* If IP header is past calculated packet end, bail.
    */
    if ((unsigned char*)(iph_p + 1) > fr_end)
        return;

    /* ip_hdr_words is the number of 32 bit words in the IP header. After
     * masking of the IPV4 version bits, the number *must* be at least
     * 5, even without options.
    */
    ip_hdr_words = iph_p->ihl & IPV4_VER_MASK;

    if (ip_hdr_words < MIN_IPV4_WORDS)
        return;

    /* Make sure to calculate the packet end based on the length in the
     * IP header. This allows additional bytes that may be added to the
     * frame (such as a 4-byte Ethernet Frame Check Sequence) to not
     * interfere with SPA operations.
    */
    pkt_end = ((unsigned char*)iph_p)+ntohs(iph_p->tot_len);
    if(pkt_end > fr_end)
        return;

    /* Now, find the packet data payload (depending on IPPROTO).
    */
    src_ip = iph_p->saddr;
    dst_ip = iph_p->daddr;

    proto = iph_p->protocol;

    if (proto == IPPROTO_TCP)
    {
        /* Process TCP packet
        */
        tcph_p = (struct tcphdr*)((unsigned char*)iph_p + (ip_hdr_words << 2));

        src_port = ntohs(tcph_p->source);
        dst_port = ntohs(tcph_p->dest);

        pkt_data = ((unsigned char*)(tcph_p+1))+((tcph_p->doff)<<2)-sizeof(struct tcphdr);

        pkt_data_len = (pkt_end-(unsigned char*)iph_p)-(pkt_data-(unsigned char*)iph_p);
    }
    else if (proto == IPPROTO_UDP)
    {
        /* Process UDP packet
        */
        udph_p = (struct udphdr*)((unsigned char*)iph_p + (ip_hdr_words << 2));

        src_port = ntohs(udph_p->source);
        dst_port = ntohs(udph_p->dest);

        pkt_data = ((unsigned char*)(udph_p + 1));
        pkt_data_len = (pkt_end-(unsigned char*)iph_p)-(pkt_data-(unsigned char*)iph_p);
    }
    else if (proto == IPPROTO_ICMP)
    {
        /* Process ICMP packet
        */
        icmph_p = (struct icmphdr*)((unsigned char*)iph_p + (ip_hdr_words << 2));

        pkt_data = ((unsigned char*)(icmph_p + 1));
        pkt_data_len = (pkt_end-(unsigned char*)iph_p)-(pkt_data-(unsigned char*)iph_p);
    }

    else
        return;

    /*
     * Now we have data. For now, we are not checking IP or port values. We
     * are relying on the pcap filter. This may change so we do retain the IP
     * addresses and ports just in case. We just go ahead and queue the
     * data.
    */

    /* Expect the data to be at least the minimum required size.  This check
     * will weed out a lot of things like small TCP ACK's if the user has a
     * permissive pcap filter
    */
    if(pkt_data_len < MIN_SPA_DATA_SIZE)
        return;

    /* Expect the data to not be too large
    */
    if(pkt_data_len > MAX_SPA_PACKET_LEN)
        return;

    /* Copy the packet for SPA processing
    */
    memcpy((char *)opts->spa_pkt.packet_data, (char *)pkt_data, pkt_data_len);
    opts->spa_pkt.packet_data[pkt_data_len] = '\0';

    opts->spa_pkt.packet_data_len = pkt_data_len;
    opts->spa_pkt.packet_proto    = proto;
    opts->spa_pkt.packet_src_ip   = src_ip;
    opts->spa_pkt.packet_dst_ip   = dst_ip;
    opts->spa_pkt.packet_src_port = src_port;
    opts->spa_pkt.packet_dst_port = dst_port;

    incoming_spa(opts);

    return;
}


/***EOF***/
