// -*- C++ -*-
//
// Copyright (C) 2017 - 2024 Vasily Evseenko <svpcom@p2ptech.org>

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sys/resource.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/random.h>
#include <inttypes.h>
#include <pthread.h>

#include <string>
#include <memory>
#include <vector>
#include <set>

#include "zfex.h"


using namespace std;

#include "wifibroadcast.hpp"
#include "tx.hpp"

// vendored C header (waybeam venc_ring SHM packet ring, consumer side)
extern "C" {
#include "venc_ring.h"
}

Transmitter::Transmitter(int k, int n, const string &keypair, uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, vector<tags_item_t> &tags) : \
    fec_p(NULL), fec_k(-1), fec_n(-1),
    block_idx(0), fragment_idx(0),
    max_packet_size(0),
    epoch(epoch),
    channel_id(channel_id),
    fec_delay(fec_delay),
    tx_secretkey{},
    rx_publickey{},
    session_key{},
    session_packet{},
    session_packet_size(0),
    tags(tags)
{

    FILE *fp;
    if ((fp = fopen(keypair.c_str(), "r")) == NULL)
    {
        throw runtime_error(string_format("Unable to open %s: %s", keypair.c_str(), strerror(errno)));
    }
    if (fread(tx_secretkey, crypto_box_SECRETKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        throw runtime_error(string_format("Unable to read tx secret key: %s", strerror(errno)));
    }
    if (fread(rx_publickey, crypto_box_PUBLICKEYBYTES, 1, fp) != 1)
    {
        fclose(fp);
        throw runtime_error(string_format("Unable to read rx public key: %s", strerror(errno)));
    }
    fclose(fp);

    init_session(k, n);
}

Transmitter::~Transmitter()
{
    if (fec_p != NULL)
    {
        deinit_session();
    }
}


void Transmitter::deinit_session(void)
{
    for(int i=0; i < fec_n; i++)
    {
        free(block[i]);
    }

    delete[] block;

    zfex_status_code_t rc = fec_free(fec_p);
    assert(rc == ZFEX_SC_OK);

    block = NULL;
    fec_p = NULL;
    fec_k = -1;
    fec_n = -1;
}

void Transmitter::init_session(int k, int n)
{
    if (fec_p != NULL)
    {
        deinit_session();
    }

    assert(fec_p == NULL);
    assert(k >= 1);
    assert(n >= 1);
    assert(n < 256);
    assert(k <= n);

    fec_k = k;
    fec_n = n;

    zfex_status_code_t rc = fec_new(fec_k, fec_n, &fec_p);
    assert(rc == ZFEX_SC_OK);

    block = new uint8_t*[fec_n];
    for(int i=0; i < fec_n; i++)
    {
        int _rc = posix_memalign((void**)&block[i], ZFEX_SIMD_ALIGNMENT, ZFEX_ROUND_UP_SIMD(MAX_FEC_PAYLOAD));
        assert(_rc == 0);
    }

    block_idx = 0;
    fragment_idx = 0;

    // init session key
    randombytes_buf(session_key, sizeof(session_key));

    // fill packet header
    wsession_hdr_t *session_hdr = (wsession_hdr_t *)session_packet;
    session_hdr->packet_type = WFB_PACKET_SESSION;

    randombytes_buf(session_hdr->session_nonce, sizeof(session_hdr->session_nonce));

    // fill packet contents

    uint8_t tmp[MAX_SESSION_PACKET_SIZE - crypto_box_MACBYTES - sizeof(wsession_hdr_t)];

    // Fill fixed headers
    {
        wsession_data_t* session_data = (wsession_data_t*)tmp;
        assert(sizeof(*session_data) <= sizeof(tmp));

        session_data->epoch = htobe64(epoch);
        session_data->channel_id = htobe32(channel_id);
        session_data->fec_type = WFB_FEC_VDM_RS;
        session_data->k = (uint8_t)fec_k;
        session_data->n = (uint8_t)fec_n;

        assert(sizeof(session_data->session_key) == sizeof(session_key));
        memcpy(session_data->session_key, session_key, sizeof(session_key));
    }

    // Fill optional Tags

    uint32_t session_data_size = sizeof(wsession_data_t);
    for(auto it = tags.begin(); it != tags.end(); it++)
    {
        tlv_hdr_t* tlv = (tlv_hdr_t*)((uint8_t*)tmp + session_data_size);
        session_data_size += sizeof(tlv_hdr_t) + it->value.size();
        assert(session_data_size <= sizeof(tmp));

        tlv->id = it->id;
        tlv->len = it->value.size();
        memcpy(tlv->value, &it->value[0], it->value.size());
    }

    if (crypto_box_easy(session_packet + sizeof(wsession_hdr_t),
                        (uint8_t*)tmp, session_data_size,
                        session_hdr->session_nonce, rx_publickey, tx_secretkey) != 0)
    {
        throw runtime_error("Unable to make session key!");
    }

    session_packet_size = sizeof(wsession_hdr_t) + session_data_size + crypto_box_MACBYTES;
    assert(session_packet_size <= MAX_SESSION_PACKET_SIZE);
}


RawSocketTransmitter::RawSocketTransmitter(int k, int n, const string &keypair, uint64_t epoch, uint32_t channel_id, uint32_t fec_delay,
                                           vector<tags_item_t> &tags, const vector<string> &wlans, radiotap_header_t &radiotap_header,
                                           uint8_t frame_type, bool use_qdisc, uint32_t fwmark_base, uint32_t inject_retries, uint32_t inject_retry_delay) : \
    Transmitter(k, n, keypair, epoch, channel_id, fec_delay, tags),
    channel_id(channel_id),
    current_output(0),
    ieee80211_seq(0),
    radiotap_header(radiotap_header),
    frame_type(frame_type),
    use_qdisc(use_qdisc),
    fwmark_base(fwmark_base),
    fwmark(fwmark_base),
    inject_retries(inject_retries),
    inject_retry_delay(inject_retry_delay)
{
    for(auto it=wlans.begin(); it!=wlans.end(); it++)
    {
        int fd = socket(PF_PACKET, SOCK_RAW, 0);
        if (fd < 0)
        {
            throw runtime_error(string_format("Unable to open PF_PACKET socket: %s", strerror(errno)));
        }

        if(!use_qdisc)
        {
            const int optval = 1;
            if(setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, (const void *)&optval , sizeof(optval)) !=0)
            {
                close(fd);
                throw runtime_error(string_format("Unable to set PACKET_QDISC_BYPASS: %s", strerror(errno)));
            }
        }

        struct ifreq ifr;
        memset(&ifr, '\0', sizeof(ifr));
        strncpy(ifr.ifr_name, it->c_str(), sizeof(ifr.ifr_name) - 1);

        if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
        {
            close(fd);
            throw runtime_error(string_format("Unable to get interface index for %s: %s", it->c_str(), strerror(errno)));
        }

        struct sockaddr_ll sll;
        memset(&sll, '\0', sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = 0;

        if (::bind(fd, (struct sockaddr *) &sll, sizeof(sll)) < 0)
        {
            close(fd);
            throw runtime_error(string_format("Unable to bind to %s: %s", it->c_str(), strerror(errno)));
        }

        sockfds.push_back(fd);
        fd_fwmarks[fd] = 0;
    }
}

void RawSocketTransmitter::inject_packet(const uint8_t *buf, size_t size)
{
    assert(size <= MAX_FORWARDER_PACKET_SIZE);
    uint8_t ieee_hdr[sizeof(ieee80211_header)];

    // fill default values
    memcpy(ieee_hdr, ieee80211_header, sizeof(ieee80211_header));

    // frame_type
    ieee_hdr[0] = frame_type;

    // channel_id
    uint32_t channel_id_be = htobe32(channel_id);
    memcpy(ieee_hdr + SRC_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));
    memcpy(ieee_hdr + DST_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));

    // sequence number
    ieee_hdr[FRAME_SEQ_LB] = ieee80211_seq & 0xff;
    ieee_hdr[FRAME_SEQ_HB] = (ieee80211_seq >> 8) & 0xff;
    ieee80211_seq += 16;

    struct iovec iov[3] = \
        {
            // radiotap header
            { .iov_base = (void*)&radiotap_header.header[0],
              .iov_len = radiotap_header.header.size()
            },
            // ieee80211 header
            { .iov_base = (void*)ieee_hdr,
              .iov_len = sizeof(ieee_hdr)
            },
            // packet payload
            { .iov_base = (void*)buf,
              .iov_len = size
            }
        };

    struct msghdr msghdr = \
        { .msg_name = NULL,
          .msg_namelen = 0,
          .msg_iov = iov,
          .msg_iovlen = 3,
          .msg_control = NULL,
          .msg_controllen = 0,
          .msg_flags = 0};

    if (current_output >= 0)
    {
        // Normal mode - only one card do packet transmission in a time
        uint64_t start_us = get_time_us();
        int fd = sockfds[current_output];

        if (use_qdisc && fd_fwmarks[fd] != fwmark)
        {
            uint32_t sockopt = fwmark;

            if(setsockopt(fd, SOL_SOCKET, SO_MARK, (const void *)&sockopt , sizeof(sockopt)) !=0)
            {
                throw runtime_error(string_format("Unable to set SO_MARK fd(%d)=%u: %s", fd, sockopt, strerror(errno)));
            }

            fd_fwmarks[fd] = fwmark;
        }

        int rc = -1;
        for(uint32_t i=0; rc < 0 && i <= inject_retries; i++)
        {
            if (i > 0)
            {
                struct timespec t = {
                    .tv_sec = (time_t)(inject_retry_delay / 1000000),
                    .tv_nsec = (suseconds_t)(inject_retry_delay % 1000000) * 1000
                };

                int rc2 = clock_nanosleep(CLOCK_MONOTONIC, 0, &t, NULL);

                if (rc2 != 0 && rc2 != EINTR)
                {
                    throw runtime_error(string_format("clock_nanosleep: %s", strerror(rc2)));
                }
            }

            rc = sendmsg(fd, &msghdr, 0);

            if (rc < 0 && errno != ENOBUFS)
            {
                throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
            }
        }

        uint64_t key = (uint64_t)(current_output) << 8 | (uint64_t)0xff;
        antenna_stat[key].log_latency(get_time_us() - start_us, rc >= 0, size);
    }
    else
    {
        // Mirror mode - transmit packet via all cards
        // Use only for different frequency channels

        vector<int> rc_vec;
        vector<uint64_t> lat_vec;
        int socks_pending = 0;

        for(auto it=sockfds.begin(); it != sockfds.end(); it++)
        {
            rc_vec.push_back(-1);
            lat_vec.push_back(0);
            socks_pending += 1;
        }

        for(uint32_t i=0; i <= inject_retries && socks_pending > 0; i++)
        {
            if (i > 0)
            {
                struct timespec t = {
                    .tv_sec = (time_t)(inject_retry_delay / 1000000),
                    .tv_nsec = (suseconds_t)(inject_retry_delay % 1000000) * 1000
                };

                int rc = clock_nanosleep(CLOCK_MONOTONIC, 0, &t, NULL);

                if(rc != 0 && rc != EINTR)
                {
                    throw runtime_error(string_format("clock_nanosleep: %s", strerror(rc)));
                }
            }

            int sock_idx = 0;
            for(auto it=sockfds.begin(); it != sockfds.end() && socks_pending > 0; it++, sock_idx++)
            {
                // skip cards that already sent packet
                if (rc_vec[sock_idx] >= 0) continue;

                uint64_t start_us = get_time_us();
                int fd = *it;

                if (use_qdisc && fd_fwmarks[fd] != fwmark)
                {
                    uint32_t sockopt = fwmark;

                    if(setsockopt(fd, SOL_SOCKET, SO_MARK, (const void *)&sockopt , sizeof(sockopt)) != 0)
                    {
                        throw runtime_error(string_format("Unable to set SO_MARK fd(%d)=%u: %s", fd, sockopt, strerror(errno)));
                    }

                    fd_fwmarks[fd] = fwmark;
                }

                rc_vec[sock_idx] = sendmsg(fd, &msghdr, 0);

                if (rc_vec[sock_idx] < 0 && errno != ENOBUFS)
                {
                    throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
                }

                if (rc_vec[sock_idx] >= 0)
                {
                    socks_pending -= 1;
                }

                lat_vec[sock_idx] += (get_time_us() - start_us);

                // log success transmission or if no more retries available
                if (rc_vec[sock_idx] >= 0 || i == inject_retries)
                {
                    uint64_t key = (uint64_t)(sock_idx) << 8 | (uint64_t)0xff;
                    antenna_stat[key].log_latency(lat_vec[sock_idx] + (uint64_t)i * inject_retry_delay,
                                                  rc_vec[sock_idx] >= 0,
                                                  size);
                }
            }
        }
    }

}

void RawSocketTransmitter::dump_stats(uint64_t ts, uint32_t &injected_packets, uint32_t &dropped_packets, uint32_t &injected_bytes, int stream_tag)
{
    for(auto it = antenna_stat.begin(); it != antenna_stat.end(); it++)
    {
        if (stream_tag < 0)
        {
            IPC_MSG("%" PRIu64 "\tTX_ANT\t%" PRIx64 "\t%u:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n",
                    ts, it->first,
                    it->second.count_p_injected, it->second.count_p_dropped,
                    it->second.latency_min,
                    it->second.latency_sum / (it->second.count_p_injected + it->second.count_p_dropped),
                    it->second.latency_max);
        }
        else
        {
            // Multi-stream mode: tag the line with the stream's radio_port.
            // Unknown command tags are ignored by legacy stats parsers.
            IPC_MSG("%" PRIu64 "\tTX_ANT_S\t%d\t%" PRIx64 "\t%u:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n",
                    ts, stream_tag, it->first,
                    it->second.count_p_injected, it->second.count_p_dropped,
                    it->second.latency_min,
                    it->second.latency_sum / (it->second.count_p_injected + it->second.count_p_dropped),
                    it->second.latency_max);
        }

        injected_packets += it->second.count_p_injected;
        dropped_packets += it->second.count_p_dropped;
        injected_bytes += it->second.count_b_injected;
    }
    antenna_stat.clear();
}

RawSocketTransmitter::~RawSocketTransmitter()
{
    for(auto it=sockfds.begin(); it != sockfds.end(); it++)
    {
        close(*it);
    }
}


RemoteTransmitter::RemoteTransmitter(int k, int n, const string &keypair, uint64_t epoch, uint32_t channel_id, uint32_t fec_delay,
                                     vector<tags_item_t> &tags, const vector<pair<string, vector<uint16_t>>> &remote_hosts, radiotap_header_t &radiotap_header,
                                     uint8_t frame_type, bool use_qdisc, uint32_t fwmark_base, int snd_buf_size) : \
    Transmitter(k, n, keypair, epoch, channel_id, fec_delay, tags),
    channel_id(channel_id),
    current_output(0),
    ieee80211_seq(0),
    radiotap_header(radiotap_header),
    frame_type(frame_type),
    use_qdisc(use_qdisc),
    fwmark_base(fwmark_base),
    fwmark(fwmark_base)
{

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) throw std::runtime_error(string_format("Error opening socket: %s", strerror(errno)));

    if (snd_buf_size > 0)
    {
        if(setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const void *)&snd_buf_size , sizeof(snd_buf_size)) !=0)
        {
            close(sockfd);
            throw runtime_error(string_format("Unable to set SO_SNDBUF: %s", strerror(errno)));
        }
    }

    int output = 0;
    for(auto h_it=remote_hosts.begin(); h_it!=remote_hosts.end(); h_it++)
    {
        uint8_t wlan_id = 0;
        for(auto p_it=h_it->second.begin(); p_it != h_it->second.end(); p_it++, output++, wlan_id++)
        {
            struct sockaddr_in saddr;
            memset(&saddr, '\0', sizeof(saddr));
            saddr.sin_family = AF_INET;
            saddr.sin_addr.s_addr = inet_addr(h_it->first.c_str());
            saddr.sin_port = htons((unsigned short)*p_it);
            sockaddrs.push_back(saddr);
            output_to_ant_id[output] = ((uint64_t)ntohl(saddr.sin_addr.s_addr) << 32) | (uint64_t)(wlan_id) << 8 | (uint64_t)0xff;
        }
    }
}

void RemoteTransmitter::inject_packet(const uint8_t *buf, size_t size)
{
    assert(size <= MAX_FORWARDER_PACKET_SIZE);
    uint8_t ieee_hdr[sizeof(ieee80211_header)];

    // fill default values
    memcpy(ieee_hdr, ieee80211_header, sizeof(ieee80211_header));

    // frame_type
    ieee_hdr[0] = frame_type;

    // channel_id
    uint32_t channel_id_be = htobe32(channel_id);
    memcpy(ieee_hdr + SRC_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));
    memcpy(ieee_hdr + DST_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));

    // sequence number
    ieee_hdr[FRAME_SEQ_LB] = ieee80211_seq & 0xff;
    ieee_hdr[FRAME_SEQ_HB] = (ieee80211_seq >> 8) & 0xff;
    ieee80211_seq += 16;

    uint32_t _fwmark = use_qdisc ? htonl(this->fwmark) : 0;

    struct iovec iov[4] = \
        {
            // fwmark
            {
                .iov_base = (void*)&_fwmark,
                .iov_len = sizeof(_fwmark),
            },
            // radiotap header
            { .iov_base = (void*)&radiotap_header.header[0],
              .iov_len = radiotap_header.header.size()
            },
            // ieee80211 header
            { .iov_base = (void*)ieee_hdr,
              .iov_len = sizeof(ieee_hdr)
            },
            // packet payload
            { .iov_base = (void*)buf,
              .iov_len = size
            }
        };

    struct msghdr msghdr = \
        { .msg_name = NULL,
          .msg_namelen = 0,
          .msg_iov = iov,
          .msg_iovlen = 4,
          .msg_control = NULL,
          .msg_controllen = 0,
          .msg_flags = 0};

    struct sockaddr_in saddr;

    if (current_output >= 0)
    {
        // Normal mode - only one card do packet transmission in a time
        uint64_t start_us = get_time_us();

        saddr = sockaddrs[current_output];
        msghdr.msg_name = &saddr;
        msghdr.msg_namelen = sizeof(saddr);

        int rc = sendmsg(sockfd, &msghdr, 0);

        if (rc < 0 && errno != ENOBUFS)
        {
            throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
        }

        uint64_t key = output_to_ant_id[current_output];
        antenna_stat[key].log_latency(get_time_us() - start_us, rc >= 0, size);
    }
    else
    {
        // Mirror mode - transmit packet via all cards
        // Use only for different frequency channels
        int i = 0;
        for(auto it=sockaddrs.begin(); it != sockaddrs.end(); it++, i++)
        {
            uint64_t start_us = get_time_us();

            saddr = *it;
            msghdr.msg_name = &saddr;
            msghdr.msg_namelen = sizeof(saddr);

            int rc = sendmsg(sockfd, &msghdr, 0);

            if (rc < 0 && errno != ENOBUFS)
            {
                throw runtime_error(string_format("Unable to inject packet: %s", strerror(errno)));
            }

            uint64_t key = output_to_ant_id[i];
            antenna_stat[key].log_latency(get_time_us() - start_us, rc >= 0, size);
        }
    }

}

void RemoteTransmitter::dump_stats(uint64_t ts, uint32_t &injected_packets, uint32_t &dropped_packets, uint32_t &injected_bytes, int stream_tag)
{
    for(auto it = antenna_stat.begin(); it != antenna_stat.end(); it++)
    {
        if (stream_tag < 0)
        {
            IPC_MSG("%" PRIu64 "\tTX_ANT\t%" PRIx64 "\t%u:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n",
                    ts, it->first,
                    it->second.count_p_injected, it->second.count_p_dropped,
                    it->second.latency_min,
                    it->second.latency_sum / (it->second.count_p_injected + it->second.count_p_dropped),
                    it->second.latency_max);
        }
        else
        {
            IPC_MSG("%" PRIu64 "\tTX_ANT_S\t%d\t%" PRIx64 "\t%u:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n",
                    ts, stream_tag, it->first,
                    it->second.count_p_injected, it->second.count_p_dropped,
                    it->second.latency_min,
                    it->second.latency_sum / (it->second.count_p_injected + it->second.count_p_dropped),
                    it->second.latency_max);
        }

        injected_packets += it->second.count_p_injected;
        dropped_packets += it->second.count_p_dropped;
        injected_bytes += it->second.count_b_injected;
    }
    antenna_stat.clear();
}



void Transmitter::send_block_fragment(size_t packet_size)
{
    uint8_t ciphertext[MAX_FORWARDER_PACKET_SIZE];
    wblock_hdr_t *block_hdr = (wblock_hdr_t*)ciphertext;
    long long unsigned int ciphertext_len;

    assert(packet_size <= MAX_FEC_PAYLOAD);

    block_hdr->packet_type = WFB_PACKET_DATA;
    block_hdr->data_nonce = htobe64(((block_idx & BLOCK_IDX_MASK) << 8) + fragment_idx);

    // encrypted payload
    if (crypto_aead_chacha20poly1305_encrypt(ciphertext + sizeof(wblock_hdr_t), &ciphertext_len,
                                             block[fragment_idx], packet_size,
                                             (uint8_t*)block_hdr, sizeof(wblock_hdr_t),
                                             NULL, (uint8_t*)(&(block_hdr->data_nonce)), session_key) < 0)
    {
        throw runtime_error("Unable to encrypt packet!");
    }

    inject_packet(ciphertext, sizeof(wblock_hdr_t) + ciphertext_len);
}

void Transmitter::send_session_key(void)
{
    WFB_DBG("Announce session key\n");
    inject_packet((uint8_t*)session_packet, session_packet_size);
}

bool Transmitter::send_packet(const uint8_t *buf, size_t size, uint8_t flags)
{
    assert(size <= MAX_PAYLOAD_SIZE);

    // FEC-only packets are only for closing already opened blocks
    if (fragment_idx == 0 && (flags & WFB_PACKET_FEC_ONLY))
    {
        return false;
    }

    wpacket_hdr_t *packet_hdr = (wpacket_hdr_t*)block[fragment_idx];

    packet_hdr->flags = flags;
    packet_hdr->packet_size = htobe16(size);

    if(size > 0)
    {
        assert(buf != NULL);
        memcpy(block[fragment_idx] + sizeof(wpacket_hdr_t), buf, size);
    }

    memset(block[fragment_idx] + sizeof(wpacket_hdr_t) + size, '\0', MAX_FEC_PAYLOAD - (sizeof(wpacket_hdr_t) + size));

    // mark data packets with fwmark
    if(fragment_idx == 0)
    {
        set_mark(0);
    }

    send_block_fragment(sizeof(wpacket_hdr_t) + size);
    max_packet_size = max(max_packet_size, sizeof(wpacket_hdr_t) + size);
    fragment_idx += 1;

    if (fragment_idx < fec_k)  return true;

    zfex_status_code_t _rc = fec_encode_simd(fec_p, (const uint8_t**)block, block + fec_k, ZFEX_ROUND_UP_SIMD(max_packet_size));
    assert(_rc == ZFEX_SC_OK);

    // mark fec packets with fwmark + 1
    set_mark(1);

    while (fragment_idx < fec_n)
    {
        if(fec_delay > 0)
        {
            struct timespec t = { .tv_sec = (time_t)(fec_delay / 1000000),
                                  .tv_nsec = (suseconds_t)(fec_delay % 1000000) * 1000 };

            int rc = clock_nanosleep(CLOCK_MONOTONIC, 0, &t, NULL);

            if(rc != 0 && rc != EINTR)
            {
                throw runtime_error(string_format("clock_nanosleep: %s", strerror(rc)));
            }
        }

        send_block_fragment(max_packet_size);
        fragment_idx += 1;
    }
    block_idx += 1;
    fragment_idx = 0;
    max_packet_size = 0;

    // Generate new session key after MAX_BLOCK_IDX blocks
    if (block_idx > MAX_BLOCK_IDX)
    {
        init_session(fec_k, fec_n);
        for(int i = 0; i < fec_n - fec_k + 1; i++)
        {
            send_session_key();
        }
    }

    return true;
}

// Extract SO_RXQ_OVFL counter
uint32_t extract_rxq_overflow(struct msghdr *msg)
{
    struct cmsghdr *cmsg;
    uint32_t rtn;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL) {
            memcpy(&rtn, CMSG_DATA(cmsg), sizeof(rtn));
            return rtn;
        }
    }
    return 0;
}

// Resolve a per-stream command target by radio_port, NULL if no stream
// uses that radio_port.
static Transmitter *find_stream_by_radio_port(const vector<Transmitter*> &stream_ts, uint8_t radio_port)
{
    for(auto t : stream_ts)
    {
        if (t->get_radio_port() == radio_port) return t;
    }
    return NULL;
}

// Restart the session of one transmitter with new FEC settings. Shared by
// the legacy CMD_SET_FEC and the per-stream CMD_SET_FEC_STREAM handlers.
static void apply_fec_settings(Transmitter *t, int fec_k, int fec_n)
{
    // Close open FEC block if any
    while(t->send_packet(NULL, 0, WFB_PACKET_FEC_ONLY));

    t->init_session(fec_k, fec_n);

    // Emulate FEC for initial session key distribution
    for(int i = 0; i < fec_n - fec_k + 1; i++)
    {
        t->send_session_key();
    }
}

// Drain and answer all pending control requests on the control socket.
// stream_ts holds one Transmitter per stream; legacy (non-stream) commands
// address stream_ts[0], which is the only stream in single-stream mode.
static void process_control_fd(int fd, const vector<Transmitter*> &stream_ts)
{
    Transmitter *t = stream_ts[0];

    for(;;)
    {
        cmd_req_t req = {};
        cmd_resp_t resp = {};
        ssize_t rsize;
        struct sockaddr_in from_addr;
        socklen_t addr_size = sizeof(from_addr);

        if ((rsize = recvfrom(fd, &req, sizeof(req), MSG_DONTWAIT, (sockaddr*)&from_addr, &addr_size )) < 0 || addr_size > sizeof(from_addr))
        {
            if (errno != EWOULDBLOCK) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
            break;
        }

        if(rsize < (ssize_t)offsetof(cmd_req_t, u)) continue;

        resp.req_id = req.req_id;
        resp.rc = 0;

        switch(req.cmd_id)
        {
        case CMD_SET_FEC:
        {
            if (rsize != offsetof(cmd_req_t, u) + sizeof(req.u.cmd_set_fec))
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                continue;
            }

            int fec_k = req.u.cmd_set_fec.k;
            int fec_n = req.u.cmd_set_fec.n;

            if(!(fec_k <= fec_n && fec_k >=1 && fec_n >= 1 && fec_n < 256))
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                WFB_ERR("Rejecting new FEC settings");
                continue;
            }

            apply_fec_settings(t, fec_k, fec_n);

            sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
            WFB_INFO("Session restarted with FEC %d/%d\n", fec_k, fec_n);
        }
        break;

        case CMD_SET_RADIO:
        {
            if (rsize != offsetof(cmd_req_t, u) + sizeof(req.u.cmd_set_radio))
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                continue;
            }

            try
            {
                auto radiotap_header = init_radiotap_header(req.u.cmd_set_radio.stbc,
                                                            req.u.cmd_set_radio.ldpc,
                                                            req.u.cmd_set_radio.short_gi,
                                                            req.u.cmd_set_radio.bandwidth,
                                                            req.u.cmd_set_radio.mcs_index,
                                                            req.u.cmd_set_radio.vht_mode,
                                                            req.u.cmd_set_radio.vht_nss);
                t->update_radiotap_header(radiotap_header);
            }
            catch(runtime_error &e)
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                WFB_ERR("Rejecting new radiotap header: %s\n", e.what());
                continue;
            }

            sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
            WFB_INFO("Radiotap updated with stbc=%d, ldpc=%d, short_gi=%d, bandwidth=%d, mcs_index=%d, vht_mode=%d, vht_nss=%d\n",
                    req.u.cmd_set_radio.stbc,
                    req.u.cmd_set_radio.ldpc,
                    req.u.cmd_set_radio.short_gi,
                    req.u.cmd_set_radio.bandwidth,
                    req.u.cmd_set_radio.mcs_index,
                    req.u.cmd_set_radio.vht_mode,
                    req.u.cmd_set_radio.vht_nss);
        }
        break;

        case CMD_GET_FEC:
        {
            int fec_k = 0, fec_n = 0;

            if (rsize != offsetof(cmd_req_t, u))
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                continue;
            }

            t->get_fec(fec_k, fec_n);

            resp.u.cmd_get_fec.k = fec_k;
            resp.u.cmd_get_fec.n = fec_n;

            sendto(fd, &resp, offsetof(cmd_resp_t, u) + sizeof(resp.u.cmd_get_fec), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
        }
        break;

        case CMD_GET_RADIO:
        {
            if (rsize != offsetof(cmd_req_t, u))
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                continue;
            }

            radiotap_header_t hdr = t->get_radiotap_header();

            resp.u.cmd_get_radio.stbc = hdr.stbc;
            resp.u.cmd_get_radio.ldpc = hdr.ldpc;
            resp.u.cmd_get_radio.short_gi = hdr.short_gi;
            resp.u.cmd_get_radio.bandwidth = hdr.bandwidth;
            resp.u.cmd_get_radio.mcs_index = hdr.mcs_index;
            resp.u.cmd_get_radio.vht_mode = hdr.vht_mode;
            resp.u.cmd_get_radio.vht_nss = hdr.vht_nss;

            sendto(fd, &resp, offsetof(cmd_resp_t, u) + sizeof(resp.u.cmd_get_radio), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
        }
        break;

        case CMD_SET_FEC_STREAM:
        {
            if (rsize != offsetof(cmd_req_t, u) + sizeof(req.u.cmd_set_fec_stream))
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                continue;
            }

            Transmitter *st = find_stream_by_radio_port(stream_ts, req.u.cmd_set_fec_stream.radio_port);
            int fec_k = req.u.cmd_set_fec_stream.k;
            int fec_n = req.u.cmd_set_fec_stream.n;

            if (st == NULL)
            {
                resp.rc = htonl(ENODEV);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                WFB_ERR("No stream with radio_port %u\n", req.u.cmd_set_fec_stream.radio_port);
                continue;
            }

            if(!(fec_k <= fec_n && fec_k >=1 && fec_n >= 1 && fec_n < 256))
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                WFB_ERR("Rejecting new FEC settings");
                continue;
            }

            apply_fec_settings(st, fec_k, fec_n);

            sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
            WFB_INFO("Stream %u: session restarted with FEC %d/%d\n",
                     req.u.cmd_set_fec_stream.radio_port, fec_k, fec_n);
        }
        break;

        case CMD_SET_RADIO_STREAM:
        {
            if (rsize != offsetof(cmd_req_t, u) + sizeof(req.u.cmd_set_radio_stream))
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                continue;
            }

            Transmitter *st = find_stream_by_radio_port(stream_ts, req.u.cmd_set_radio_stream.radio_port);

            if (st == NULL)
            {
                resp.rc = htonl(ENODEV);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                WFB_ERR("No stream with radio_port %u\n", req.u.cmd_set_radio_stream.radio_port);
                continue;
            }

            try
            {
                auto radiotap_header = init_radiotap_header(req.u.cmd_set_radio_stream.stbc,
                                                            req.u.cmd_set_radio_stream.ldpc,
                                                            req.u.cmd_set_radio_stream.short_gi,
                                                            req.u.cmd_set_radio_stream.bandwidth,
                                                            req.u.cmd_set_radio_stream.mcs_index,
                                                            req.u.cmd_set_radio_stream.vht_mode,
                                                            req.u.cmd_set_radio_stream.vht_nss);
                st->update_radiotap_header(radiotap_header);
            }
            catch(runtime_error &e)
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                WFB_ERR("Rejecting new radiotap header: %s\n", e.what());
                continue;
            }

            sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
            WFB_INFO("Stream %u: radiotap updated with stbc=%d, ldpc=%d, short_gi=%d, bandwidth=%d, mcs_index=%d, vht_mode=%d, vht_nss=%d\n",
                    req.u.cmd_set_radio_stream.radio_port,
                    req.u.cmd_set_radio_stream.stbc,
                    req.u.cmd_set_radio_stream.ldpc,
                    req.u.cmd_set_radio_stream.short_gi,
                    req.u.cmd_set_radio_stream.bandwidth,
                    req.u.cmd_set_radio_stream.mcs_index,
                    req.u.cmd_set_radio_stream.vht_mode,
                    req.u.cmd_set_radio_stream.vht_nss);
        }
        break;

        case CMD_GET_FEC_STREAM:
        {
            int fec_k = 0, fec_n = 0;

            if (rsize != offsetof(cmd_req_t, u) + sizeof(req.u.cmd_get_fec_stream))
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                continue;
            }

            Transmitter *st = find_stream_by_radio_port(stream_ts, req.u.cmd_get_fec_stream.radio_port);

            if (st == NULL)
            {
                resp.rc = htonl(ENODEV);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                continue;
            }

            st->get_fec(fec_k, fec_n);

            resp.u.cmd_get_fec.k = fec_k;
            resp.u.cmd_get_fec.n = fec_n;

            sendto(fd, &resp, offsetof(cmd_resp_t, u) + sizeof(resp.u.cmd_get_fec), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
        }
        break;

        case CMD_GET_RADIO_STREAM:
        {
            if (rsize != offsetof(cmd_req_t, u) + sizeof(req.u.cmd_get_radio_stream))
            {
                resp.rc = htonl(EINVAL);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                continue;
            }

            Transmitter *st = find_stream_by_radio_port(stream_ts, req.u.cmd_get_radio_stream.radio_port);

            if (st == NULL)
            {
                resp.rc = htonl(ENODEV);
                sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
                continue;
            }

            radiotap_header_t hdr = st->get_radiotap_header();

            resp.u.cmd_get_radio.stbc = hdr.stbc;
            resp.u.cmd_get_radio.ldpc = hdr.ldpc;
            resp.u.cmd_get_radio.short_gi = hdr.short_gi;
            resp.u.cmd_get_radio.bandwidth = hdr.bandwidth;
            resp.u.cmd_get_radio.mcs_index = hdr.mcs_index;
            resp.u.cmd_get_radio.vht_mode = hdr.vht_mode;
            resp.u.cmd_get_radio.vht_nss = hdr.vht_nss;

            sendto(fd, &resp, offsetof(cmd_resp_t, u) + sizeof(resp.u.cmd_get_radio), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
        }
        break;

        default:
        {
            resp.rc = htonl(ENOTSUP);
            sendto(fd, &resp, offsetof(cmd_resp_t, u), MSG_DONTWAIT, (sockaddr*)&from_addr, addr_size);
            continue;
        }
        break;
        }
    }
}

void data_source(unique_ptr<Transmitter> &t, vector<int> &rx_fd, int control_fd, int fec_timeout, bool mirror, int log_interval)
{
    int nfds = rx_fd.size();
    assert(nfds > 0);

    struct pollfd fds[nfds + 1];
    memset(fds, '\0', sizeof(fds));

    for(size_t i=0; i < rx_fd.size(); i++)
    {
        fds[i].fd = rx_fd[i];
        fds[i].events = POLLIN;
    }

    fds[nfds].fd = control_fd;
    fds[nfds].events = POLLIN;

    uint64_t session_key_announce_ts = get_time_ms();
    uint32_t rxq_overflow = 0;
    uint64_t log_send_ts = get_time_ms();
    uint64_t fec_close_ts = fec_timeout > 0 ? get_time_ms() + fec_timeout : 0;
    uint32_t count_p_fec_timeouts = 0; // empty packets sent to close fec block due to timeout
    uint32_t count_p_incoming = 0;   // incoming udp packets (received + dropped due to rxq overflow)
    uint32_t count_b_incoming = 0;   // incoming udp bytes (received only)
    uint32_t count_p_injected = 0;  // successfully injected packets (include additional fec packets)
    uint32_t count_b_injected = 0;  // successfully injected bytes (include additional fec packets)
    uint32_t count_p_dropped = 0;   // dropped due to rxq overflows or injection timeout
    uint32_t count_p_truncated = 0; // injected large packets that were truncated
    int start_fd_idx = 0;

    for(;;)
    {
        uint64_t cur_ts = get_time_ms();
        int poll_timeout = log_send_ts > cur_ts ? log_send_ts - cur_ts : 0;

        if (fec_timeout > 0)
        {
            poll_timeout = std::min(poll_timeout, (int)(fec_close_ts > cur_ts ? fec_close_ts - cur_ts : 0));
        }

        int rc = poll(fds, nfds + 1, poll_timeout);

        if (rc < 0)
        {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("poll error: %s", strerror(errno)));
        }

        cur_ts = get_time_ms();

        if (cur_ts >= log_send_ts)  // log timeout expired
        {
            t->dump_stats(cur_ts, count_p_injected, count_p_dropped, count_b_injected, -1);

            IPC_MSG("%" PRIu64 "\tPKT\t%u:%u:%u:%u:%u:%u:%u\n",
                    cur_ts, count_p_fec_timeouts, count_p_incoming, count_b_incoming, count_p_injected, count_b_injected, count_p_dropped, count_p_truncated);
            IPC_MSG_SEND();

            if(count_p_dropped)
            {
                WFB_ERR("%u packets dropped\n", count_p_dropped);
            }

            if(count_p_truncated)
            {
                WFB_ERR("%u packets truncated\n", count_p_truncated);
            }

            count_p_fec_timeouts = 0;
            count_p_incoming = 0;
            count_b_incoming = 0;
            count_p_injected = 0;
            count_b_injected = 0;
            count_p_dropped = 0;
            count_p_truncated = 0;

            log_send_ts = cur_ts + log_interval - ((cur_ts - log_send_ts) % log_interval);
        }

        // Check control socket first
        if (rc > 0 && fds[nfds].revents & (POLLERR | POLLNVAL))
        {
            throw runtime_error(string_format("socket error: %s", strerror(errno)));
        }

        if (rc > 0 && fds[nfds].revents & POLLIN)
        {
            rc -= 1;
            vector<Transmitter*> stream_ts = { t.get() };
            process_control_fd(fds[nfds].fd, stream_ts);
        }

        if (rc == 0) // poll timeout
        {
            // close fec only if no data packets and fec timeout expired
            if (fec_timeout > 0 && cur_ts >= fec_close_ts)
            {
                if(t->send_packet(NULL, 0, WFB_PACKET_FEC_ONLY))
                {
                    count_p_fec_timeouts += 1;
                }
                fec_close_ts = cur_ts + fec_timeout;
            }
            continue;
        }

        // rc > 0: events detected
        // start from last fd index and reset it to zero
        int _tmp = start_fd_idx;
        start_fd_idx = 0;

        for(int i = _tmp; rc > 0; i = (i + 1) % nfds)
        {
            assert(i < nfds);

            if (fds[i].revents & (POLLERR | POLLNVAL))
            {
                throw runtime_error(string_format("socket error: %s", strerror(errno)));
            }

            if (fds[i].revents & POLLIN)
            {
                uint8_t buf[MAX_PAYLOAD_SIZE + 1];
                uint8_t cmsgbuf[CMSG_SPACE(sizeof(uint32_t))];
                rc -= 1;

                t->select_output(mirror ? -1 : (i));

                for(;;)
                {
                    ssize_t rsize;
                    int fd = fds[i].fd;
                    struct iovec iov = { .iov_base = (void*)buf,
                                         .iov_len = sizeof(buf) };

                    struct msghdr msghdr = { .msg_name = NULL,
                                             .msg_namelen = 0,
                                             .msg_iov = &iov,
                                             .msg_iovlen = 1,
                                             .msg_control = &cmsgbuf,
                                             .msg_controllen = sizeof(cmsgbuf),
                                             .msg_flags = 0 };

                    memset(cmsgbuf, '\0', sizeof(cmsgbuf));

                    if ((rsize = recvmsg(fd, &msghdr, MSG_DONTWAIT)) < 0)
                    {
                        if (errno != EWOULDBLOCK) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
                        break;
                    }

                    count_p_incoming += 1;
                    count_b_incoming += rsize;

                    if (rsize > (ssize_t)MAX_PAYLOAD_SIZE)
                    {
                        rsize = MAX_PAYLOAD_SIZE;
                        count_p_truncated += 1;
                    }

                    uint32_t cur_rxq_overflow = extract_rxq_overflow(&msghdr);
                    if (cur_rxq_overflow != rxq_overflow)
                    {
                        // Count dropped packets as possible incoming
                        count_p_dropped += (cur_rxq_overflow - rxq_overflow);
                        count_p_incoming += (cur_rxq_overflow - rxq_overflow);
                        rxq_overflow = cur_rxq_overflow;
                    }

                    cur_ts = get_time_ms();

                    if (cur_ts >= session_key_announce_ts)
                    {
                        // Announce session key
                        t->send_session_key();

                        // Session packet interval is not in fixed grid because
                        // we yield session packets only if there are data packets
                        session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_MSEC;
                    }

                    t->send_packet(buf, rsize, 0);

                    if (cur_ts >= log_send_ts)  // log timeout expired
                    {
                        // Save current index and go to outer loop
                        // We need to transmit all packets from the queue before tx card switch
                        start_fd_idx = i;
                        rc = 0;
                        break;
                    }
                }
            }
        }

        // reset fec timeout if data arrived
        if(fec_timeout > 0)
        {
            fec_close_ts = get_time_ms() + fec_timeout;
        }
    }
}


radiotap_header_t init_radiotap_header(uint8_t stbc,
                                       bool ldpc,
                                       bool short_gi,
                                       uint8_t bandwidth,
                                       uint8_t mcs_index,
                                       bool vht_mode,
                                       uint8_t vht_nss)
{
    radiotap_header_t res = {
        .header = {},
        .stbc = stbc,
        .ldpc = ldpc,
        .short_gi = short_gi,
        .bandwidth = bandwidth,
        .mcs_index = mcs_index,
        .vht_mode = vht_mode,
        .vht_nss = vht_nss,
    };

    if (!vht_mode)
    {
        // Set flags in HT radiotap header
        uint8_t flags = 0;

        switch(bandwidth)
        {
        case 10:
        case 20:
            flags |= IEEE80211_RADIOTAP_MCS_BW_20;
            break;
        case 40:
            flags |= IEEE80211_RADIOTAP_MCS_BW_40;
            break;
        default:
            throw runtime_error(string_format("Unsupported HT bandwidth: %d", bandwidth));
        }

        if (short_gi)
        {
            flags |= IEEE80211_RADIOTAP_MCS_SGI;
        }

        switch(stbc)
        {
        case 0:
            break;
        case 1:
            flags |= (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
            break;
        case 2:
            flags |= (IEEE80211_RADIOTAP_MCS_STBC_2 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
            break;
        case 3:
            flags |= (IEEE80211_RADIOTAP_MCS_STBC_3 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
            break;
        default:
            throw runtime_error(string_format("Unsupported HT STBC type: %d", stbc));
        }

        if (ldpc)
        {
            flags |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
        }

        copy(radiotap_header_ht, radiotap_header_ht + sizeof(radiotap_header_ht), back_inserter(res.header));

        res.header[MCS_FLAGS_OFF] = flags;
        res.header[MCS_IDX_OFF] = mcs_index;
    }
    else
    {
        // Set flags in VHT radiotap header
        uint8_t flags = 0;

        copy(radiotap_header_vht, radiotap_header_vht + sizeof(radiotap_header_vht), back_inserter(res.header));

        if (short_gi)
        {
            flags |= IEEE80211_RADIOTAP_VHT_FLAG_SGI;
        }

        if (stbc)
        {
            flags |= IEEE80211_RADIOTAP_VHT_FLAG_STBC;
        }

        switch(bandwidth)
        {
        case 10:
        case 20:
            res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_20M;
            break;
        case 40:
            res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_40M;
            break;
        case 80:
            res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_80M;
            break;
        case 160:
            res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_160M;
            break;
        default:
            throw runtime_error(string_format("Unsupported VHT bandwidth: %d", bandwidth));
        }

        if (ldpc)
        {
            res.header[VHT_CODING_OFF] = IEEE80211_RADIOTAP_VHT_CODING_LDPC_USER0;
        }

        res.header[VHT_FLAGS_OFF] = flags;
        res.header[VHT_MCSNSS0_OFF] |= ((mcs_index << IEEE80211_RADIOTAP_VHT_MCS_SHIFT) & IEEE80211_RADIOTAP_VHT_MCS_MASK);
        res.header[VHT_MCSNSS0_OFF] |= ((vht_nss << IEEE80211_RADIOTAP_VHT_NSS_SHIFT) & IEEE80211_RADIOTAP_VHT_NSS_MASK);
    }

    return res;
}


void packet_injector(RawSocketInjector &t, vector<int> &rx_fd, int log_interval)
{
    int nfds = rx_fd.size();
    assert(nfds > 0);

    struct pollfd fds[nfds];
    memset(fds, '\0', sizeof(fds));

    for(size_t i=0; i < rx_fd.size(); i++)
    {
        fds[i].fd = rx_fd[i];
        fds[i].events = POLLIN;
    }

    uint32_t rxq_overflow = 0;
    uint64_t log_send_ts = get_time_ms();

    uint32_t count_p_incoming = 0;   // incoming udp packets (received + dropped due to rxq overflow)
    uint32_t count_b_incoming = 0;   // incoming udp bytes (received only)
    uint32_t count_p_dropped = 0;   // dropped due to rxq overflows or injection timeout
    uint32_t count_p_bad = 0; // injected large packets that were bad

    int start_fd_idx = 0;

    for(;;)
    {
        uint64_t cur_ts = get_time_ms();
        int poll_timeout = log_send_ts > cur_ts ? log_send_ts - cur_ts : 0;
        int rc = poll(fds, nfds, poll_timeout);

        if (rc < 0)
        {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("poll error: %s", strerror(errno)));
        }

        cur_ts = get_time_ms();

        if (cur_ts >= log_send_ts)  // log timeout expired
        {
            if(count_p_dropped)
            {
                WFB_ERR("%u packets dropped\n", count_p_dropped);
            }

            if(count_p_bad)
            {
                WFB_ERR("%u packets bad\n", count_p_bad);
            }

            count_p_incoming = 0;
            count_b_incoming = 0;
            count_p_dropped = 0;
            count_p_bad = 0;

            log_send_ts = cur_ts + log_interval - ((cur_ts - log_send_ts) % log_interval);
        }

        if (rc == 0) // poll timeout
        {
            continue;
        }

        // rc > 0: events detected
        // start from last fd index and reset it to zero
        int _tmp = start_fd_idx;
        start_fd_idx = 0;

        for(int i = _tmp; rc > 0; i = (i + 1) % nfds)
        {
            assert(i < nfds);

            if (fds[i].revents & (POLLERR | POLLNVAL))
            {
                throw runtime_error(string_format("socket error: %s", strerror(errno)));
            }

            if (fds[i].revents & POLLIN)
            {
                uint8_t buf[MAX_DISTRIBUTION_PACKET_SIZE - sizeof(uint32_t) + 1];
                uint8_t cmsgbuf[CMSG_SPACE(sizeof(uint32_t))];
                rc -= 1;

                for(;;)
                {
                    ssize_t rsize;
                    uint32_t _fwmark;
                    int fd = fds[i].fd;

                    struct iovec iov[2] = {
                        // fwmark
                        {
                            .iov_base = (void*)&_fwmark,
                            .iov_len = sizeof(_fwmark),
                        },
                        // packet with radiotap header
                        {
                            .iov_base = (void*)buf,
                            .iov_len = sizeof(buf),
                        }
                    };

                    struct msghdr msghdr = { .msg_name = NULL,
                                             .msg_namelen = 0,
                                             .msg_iov = iov,
                                             .msg_iovlen = 2,
                                             .msg_control = &cmsgbuf,
                                             .msg_controllen = sizeof(cmsgbuf),
                                             .msg_flags = 0 };

                    memset(cmsgbuf, '\0', sizeof(cmsgbuf));

                    if ((rsize = recvmsg(fd, &msghdr, MSG_DONTWAIT)) < 0)
                    {
                        if (errno != EWOULDBLOCK) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
                        break;
                    }

                    if (rsize < (ssize_t)MIN_DISTRIBUTION_PACKET_SIZE || rsize > (ssize_t)MAX_DISTRIBUTION_PACKET_SIZE)
                    {
                        count_p_bad += 1;
                        continue;
                    }

                    rsize -= sizeof(uint32_t);
                    count_p_incoming += 1;
                    count_b_incoming += rsize;

                    uint32_t cur_rxq_overflow = extract_rxq_overflow(&msghdr);
                    if (cur_rxq_overflow != rxq_overflow)
                    {
                        // Count dropped packets as possible incoming
                        count_p_dropped += (cur_rxq_overflow - rxq_overflow);
                        count_p_incoming += (cur_rxq_overflow - rxq_overflow);
                        rxq_overflow = cur_rxq_overflow;
                    }

                    cur_ts = get_time_ms();

                    t.inject_packet(i, buf, rsize, ntohl(_fwmark));

                    if (cur_ts >= log_send_ts)  // log timeout expired
                    {
                        // Save current index and go to outer loop
                        // We need to transmit all packets from the queue before tx card switch
                        start_fd_idx = i;
                        rc = 0;
                        break;
                    }
                }
            }
        }
    }
}

void injector_loop(int argc, char* const* argv, int optind, int srv_port, int rcv_buf, bool use_qdisc, int log_interval)
{
    vector<int> rx_fd;
    vector<string> wlans;
    for(int i = 0; optind + i < argc; i++)
    {
        int bind_port = srv_port != 0 ? srv_port + i : 0;
        int fd = open_udp_socket_for_rx(bind_port, rcv_buf);

        if (srv_port == 0)
        {
            struct sockaddr_in saddr;
            socklen_t saddr_size = sizeof(saddr);

            if (getsockname(fd, (struct sockaddr *)&saddr, &saddr_size) != 0)
            {
                throw runtime_error(string_format("Unable to get socket info: %s", strerror(errno)));
            }
            bind_port = ntohs(saddr.sin_port);
            IPC_MSG("%" PRIu64 "\tLISTEN_UDP\t%d:%x\n", get_time_ms(), bind_port, i);
        }
        WFB_INFO("Listen on %d for %s\n", bind_port, argv[optind + i]);
        rx_fd.push_back(fd);
        wlans.push_back(string(argv[optind + i]));
    }

    if (srv_port == 0)
    {
        IPC_MSG("%" PRIu64 "\tLISTEN_UDP_END\n", get_time_ms());
        IPC_MSG_SEND();
    }

    auto t = RawSocketInjector(wlans, use_qdisc);
    packet_injector(t, rx_fd, log_interval);
}


int open_control_fd(int control_port)
{
    int control_fd = open_udp_socket_for_rx(control_port, 0, 0x7f000001);  // bind to 127.0.0.1 for security reasons

    if (control_port == 0)
    {
        struct sockaddr_in saddr;
        socklen_t saddr_size = sizeof(saddr);

        if (getsockname(control_fd, (struct sockaddr *)&saddr, &saddr_size) != 0)
        {
            throw runtime_error(string_format("Unable to get socket info: %s", strerror(errno)));
        }
        control_port = ntohs(saddr.sin_port);
        IPC_MSG("%" PRIu64 "\tLISTEN_UDP_CONTROL\t%d\n", get_time_ms(), control_port);
    }

    WFB_INFO("Listen on %d for management commands\n", control_port);
    return control_fd;
}

void local_loop_udp(int argc, char* const* argv, int optind, int rcv_buf, int log_interval,
                    int udp_port, int debug_port, int k, int n, const string &keypair, int fec_timeout,
                    uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, bool use_qdisc, uint32_t fwmark,
                    radiotap_header_t &radiotap_header, uint8_t frame_type, int control_port, bool mirror,
                    int snd_buf_size, uint32_t inject_retries, uint32_t inject_retry_delay)
{
    vector<int> rx_fd;
    vector<string> wlans;
    vector<tags_item_t> tags;
    unique_ptr<Transmitter> t;

    for(int i = 0; optind + i < argc; i++)
    {
        int bind_port = udp_port != 0 ? udp_port + i : 0;
        int fd = open_udp_socket_for_rx(bind_port, rcv_buf);

        if (udp_port == 0)
        {
            struct sockaddr_in saddr;
            socklen_t saddr_size = sizeof(saddr);

            if (getsockname(fd, (struct sockaddr *)&saddr, &saddr_size) != 0)
            {
                throw runtime_error(string_format("Unable to get socket info: %s", strerror(errno)));
            }
            bind_port = ntohs(saddr.sin_port);
            IPC_MSG("%" PRIu64 "\tLISTEN_UDP\t%d:%x\n", get_time_ms(), bind_port, i);
        }

        WFB_INFO("Listen on %d for %s\n", bind_port, argv[optind + i]);
        rx_fd.push_back(fd);
        wlans.push_back(string(argv[optind + i]));
    }

    if (udp_port == 0)
    {
        IPC_MSG("%" PRIu64 "\tLISTEN_UDP_END\n", get_time_ms());
        IPC_MSG_SEND();
    }

    if (debug_port)
    {
        WFB_INFO("Using %zu ports from %d for wlan emulation\n", wlans.size(), debug_port);
        t = unique_ptr<UdpTransmitter>(new UdpTransmitter(k, n, keypair, "127.0.0.1", debug_port, epoch, channel_id,
                                                          fec_delay, tags, use_qdisc, fwmark, snd_buf_size));
    }
    else
    {
        t = unique_ptr<RawSocketTransmitter>(new RawSocketTransmitter(k, n, keypair, epoch, channel_id, fec_delay, tags,
                                                                      wlans, radiotap_header, frame_type, use_qdisc, fwmark,
                                                                      inject_retries, inject_retry_delay));
    }

    int control_fd = open_control_fd(control_port);
    data_source(t, rx_fd, control_fd, fec_timeout, mirror, log_interval);
}

void local_loop_unix(int argc, char* const* argv, int optind, int rcv_buf, int log_interval,
                     const char *unix_socket, int debug_port, int k, int n, const string &keypair, int fec_timeout,
                     uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, bool use_qdisc, uint32_t fwmark,
                     radiotap_header_t &radiotap_header, uint8_t frame_type, int control_port, bool mirror,
                     int snd_buf_size, uint32_t inject_retries, uint32_t inject_retry_delay)
{
    vector<int> rx_fd;
    vector<string> wlans;
    vector<tags_item_t> tags;
    unique_ptr<Transmitter> t;

    for(int i = 0; optind + i < argc; i++)
    {
        char* wlan = argv[optind + i];
        string tmp = i > 0 ? string_format("%s-%d", unix_socket, i) : string(unix_socket);
        int fd = open_unix_socket_for_rx(tmp.c_str(), rcv_buf);

        IPC_MSG("%" PRIu64 "\tLISTEN_UNIX\t%s:%x\n", get_time_ms(), tmp.c_str(), i);
        WFB_INFO("Listen on @%s for %s\n", tmp.c_str(), wlan);

        rx_fd.push_back(fd);
        wlans.push_back(string(wlan));
    }

    IPC_MSG("%" PRIu64 "\tLISTEN_UNIX_END\n", get_time_ms());
    IPC_MSG_SEND();

    if (debug_port)
    {
        WFB_INFO("Using %zu ports from %d for wlan emulation\n", wlans.size(), debug_port);
        t = unique_ptr<UdpTransmitter>(new UdpTransmitter(k, n, keypair, "127.0.0.1", debug_port, epoch, channel_id,
                                                          fec_delay, tags, use_qdisc, fwmark, snd_buf_size));
    }
    else
    {
        t = unique_ptr<RawSocketTransmitter>(new RawSocketTransmitter(k, n, keypair, epoch, channel_id, fec_delay, tags,
                                                                      wlans, radiotap_header, frame_type, use_qdisc, fwmark,
                                                                      inject_retries, inject_retry_delay));
    }

    int control_fd = open_control_fd(control_port);
    data_source(t, rx_fd, control_fd, fec_timeout, mirror, log_interval);
}


// Parse one "-y key=val,..." stream spec. Unset numeric fields stay -1
// and inherit the corresponding global option at stream creation time.
stream_spec_t parse_stream_spec(const char *arg)
{
    stream_spec_t spec;

    spec.udp_port = -1;
    spec.radio_port = -1;
    spec.k = -1;
    spec.n = -1;
    spec.fec_timeout = -1;
    spec.fec_delay = -1;
    spec.mcs_index = -1;
    spec.bandwidth = -1;
    spec.short_gi = -1;
    spec.stbc = -1;
    spec.ldpc = -1;
    spec.vht_mode = -1;
    spec.vht_nss = -1;

    char *tmp = strdup(arg);
    if (tmp == NULL)
    {
        throw runtime_error("strdup failed");
    }

    try
    {
        char *cursor = tmp;
        char *item;

        while ((item = strsep(&cursor, ",")) != NULL)
        {
            if (item[0] == '\0') continue;

            char *value = item;
            char *key = strsep(&value, "=");

            if (value == NULL || value[0] == '\0')
            {
                throw runtime_error(string_format("Stream spec item without value: %s", item));
            }

            if (strcmp(key, "u") == 0)             spec.udp_port = atoi(value);
            else if (strcmp(key, "shm") == 0)      spec.shm_name = string(value);
            else if (strcmp(key, "p") == 0)        spec.radio_port = atoi(value);
            else if (strcmp(key, "k") == 0)        spec.k = atoi(value);
            else if (strcmp(key, "n") == 0)        spec.n = atoi(value);
            else if (strcmp(key, "T") == 0)        spec.fec_timeout = atoi(value);
            else if (strcmp(key, "F") == 0)        spec.fec_delay = atoll(value);
            else if (strcmp(key, "mcs") == 0)      spec.mcs_index = atoi(value);
            else if (strcmp(key, "bw") == 0)       spec.bandwidth = atoi(value);
            else if (strcmp(key, "gi") == 0)       spec.short_gi = (value[0] == 's' || value[0] == 'S') ? 1 : 0;
            else if (strcmp(key, "stbc") == 0)     spec.stbc = atoi(value);
            else if (strcmp(key, "ldpc") == 0)     spec.ldpc = atoi(value);
            else if (strcmp(key, "vht") == 0)      spec.vht_mode = atoi(value);
            else if (strcmp(key, "nss") == 0)      spec.vht_nss = atoi(value);
            else
            {
                throw runtime_error(string_format("Unknown stream spec key: %s", key));
            }
        }
    }
    catch(...)
    {
        free(tmp);
        throw;
    }

    free(tmp);

    if (spec.radio_port < 0 || spec.radio_port > 255)
    {
        throw runtime_error(string_format("Stream spec needs p=<radio_port> in [0, 255]: %s", arg));
    }

    if ((spec.udp_port > 0) == !spec.shm_name.empty())
    {
        throw runtime_error(string_format("Stream spec needs exactly one input: u=<udp_port> or shm=<ring_name>: %s", arg));
    }

    return spec;
}

void validate_stream_specs(const vector<stream_spec_t> &specs)
{
    if (specs.size() > MAX_TX_STREAMS)
    {
        throw runtime_error(string_format("Too many streams: %zu > %d", specs.size(), MAX_TX_STREAMS));
    }

    for(size_t i = 0; i < specs.size(); i++)
    {
        for(size_t j = i + 1; j < specs.size(); j++)
        {
            if (specs[i].radio_port == specs[j].radio_port)
            {
                throw runtime_error(string_format("Duplicate radio_port %d in stream specs", specs[i].radio_port));
            }

            if (specs[i].udp_port > 0 && specs[i].udp_port == specs[j].udp_port)
            {
                throw runtime_error(string_format("Duplicate udp_port %d in stream specs", specs[i].udp_port));
            }
        }
    }
}

// Per-stream runtime state for the multi-stream data source.
typedef struct {
    unique_ptr<Transmitter> t;
    int rx_fd;
    int fec_timeout;                     // [ms], 0 = disabled
    uint64_t fec_close_ts;               // 0 = no pending close
    uint64_t session_key_announce_ts;
    uint32_t rxq_overflow;

    // per-stream counters, reset each log interval
    uint32_t count_p_fec_timeouts;
    uint32_t count_p_incoming;
    uint32_t count_b_incoming;
    uint32_t count_p_injected;
    uint32_t count_b_injected;
    uint32_t count_p_dropped;
    uint32_t count_p_truncated;
} tx_stream_t;

// Multi-stream event loop. Stream order is strict drain priority:
// on every wakeup ready inputs are serviced lowest-index-first and
// drained fully, so when the radio (or its qdisc) saturates, the
// kernel socket buffers of later streams overflow first. That is the
// intended unequal-protection behavior for layered video: the base
// layer is configured as stream 0 and keeps flowing while droppable
// enhancement streams shed load.
void multi_stream_data_source(vector<tx_stream_t> &streams, int control_fd, bool mirror, int log_interval)
{
    int nfds = streams.size();
    assert(nfds > 0);

    struct pollfd fds[nfds + 1];
    memset(fds, '\0', sizeof(fds));

    for(int i = 0; i < nfds; i++)
    {
        fds[i].fd = streams[i].rx_fd;
        fds[i].events = POLLIN;
    }

    fds[nfds].fd = control_fd;
    fds[nfds].events = POLLIN;

    vector<Transmitter*> stream_ts;
    for(auto &s : streams)
    {
        stream_ts.push_back(s.t.get());
    }

    uint64_t log_send_ts = get_time_ms();

    for(auto &s : streams)
    {
        s.session_key_announce_ts = log_send_ts;
        s.fec_close_ts = s.fec_timeout > 0 ? log_send_ts + s.fec_timeout : 0;
    }

    for(;;)
    {
        uint64_t cur_ts = get_time_ms();
        int poll_timeout = log_send_ts > cur_ts ? log_send_ts - cur_ts : 0;

        for(auto &s : streams)
        {
            if (s.fec_timeout > 0)
            {
                poll_timeout = std::min(poll_timeout, (int)(s.fec_close_ts > cur_ts ? s.fec_close_ts - cur_ts : 0));
            }
        }

        int rc = poll(fds, nfds + 1, poll_timeout);

        if (rc < 0)
        {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw runtime_error(string_format("poll error: %s", strerror(errno)));
        }

        cur_ts = get_time_ms();

        if (cur_ts >= log_send_ts)  // log timeout expired
        {
            uint32_t agg_fec_timeouts = 0, agg_p_incoming = 0, agg_b_incoming = 0;
            uint32_t agg_p_injected = 0, agg_b_injected = 0, agg_p_dropped = 0, agg_p_truncated = 0;

            for(auto &s : streams)
            {
                int stream_tag = s.t->get_radio_port();

                s.t->dump_stats(cur_ts, s.count_p_injected, s.count_p_dropped, s.count_b_injected, stream_tag);

                IPC_MSG("%" PRIu64 "\tPKT_S\t%d\t%u:%u:%u:%u:%u:%u:%u\n",
                        cur_ts, stream_tag, s.count_p_fec_timeouts, s.count_p_incoming, s.count_b_incoming,
                        s.count_p_injected, s.count_b_injected, s.count_p_dropped, s.count_p_truncated);

                agg_fec_timeouts += s.count_p_fec_timeouts;
                agg_p_incoming += s.count_p_incoming;
                agg_b_incoming += s.count_b_incoming;
                agg_p_injected += s.count_p_injected;
                agg_b_injected += s.count_b_injected;
                agg_p_dropped += s.count_p_dropped;
                agg_p_truncated += s.count_p_truncated;

                if(s.count_p_dropped)
                {
                    WFB_ERR("stream %d: %u packets dropped\n", stream_tag, s.count_p_dropped);
                }

                if(s.count_p_truncated)
                {
                    WFB_ERR("stream %d: %u packets truncated\n", stream_tag, s.count_p_truncated);
                }

                s.count_p_fec_timeouts = 0;
                s.count_p_incoming = 0;
                s.count_b_incoming = 0;
                s.count_p_injected = 0;
                s.count_b_injected = 0;
                s.count_p_dropped = 0;
                s.count_p_truncated = 0;
            }

            // Aggregate line keeps the legacy stats consumers working
            IPC_MSG("%" PRIu64 "\tPKT\t%u:%u:%u:%u:%u:%u:%u\n",
                    cur_ts, agg_fec_timeouts, agg_p_incoming, agg_b_incoming,
                    agg_p_injected, agg_b_injected, agg_p_dropped, agg_p_truncated);
            IPC_MSG_SEND();

            log_send_ts = cur_ts + log_interval - ((cur_ts - log_send_ts) % log_interval);
        }

        // Close timed-out FEC blocks per stream. A busy stream pushes
        // only its own fec_close_ts forward, so an idle stream still
        // flushes its open block on time.
        for(auto &s : streams)
        {
            if (s.fec_timeout > 0 && cur_ts >= s.fec_close_ts)
            {
                if(s.t->send_packet(NULL, 0, WFB_PACKET_FEC_ONLY))
                {
                    s.count_p_fec_timeouts += 1;
                }
                s.fec_close_ts = cur_ts + s.fec_timeout;
            }
        }

        if (rc == 0) continue;  // poll timeout, no events

        // Check control socket
        if (fds[nfds].revents & (POLLERR | POLLNVAL))
        {
            throw runtime_error(string_format("socket error: %s", strerror(errno)));
        }

        if (fds[nfds].revents & POLLIN)
        {
            rc -= 1;
            process_control_fd(fds[nfds].fd, stream_ts);
        }

        // Strict priority drain: lowest stream index first, drained fully.
        for(int i = 0; i < nfds && rc > 0; i++)
        {
            if (fds[i].revents & (POLLERR | POLLNVAL))
            {
                throw runtime_error(string_format("socket error: %s", strerror(errno)));
            }

            if (!(fds[i].revents & POLLIN)) continue;

            rc -= 1;

            tx_stream_t &s = streams[i];
            uint8_t buf[MAX_PAYLOAD_SIZE + 1];
            uint8_t cmsgbuf[CMSG_SPACE(sizeof(uint32_t))];

            s.t->select_output(mirror ? -1 : 0);

            for(;;)
            {
                ssize_t rsize;
                struct iovec iov = { .iov_base = (void*)buf,
                                     .iov_len = sizeof(buf) };

                struct msghdr msghdr = { .msg_name = NULL,
                                         .msg_namelen = 0,
                                         .msg_iov = &iov,
                                         .msg_iovlen = 1,
                                         .msg_control = &cmsgbuf,
                                         .msg_controllen = sizeof(cmsgbuf),
                                         .msg_flags = 0 };

                memset(cmsgbuf, '\0', sizeof(cmsgbuf));

                if ((rsize = recvmsg(s.rx_fd, &msghdr, MSG_DONTWAIT)) < 0)
                {
                    if (errno != EWOULDBLOCK) throw runtime_error(string_format("Error receiving packet: %s", strerror(errno)));
                    break;
                }

                s.count_p_incoming += 1;
                s.count_b_incoming += rsize;

                if (rsize > (ssize_t)MAX_PAYLOAD_SIZE)
                {
                    rsize = MAX_PAYLOAD_SIZE;
                    s.count_p_truncated += 1;
                }

                uint32_t cur_rxq_overflow = extract_rxq_overflow(&msghdr);
                if (cur_rxq_overflow != s.rxq_overflow)
                {
                    // Count dropped packets as possible incoming
                    s.count_p_dropped += (cur_rxq_overflow - s.rxq_overflow);
                    s.count_p_incoming += (cur_rxq_overflow - s.rxq_overflow);
                    s.rxq_overflow = cur_rxq_overflow;
                }

                cur_ts = get_time_ms();

                if (cur_ts >= s.session_key_announce_ts)
                {
                    // Announce session key
                    s.t->send_session_key();

                    // Session packet interval is not in fixed grid because
                    // we yield session packets only if there are data packets
                    s.session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_MSEC;
                }

                s.t->send_packet(buf, rsize, 0);

                if (cur_ts >= log_send_ts)  // log timeout expired
                {
                    // Leave the drain; stats run on the next iteration and
                    // strict priority restarts from stream 0 anyway.
                    rc = 0;
                    break;
                }
            }

            // reset fec timeout because data arrived on this stream
            if (s.fec_timeout > 0)
            {
                s.fec_close_ts = get_time_ms() + s.fec_timeout;
            }
        }
    }
}

// SHM ring reader thread context (waybeam venc_ring input).
typedef struct {
    string ring_name;
    int write_fd;       // our end of the socketpair, packets forwarded here
    int radio_port;     // for log messages only
} shm_reader_ctx_t;

// Forward packets from a waybeam venc_ring SHM ring into the socketpair
// consumed by multi_stream_data_source(). The ring is single-consumer,
// so this thread is its only reader; all Transmitter state stays owned
// by the main loop. The producer (waybeam) recreates the ring on respawn
// with a new epoch — on read timeouts we probe the shm name and migrate
// to the new ring when the epoch changes. A blocking write into the
// socketpair gives natural backpressure: if the main loop falls behind,
// the ring fills and the producer accounts drops on its side.
static void *shm_reader_loop(void *arg)
{
    shm_reader_ctx_t *ctx = (shm_reader_ctx_t*)arg;
    venc_ring_t *ring = NULL;
    uint8_t buf[65535];
    bool announced_wait = false;

    for(;;)
    {
        if (ring == NULL)
        {
            ring = venc_ring_attach(ctx->ring_name.c_str());

            if (ring == NULL)
            {
                if (!announced_wait)
                {
                    WFB_INFO("Stream %d: waiting for shm ring %s\n", ctx->radio_port, ctx->ring_name.c_str());
                    announced_wait = true;
                }
                usleep(500000);
                continue;
            }

            WFB_INFO("Stream %d: attached to shm ring %s (epoch=%u)\n",
                     ctx->radio_port, ctx->ring_name.c_str(), ring->hdr->epoch);
            announced_wait = false;
        }

        uint16_t len = 0;

        if (venc_ring_read_wait(ring, buf, sizeof(buf), &len, 500) == 0)
        {
            if (len > 0 && write(ctx->write_fd, buf, len) < 0)
            {
                WFB_ERR("Stream %d: shm forward failed: %s\n", ctx->radio_port, strerror(errno));
            }
            continue;
        }

        // Read timeout: probe for a producer respawn. waybeam unlinks and
        // recreates the ring, so a fresh attach lands on the new inode
        // while our old mapping points at the orphaned one.
        venc_ring_t *fresh = venc_ring_attach(ctx->ring_name.c_str());

        if (fresh == NULL)
        {
            continue;  // producer gone, keep the old mapping and retry
        }

        if (fresh->hdr->epoch != ring->hdr->epoch)
        {
            WFB_INFO("Stream %d: shm ring %s recreated (epoch %u -> %u), re-attached\n",
                     ctx->radio_port, ctx->ring_name.c_str(), ring->hdr->epoch, fresh->hdr->epoch);
            venc_ring_destroy(ring);
            ring = fresh;
        }
        else
        {
            venc_ring_destroy(fresh);
        }
    }

    return NULL;
}

// Create the socketpair + detached reader thread for one shm= stream and
// return the fd the main loop should poll.
static int start_shm_reader(const string &ring_name, int radio_port)
{
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
    {
        throw runtime_error(string_format("Unable to create socketpair: %s", strerror(errno)));
    }

    shm_reader_ctx_t *ctx = new shm_reader_ctx_t();
    ctx->ring_name = ring_name;
    ctx->write_fd = sv[1];
    ctx->radio_port = radio_port;

    pthread_t tid;
    int rc = pthread_create(&tid, NULL, shm_reader_loop, ctx);

    if (rc != 0)
    {
        close(sv[0]);
        close(sv[1]);
        delete ctx;
        throw runtime_error(string_format("Unable to start shm reader thread: %s", strerror(rc)));
    }

    pthread_detach(tid);
    return sv[0];
}

void local_loop_multi(int argc, char* const* argv, int optind, int rcv_buf, int log_interval,
                      const vector<stream_spec_t> &specs, int debug_port, int k, int n, const string &keypair,
                      int fec_timeout, uint64_t epoch, uint32_t link_id, uint32_t fec_delay, bool use_qdisc,
                      uint32_t fwmark, int stbc, int ldpc, int short_gi, int bandwidth, int mcs_index,
                      bool vht_mode, int vht_nss, uint8_t frame_type, int control_port, bool mirror,
                      int snd_buf_size, uint32_t inject_retries, uint32_t inject_retry_delay)
{
    vector<string> wlans;
    vector<tx_stream_t> streams(specs.size());

    for(int i = 0; optind + i < argc; i++)
    {
        wlans.push_back(string(argv[optind + i]));
    }

    for(size_t i = 0; i < specs.size(); i++)
    {
        const stream_spec_t &spec = specs[i];
        tx_stream_t &s = streams[i];
        vector<tags_item_t> tags;

        uint32_t channel_id = (link_id << 8) + spec.radio_port;
        int stream_k = spec.k >= 0 ? spec.k : k;
        int stream_n = spec.n >= 0 ? spec.n : n;
        uint32_t stream_fec_delay = spec.fec_delay >= 0 ? (uint32_t)spec.fec_delay : fec_delay;

        if (!(stream_k <= stream_n && stream_k >= 1 && stream_n >= 1 && stream_n < 256))
        {
            throw runtime_error(string_format("Invalid FEC %d/%d for stream %d", stream_k, stream_n, spec.radio_port));
        }

        s.fec_timeout = spec.fec_timeout >= 0 ? spec.fec_timeout : fec_timeout;
        s.rxq_overflow = 0;
        s.count_p_fec_timeouts = 0;
        s.count_p_incoming = 0;
        s.count_b_incoming = 0;
        s.count_p_injected = 0;
        s.count_b_injected = 0;
        s.count_p_dropped = 0;
        s.count_p_truncated = 0;

        if (!spec.shm_name.empty())
        {
            s.rx_fd = start_shm_reader(spec.shm_name, spec.radio_port);
            WFB_INFO("Stream %d: shm ring %s, FEC %d/%d, priority %zu\n",
                     spec.radio_port, spec.shm_name.c_str(), stream_k, stream_n, i);
        }
        else
        {
            s.rx_fd = open_udp_socket_for_rx(spec.udp_port, rcv_buf);
            WFB_INFO("Stream %d: listen on %d, FEC %d/%d, priority %zu\n",
                     spec.radio_port, spec.udp_port, stream_k, stream_n, i);
        }

        if (debug_port)
        {
            // Stream i gets its own debug port range so emulated wlan
            // packets stay per-stream: port = debug_port + i*W + wlan_idx
            int stream_debug_base = debug_port + (int)(i * wlans.size());
            s.t = unique_ptr<UdpTransmitter>(new UdpTransmitter(stream_k, stream_n, keypair, "127.0.0.1", stream_debug_base,
                                                                epoch, channel_id, stream_fec_delay, tags, use_qdisc, fwmark,
                                                                snd_buf_size));
        }
        else
        {
            auto stream_radiotap_header = init_radiotap_header(
                spec.stbc >= 0 ? spec.stbc : stbc,
                spec.ldpc >= 0 ? (spec.ldpc != 0) : (ldpc != 0),
                spec.short_gi >= 0 ? (spec.short_gi != 0) : (short_gi != 0),
                spec.bandwidth >= 0 ? spec.bandwidth : bandwidth,
                spec.mcs_index >= 0 ? spec.mcs_index : mcs_index,
                spec.vht_mode >= 0 ? (spec.vht_mode != 0) : (vht_mode || spec.bandwidth >= 80),
                spec.vht_nss >= 0 ? spec.vht_nss : vht_nss);

            s.t = unique_ptr<RawSocketTransmitter>(new RawSocketTransmitter(stream_k, stream_n, keypair, epoch, channel_id,
                                                                            stream_fec_delay, tags, wlans, stream_radiotap_header,
                                                                            frame_type, use_qdisc, fwmark,
                                                                            inject_retries, inject_retry_delay));
        }
    }

    if (debug_port)
    {
        WFB_INFO("Using %zu ports from %d for wlan emulation (%zu per stream)\n",
                 wlans.size() * specs.size(), debug_port, wlans.size());
    }

    int control_fd = open_control_fd(control_port);
    multi_stream_data_source(streams, control_fd, mirror, log_interval);
}


void distributor_loop(int argc, char* const* argv, int optind, int rcv_buf, int log_interval,
                      int udp_port, int k, int n, const string &keypair, int fec_timeout,
                      uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, bool use_qdisc, uint32_t fwmark,
                      radiotap_header_t &radiotap_header, uint8_t frame_type, int control_port, bool mirror,
                      int snd_buf_size)
{
    vector<int> rx_fd;
    vector<pair<string, vector<uint16_t>>> remote_hosts;
    int port_idx = 0;

    set<string> hosts;

    for(int i = optind; i < argc; i++)
    {
        vector<uint16_t> remote_ports;
        char *p = argv[i];
        char *t = NULL;

        t = strsep(&p, ":");
        if (t == NULL) continue;

        string remote_host = string(t);

        if(hosts.count(remote_host))
        {
            throw runtime_error(string_format("Duplicate host %s", remote_host.c_str()));
        }

        hosts.insert(remote_host);

        for(int j=0; (t=strsep(&p, ",")) != NULL; j++)
        {
            uint16_t remote_port = atoi(t);
            int bind_port = (udp_port != 0) ? (udp_port + port_idx++) : 0;
            int fd = open_udp_socket_for_rx(bind_port, rcv_buf);

            if (udp_port == 0)
            {
                struct sockaddr_in saddr;
                socklen_t saddr_size = sizeof(saddr);

                if (getsockname(fd, (struct sockaddr *)&saddr, &saddr_size) != 0)
                {
                    throw runtime_error(string_format("Unable to get socket info: %s", strerror(errno)));
                }
                bind_port = ntohs(saddr.sin_port);

                uint64_t wlan_id = (uint64_t)ntohl(inet_addr(remote_host.c_str())) << 24  | j;
                IPC_MSG("%" PRIu64 "\tLISTEN_UDP\t%d:%" PRIx64 "\n", get_time_ms(), bind_port, wlan_id);
            }

            WFB_INFO("Listen on %d for %s:%d\n", bind_port, remote_host.c_str(), remote_port);

            rx_fd.push_back(fd);
            remote_ports.push_back(remote_port);
        }

        remote_hosts.push_back(pair<string, vector<uint16_t>>(remote_host, remote_ports));
    }

    if (udp_port == 0)
    {
        IPC_MSG("%" PRIu64 "\tLISTEN_UDP_END\n", get_time_ms());
        IPC_MSG_SEND();
    }

    vector<tags_item_t> tags;
    unique_ptr<Transmitter> t = unique_ptr<RemoteTransmitter>(new RemoteTransmitter(k, n, keypair, epoch, channel_id, fec_delay, tags,
                                                                                    remote_hosts, radiotap_header, frame_type, use_qdisc,
                                                                                    fwmark, snd_buf_size));

    int control_fd = open_control_fd(control_port);
    data_source(t, rx_fd, control_fd, fec_timeout, mirror, log_interval);
}


void distributor_loop_unix(int argc, char* const* argv, int optind, int rcv_buf, int log_interval,
                           const char* unix_socket, int k, int n, const string &keypair, int fec_timeout,
                           uint64_t epoch, uint32_t channel_id, uint32_t fec_delay, bool use_qdisc, uint32_t fwmark,
                           radiotap_header_t &radiotap_header, uint8_t frame_type, int control_port, bool mirror,
                           int snd_buf_size)
{
    vector<int> rx_fd;
    vector<pair<string, vector<uint16_t>>> remote_hosts;
    int port_idx = 0;

    set<string> hosts;

    for(int i = optind; i < argc; i++)
    {
        vector<uint16_t> remote_ports;
        char *p = argv[i];
        char *t = NULL;

        t = strsep(&p, ":");
        if (t == NULL) continue;

        string remote_host = string(t);

        if(hosts.count(remote_host))
        {
            throw runtime_error(string_format("Duplicate host %s", remote_host.c_str()));
        }

        hosts.insert(remote_host);

        for(int j=0; (t=strsep(&p, ",")) != NULL; j++, port_idx++)
        {
            uint16_t remote_port = atoi(t);

            string tmp = port_idx > 0 ? string_format("%s-%d", unix_socket, port_idx) : string(unix_socket);
            int fd = open_unix_socket_for_rx(tmp.c_str(), rcv_buf);

            uint64_t wlan_id = (uint64_t)ntohl(inet_addr(remote_host.c_str())) << 24  | j;

            IPC_MSG("%" PRIu64 "\tLISTEN_UNIX\t%s:%" PRIx64 "\n", get_time_ms(), tmp.c_str(), wlan_id);
            WFB_INFO("Listen on @%s for %s:%d\n", tmp.c_str(), remote_host.c_str(), remote_port);

            rx_fd.push_back(fd);
            remote_ports.push_back(remote_port);
        }

        remote_hosts.push_back(pair<string, vector<uint16_t>>(remote_host, remote_ports));
    }

    IPC_MSG("%" PRIu64 "\tLISTEN_UNIX_END\n", get_time_ms());
    IPC_MSG_SEND();

    vector<tags_item_t> tags;
    unique_ptr<Transmitter> t = unique_ptr<RemoteTransmitter>(new RemoteTransmitter(k, n, keypair, epoch, channel_id, fec_delay, tags,
                                                                                    remote_hosts, radiotap_header, frame_type, use_qdisc,
                                                                                    fwmark, snd_buf_size));

    int control_fd = open_control_fd(control_port);
    data_source(t, rx_fd, control_fd, fec_timeout, mirror, log_interval);
}


int main(int argc, char * const *argv)
{
    int opt;
    uint8_t k=8, n=12, radio_port=0;
    uint32_t fec_delay = 0;
    uint32_t link_id = 0x0;
    uint64_t epoch = 0;
    int srv_port = 10000;
    int udp_port=5600;
    int control_port=0;
    int log_interval = 1000;

    int bandwidth = 20;
    int short_gi = 0;
    int stbc = 0;
    int ldpc = 0;
    int mcs_index = 1;
    int vht_nss = 1;
    int debug_port = 0;
    int fec_timeout = 0;
    int rcv_buf = 0;
    int snd_buf = 0;
    bool mirror = false;
    bool vht_mode = false;
    string keypair = "tx.key";
    uint8_t frame_type = FRAME_TYPE_DATA;
    bool use_qdisc = false;
    uint32_t fwmark = 0;
    tx_mode_t tx_mode = LOCAL;
    char *unix_socket = NULL;
    uint32_t inject_retries = 0;
    uint32_t inject_retry_delay = 5000; // 5ms
    bool udp_port_given = false;
    vector<string> stream_args;

    while ((opt = getopt(argc, argv, "dI:K:k:n:u:U:p:F:l:B:G:S:L:M:N:D:T:i:e:R:s:f:mVQP:C:J:E:y:")) != -1) {
        switch (opt) {
        case 'I':
            tx_mode = INJECTOR;
            srv_port = atoi(optarg);
            break;
        case 'd':
            tx_mode = DISTRIBUTOR;
            break;
        case 'K':
            keypair = optarg;
            break;
        case 'k':
            k = atoi(optarg);
            break;
        case 'n':
            n = atoi(optarg);
            break;
        case 'u':
            udp_port = atoi(optarg);
            udp_port_given = true;
            break;
        case 'y':
            stream_args.push_back(string(optarg));
            break;
        case 'U':
            unix_socket = optarg;
            break;
        case 'p':
            radio_port = atoi(optarg);
            break;
        case 'F':
            fec_delay = atoi(optarg);
            break;
        case 'R':
            rcv_buf = atoi(optarg);
            break;
        case 's':
            snd_buf = atoi(optarg);
            break;
        case 'B':
            bandwidth = atoi(optarg);
            // Force VHT mode for bandwidth >= 80
            if (bandwidth >= 80) {
                vht_mode = true;
            }
            break;
        case 'G':
            short_gi = (optarg[0] == 's' || optarg[0] == 'S') ? 1 : 0;
            break;
        case 'S':
            stbc = atoi(optarg);
            break;
        case 'L':
            ldpc = atoi(optarg);
            break;
        case 'M':
            mcs_index = atoi(optarg);
            break;
        case 'N':
            vht_nss = atoi(optarg);
            break;
        case 'D':
            debug_port = atoi(optarg);
            break;
        case 'T':
            fec_timeout = atoi(optarg);
            break;
        case 'l':
            log_interval = atoi(optarg);
            break;
        case 'i':
            link_id = ((uint32_t)atoi(optarg)) & 0xffffff;
            break;
        case 'e':
            epoch = atoll(optarg);
            break;
        case 'm':
            mirror = true;
            break;
        case 'V':
            vht_mode = true;
            break;
        case 'f':
            if (strcmp(optarg, "data") == 0)
            {
                WFB_INFO("Using data frames\n");
                frame_type = FRAME_TYPE_DATA;
            }
            else if (strcmp(optarg, "rts") == 0)
            {
                WFB_INFO("Using rts frames\n");
                frame_type = FRAME_TYPE_RTS;
            }
            else
            {
                WFB_ERR("Invalid frame type: %s\n", optarg);
                exit(1);
            }
            break;

        case 'Q':
            use_qdisc = true;
            break;

        case 'P':
            fwmark = (uint32_t)atoi(optarg);
            break;

        case 'C':
            control_port = atoi(optarg);
            break;

        case 'J':
            inject_retries = atoi(optarg);
            break;

        case 'E':
            inject_retry_delay = atoi(optarg);
            break;

        default: /* '?' */
        show_usage:
            WFB_INFO("Local TX: %s [-K tx_key] [-k RS_K] [-n RS_N] { [-u udp_port] | [-U unix_socket] } [-R rcv_buf] [-p radio_port]\n"
                     "             [-F fec_delay] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] [-N VHT_NSS]\n"
                     "             [-T fec_timeout] [-l log_interval] [-e epoch] [-i link_id] [-f { data | rts }] [-m] [-V] [-Q]\n"
                     "             [-P fwmark] [-J inject_retries] [-E inject_retry_delay] [-C control_port] interface1 [interface2] ...\n",
                    argv[0]);
            WFB_INFO("TX distributor: %s -d [-K tx_key] [-k RS_K] [-n RS_N] { [-u udp_port] | [-U unix_socket] } [-R rcv_buf] [-s snd_buf] [-p radio_port]\n"
                     "                      [-F fec_delay] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] [-N VHT_NSS]\n"
                     "                      [-T fec_timeout] [-l log_interval] [-e epoch] [-i link_id] [-f { data | rts }] [-m] [-V] [-Q]\n"
                     "                      [-P fwmark] [-C control_port] host1:port1,port2,... [host2:port1,port2,...] ...\n",
                    argv[0]);
            WFB_INFO("TX injector: %s -I port [-Q] [-R rcv_buf] [-l log_interval] interface1 [interface2] ...\n",
                    argv[0]);
            WFB_INFO("Multi-stream TX: %s -y stream_spec [-y stream_spec] ... [common Local TX options] interface1 [interface2] ...\n"
                     "                 stream_spec: u=<udp_port>,p=<radio_port>[,k=...][,n=...][,T=fec_timeout][,F=fec_delay]\n"
                     "                              [,mcs=...][,bw=...][,gi={short|long}][,stbc=...][,ldpc=...][,vht={0|1}][,nss=...]\n"
                     "                 Spec order is strict drain priority (first = highest). Unset keys inherit the global options.\n"
                     "                 Each stream gets its own FEC encoder, session key and radiotap header on the same link_id.\n",
                    argv[0]);
            WFB_INFO("Default: K='%s', k=%d, n=%d, fec_delay=%u [us], udp_port=%d, link_id=0x%06x, radio_port=%u, epoch=%" PRIu64 ", bandwidth=%d guard_interval=%s stbc=%d ldpc=%d mcs_index=%d vht_nss=%d, vht_mode=%d, fec_timeout=%d, log_interval=%d, rcv_buf=system_default, snd_buf=system_default, frame_type=data, mirror=false, use_qdisc=false, fwmark=%u, control_port=%d, inject_retries=%u, inject_retry_delay=%u\n",
                     keypair.c_str(), k, n, fec_delay, udp_port, link_id, radio_port, epoch, bandwidth, short_gi ? "short" : "long", stbc, ldpc, mcs_index, vht_nss, vht_mode, fec_timeout, log_interval, fwmark, control_port, inject_retries, inject_retry_delay);
            WFB_INFO("Radio MTU: %lu\n", (unsigned long)MAX_PAYLOAD_SIZE);
            WFB_INFO("WFB-ng version %s, FEC: %s\n", WFB_VERSION, zfex_opt);
            WFB_INFO("WFB-ng home page: <http://wfb-ng.org>\n");
            exit(1);
        }
    }

    if (optind >= argc) {
        goto show_usage;
    }

    {
        int fd;
        int c;

        if ((fd = open("/dev/random", O_RDONLY)) != -1) {
            if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
                WFB_ERR("This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
                        "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
                        "On virtualized Linux environments, also consider using virtio-rng.\n"
                        "The service will not start until enough entropy has been collected.\n");
            }
            (void) close(fd);
        }
    }

    if (sodium_init() < 0)
    {
        WFB_ERR("Libsodium init failed\n");
        return 1;
    }

    try
    {
        auto radiotap_header = init_radiotap_header(stbc, ldpc, short_gi, bandwidth, mcs_index, vht_mode, vht_nss);
        uint32_t channel_id = (link_id << 8) + radio_port;

        if (!stream_args.empty())
        {
            if (tx_mode != LOCAL)
            {
                throw runtime_error("Multi-stream specs (-y) are only supported in local TX mode");
            }

            if (unix_socket != NULL || udp_port_given)
            {
                throw runtime_error("Multi-stream mode: stream inputs are defined inside -y specs, not via -u/-U");
            }
        }

        switch(tx_mode)
        {
        case INJECTOR:
            injector_loop(argc, argv, optind, srv_port, rcv_buf, use_qdisc, log_interval);
            break;

        case LOCAL:
            if (!stream_args.empty())
            {
                vector<stream_spec_t> stream_specs;

                for(auto &arg : stream_args)
                {
                    stream_specs.push_back(parse_stream_spec(arg.c_str()));
                }

                validate_stream_specs(stream_specs);

                local_loop_multi(argc, argv, optind, rcv_buf, log_interval,
                                 stream_specs, debug_port, k, n, keypair, fec_timeout,
                                 epoch, link_id, fec_delay, use_qdisc, fwmark,
                                 stbc, ldpc, short_gi, bandwidth, mcs_index,
                                 vht_mode, vht_nss, frame_type, control_port, mirror,
                                 snd_buf, inject_retries, inject_retry_delay);
            }
            else if (unix_socket != NULL)
            {
                local_loop_unix(argc, argv, optind, rcv_buf, log_interval,
                                unix_socket, debug_port, k, n, keypair, fec_timeout,
                                epoch, channel_id, fec_delay, use_qdisc, fwmark,
                                radiotap_header, frame_type, control_port, mirror,
                                snd_buf, inject_retries, inject_retry_delay);
            }
            else
            {
                local_loop_udp(argc, argv, optind, rcv_buf, log_interval,
                               udp_port, debug_port, k, n, keypair, fec_timeout,
                               epoch, channel_id, fec_delay, use_qdisc, fwmark,
                               radiotap_header, frame_type, control_port, mirror,
                               snd_buf, inject_retries, inject_retry_delay);
            }
            break;

        case DISTRIBUTOR:
            if (unix_socket != NULL)
            {
                distributor_loop_unix(argc, argv, optind, rcv_buf, log_interval,
                                      unix_socket, k, n, keypair, fec_timeout,
                                      epoch, channel_id, fec_delay, use_qdisc, fwmark,
                                      radiotap_header, frame_type, control_port, mirror,
                                      snd_buf);
            }
            else
            {
                distributor_loop(argc, argv, optind, rcv_buf, log_interval,
                                 udp_port, k, n, keypair, fec_timeout,
                                 epoch, channel_id, fec_delay, use_qdisc, fwmark,
                                 radiotap_header, frame_type, control_port, mirror,
                                 snd_buf);
            }
            break;

        default:
            assert(0);
        }
    }
    catch(runtime_error &e)
    {
        WFB_ERR("Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}
