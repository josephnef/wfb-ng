#pragma once
#include <stdint.h>

#define CMD_SET_FEC   1
#define CMD_SET_RADIO 2
#define CMD_GET_FEC   3
#define CMD_GET_RADIO 4

// Per-stream variants for multi-stream TX mode (-y). The target stream is
// addressed by its radio_port. Legacy commands above keep operating on the
// first stream. Responses of the per-stream getters reuse cmd_get_fec /
// cmd_get_radio.
#define CMD_SET_FEC_STREAM   5
#define CMD_SET_RADIO_STREAM 6
#define CMD_GET_FEC_STREAM   7
#define CMD_GET_RADIO_STREAM 8

typedef struct {
    uint32_t req_id;
    uint8_t cmd_id;
    union {
        struct
        {
            uint8_t k;
            uint8_t n;
        } __attribute__ ((packed)) cmd_set_fec;

        struct
        {
            uint8_t stbc;
            bool ldpc;
            bool short_gi;
            uint8_t bandwidth;
            uint8_t mcs_index;
            bool vht_mode;
            uint8_t vht_nss;
        } __attribute__ ((packed)) cmd_set_radio;

        struct
        {
            uint8_t radio_port;
            uint8_t k;
            uint8_t n;
        } __attribute__ ((packed)) cmd_set_fec_stream;

        struct
        {
            uint8_t radio_port;
            uint8_t stbc;
            bool ldpc;
            bool short_gi;
            uint8_t bandwidth;
            uint8_t mcs_index;
            bool vht_mode;
            uint8_t vht_nss;
        } __attribute__ ((packed)) cmd_set_radio_stream;

        struct
        {
            uint8_t radio_port;
        } __attribute__ ((packed)) cmd_get_fec_stream;

        struct
        {
            uint8_t radio_port;
        } __attribute__ ((packed)) cmd_get_radio_stream;
    } __attribute__ ((packed)) u;
} __attribute__ ((packed)) cmd_req_t;


typedef struct {
    uint32_t req_id;
    uint32_t rc;
    union {
        struct
        {
            uint8_t k;
            uint8_t n;
        } __attribute__ ((packed)) cmd_get_fec;

        struct
        {
            uint8_t stbc;
            bool ldpc;
            bool short_gi;
            uint8_t bandwidth;
            uint8_t mcs_index;
            bool vht_mode;
            uint8_t vht_nss;
        } __attribute__ ((packed)) cmd_get_radio;
    } __attribute__ ((packed)) u;
} __attribute__ ((packed)) cmd_resp_t;
