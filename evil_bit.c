#include <stdint.h>

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

const int l3_off = L3_OFF;
const int l3_len = sizeof(struct iphdr);

static int set_evil_bit(struct __sk_buff *skb);

SEC("egress")
int egress_handler(struct __sk_buff *skb)
{
    if (bpf_skb_pull_data(skb, l3_off + l3_len) < 0)
        return TC_ACT_OK;

    void *data_end = (void *)(uint64_t)skb->data_end;
    void *data = (void *)(uint64_t)skb->data;

    // not enough data
    if (data + l3_off + l3_len > data_end)
        return TC_ACT_OK;

    uint16_t ether_type;
    uint8_t version;

    switch (l3_off)
    {
    case 0: // L3 tunnel (e.g wireguard/tun); check first 4 bits for IPv4 version field
        version = *(uint8_t *)(data + l3_off);
        if ((version >> 4) != 4)
            return TC_ACT_OK;
        break;
    case 14:
    case 18:
        // ethernet (dot1q or otherwise)
        // ensure ethertype is IPv4
        ether_type = *(uint16_t *)(data + l3_off - 2);
        ether_type = bpf_ntohs(ether_type);
        if (ether_type != ETH_P_IP)
            return TC_ACT_OK;
        break;
    default:
        // unknown type, ignore
        return TC_ACT_OK;
    }

    return set_evil_bit(skb);
}

__always_inline static int set_evil_bit(struct __sk_buff *skb)
{
    struct iphdr *ip = (void *)(uint64_t)skb->data + l3_off;
    // bpf_skb_store_bytes expects a multiple of 4 bytes, so include the id field
    uint32_t id_frag_off = bpf_ntohs(ip->id) << 16 | bpf_ntohs(ip->frag_off);
    // set evil bit
    id_frag_off |= 0x8000;
    id_frag_off = bpf_htonl(id_frag_off);

    // calculate and set new IPv4 checksum
    uint32_t sum = bpf_csum_diff((uint32_t *)&ip->id, 4, &id_frag_off, 4, 0);

    if (bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, id), &id_frag_off, 4, 0) < 0)
        return TC_ACT_SHOT;

    if (bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}
