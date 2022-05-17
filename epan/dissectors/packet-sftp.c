/* packet-sftp.c
 * Routines for ssh packet dissection
 *
 * Jérôme Hamm
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-ssh.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *
 * Note:  support for SFTP.
 *
 */

/* SFTP is defined in:
 *
 * draft-ietf-secsh-filexfer-02 - SSH File Transfer Protocol
 *
 */

#include "config.h"

/* Start with WIRESHARK_LOG_DOMAINS=sftp and WIRESHARK_LOG_LEVEL=debug to see messages. */
#define WS_LOG_DOMAIN "sftp"

#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/expert.h>

#include "packet-ssh.h"

void proto_register_sftp(void);

static int proto_sftp = -1;

static int hf_ssh_sftp_len = -1;
static int hf_ssh_sftp_type = -1;
static int hf_ssh_sftp_version = -1;
static int hf_ssh_sftp_id = -1;
static int hf_ssh_sftp_path_len = -1;
static int hf_ssh_sftp_path = -1;
static int hf_ssh_sftp_pflags = -1;
static int hf_ssh_sftp_name_count = -1;
static int hf_ssh_sftp_name_fn_len = -1;
static int hf_ssh_sftp_name_fn = -1;
static int hf_ssh_sftp_name_ln_len = -1;
static int hf_ssh_sftp_name_ln = -1;
static int hf_ssh_sftp_attrs_flags = -1;
static int hf_ssh_sftp_attrs_size = -1;
static int hf_ssh_sftp_attrs_uid = -1;
static int hf_ssh_sftp_attrs_gid = -1;
static int hf_ssh_sftp_attrs_permissions = -1;
static int hf_ssh_sftp_attrs_atime = -1;
static int hf_ssh_sftp_attrs_mtime = -1;
static int hf_ssh_sftp_attrs_extended_count = -1;
static int hf_ssh_sftp_handle_len = -1;
static int hf_ssh_sftp_handle = -1;
static int hf_ssh_sftp_status = -1;
static int hf_ssh_sftp_error_message_len = -1;
static int hf_ssh_sftp_error_message = -1;
static int hf_ssh_sftp_offset = -1;
static int hf_ssh_sftp_length = -1;
static int hf_ssh_sftp_data_len = -1;
static int hf_ssh_sftp_data = -1;
static int hf_ssh_lang_tag_length = -1;
static int hf_ssh_lang_tag = -1;

static int hf_sftp_data_fragments = -1;
static int hf_sftp_data_fragment = -1;
static int hf_sftp_data_fragment_overlap = -1;
static int hf_sftp_data_fragment_overlap_conflicts = -1;
static int hf_sftp_data_fragment_multiple_tails = -1;
static int hf_sftp_data_fragment_too_long_fragment = -1;
static int hf_sftp_data_fragment_error = -1;
static int hf_sftp_data_fragment_count = -1;
static int hf_sftp_data_reassembled_in = -1;
static int hf_sftp_data_reassembled_length = -1;

/* For reassembly */
static gint32 sftp_last_pdu = -1;

static gint ett_sftp = -1;
static gint ett_sftp_attrs = -1;

static dissector_handle_t sftp_handle;

static gint ett_sftp_data_fragment = -1;
static gint ett_sftp_data_fragments = -1;

static const fragment_items sftp_frag_items = {
  /* Fragment subtrees */
  &ett_sftp_data_fragment,
  &ett_sftp_data_fragments,
  /* Fragment fields */
  &hf_sftp_data_fragments,
  &hf_sftp_data_fragment,
  &hf_sftp_data_fragment_overlap,
  &hf_sftp_data_fragment_overlap_conflicts,
  &hf_sftp_data_fragment_multiple_tails,
  &hf_sftp_data_fragment_too_long_fragment,
  &hf_sftp_data_fragment_error,
  &hf_sftp_data_fragment_count,
  /* Reassembled in field */
  &hf_sftp_data_reassembled_in,
  /* Reassembled length field */
  &hf_sftp_data_reassembled_length,
  /* Reassembled data field */
  NULL,
  /* Tag */
  "SFTP fragments"
};

#define SSH_FXP_INIT                1
#define SSH_FXP_VERSION             2
#define SSH_FXP_OPEN                3
#define SSH_FXP_CLOSE               4
#define SSH_FXP_READ                5
#define SSH_FXP_WRITE               6
#define SSH_FXP_LSTAT               7
#define SSH_FXP_FSTAT               8
#define SSH_FXP_SETSTAT             9
#define SSH_FXP_FSETSTAT           10
#define SSH_FXP_OPENDIR            11
#define SSH_FXP_READDIR            12
#define SSH_FXP_REMOVE             13
#define SSH_FXP_MKDIR              14
#define SSH_FXP_RMDIR              15
#define SSH_FXP_REALPATH           16
#define SSH_FXP_STAT               17
#define SSH_FXP_RENAME             18
#define SSH_FXP_READLINK           19
#define SSH_FXP_LINK               21
#define SSH_FXP_BLOCK              22
#define SSH_FXP_UNBLOCK            23

#define SSH_FXP_STATUS            101
#define SSH_FXP_HANDLE            102
#define SSH_FXP_DATA              103
#define SSH_FXP_NAME              104
#define SSH_FXP_ATTRS             105

#define SSH_FXP_EXTENDED          200
#define SSH_FXP_EXTENDED_REPLY    201

#define SSH_FILEXFER_ATTR_SIZE          0x00000001
#define SSH_FILEXFER_ATTR_UIDGID        0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS   0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME     0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED      0x80000000

static const value_string ssh2_sftp_vals[] = {
    {SSH_FXP_INIT,                       "SSH_FXP_INIT"},
    {SSH_FXP_VERSION,                    "SSH_FXP_VERSION"},
    {SSH_FXP_OPEN,                       "SSH_FXP_OPEN"},
    {SSH_FXP_CLOSE,                      "SSH_FXP_CLOSE"},
    {SSH_FXP_READ,                       "SSH_FXP_READ"},
    {SSH_FXP_WRITE,                      "SSH_FXP_WRITE"},
    {SSH_FXP_LSTAT,                      "SSH_FXP_LSTAT"},
    {SSH_FXP_FSTAT,                      "SSH_FXP_FSTAT"},
    {SSH_FXP_SETSTAT,                    "SSH_FXP_SETSTAT"},
    {SSH_FXP_FSETSTAT,                   "SSH_FXP_FSETSTAT"},
    {SSH_FXP_OPENDIR,                    "SSH_FXP_OPENDIR"},
    {SSH_FXP_READDIR,                    "SSH_FXP_READDIR"},
    {SSH_FXP_REMOVE,                     "SSH_FXP_REMOVE"},
    {SSH_FXP_MKDIR,                      "SSH_FXP_MKDIR"},
    {SSH_FXP_RMDIR,                      "SSH_FXP_RMDIR"},
    {SSH_FXP_REALPATH,                   "SSH_FXP_REALPATH"},
    {SSH_FXP_STAT,                       "SSH_FXP_STAT"},
    {SSH_FXP_RENAME,                     "SSH_FXP_RENAME"},
    {SSH_FXP_READLINK,                   "SSH_FXP_READLINK"},
    {SSH_FXP_LINK,                       "SSH_FXP_LINK"},
    {SSH_FXP_BLOCK,                      "SSH_FXP_BLOCK"},
    {SSH_FXP_UNBLOCK,                    "SSH_FXP_UNBLOCK"},
    {SSH_FXP_STATUS,                     "SSH_FXP_STATUS"},
    {SSH_FXP_HANDLE,                     "SSH_FXP_HANDLE"},
    {SSH_FXP_DATA,                       "SSH_FXP_DATA"},
    {SSH_FXP_NAME,                       "SSH_FXP_NAME"},
    {SSH_FXP_ATTRS,                      "SSH_FXP_ATTRS"},
    {SSH_FXP_EXTENDED,                   "SSH_FXP_EXTENDED"},
    {SSH_FXP_EXTENDED_REPLY,             "SSH_FXP_EXTENDED_REPLY"},
    {0, NULL}
};

static int dissect_sftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
static int dissect_sftp_attrs(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree);


struct sftp_multisegment_pdu {
    guint nxtpdu;
    guint32 first_frame;
    guint32 running_size;
    gboolean finished;
    gboolean reassembled;

    guint plen;

    guint32 flags;
    #define MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT	0x00000001
    #define MSP_FLAGS_GOT_ALL_SEGMENTS          0x00000002
    #define MSP_FLAGS_MISSING_FIRST_SEGMENT     0x00000004
};

static struct sftp_multisegment_pdu *
pdu_store(guint32 key, wmem_tree_t *multisegment_pdus, guint32 first_frame)
{
    struct sftp_multisegment_pdu *msp;

    msp = wmem_new(wmem_file_scope(), struct sftp_multisegment_pdu);
    msp->first_frame = first_frame;
    msp->finished = FALSE;
    msp->reassembled = FALSE;
    msp->flags = 0;
    wmem_tree_insert32(multisegment_pdus, key, (void *)msp);

    return msp;
}

struct sftp_analysis {
    wmem_tree_t *multisegment_pdus[2];
};

static struct sftp_analysis *
init_sftp_conversation_data(void)
{
    struct sftp_analysis *sftpd;

    sftpd = wmem_new0(wmem_file_scope(), struct sftp_analysis);

    sftpd->multisegment_pdus[0] = wmem_tree_new(wmem_file_scope());
    sftpd->multisegment_pdus[1] = wmem_tree_new(wmem_file_scope());

    return sftpd;
}

static struct sftp_analysis *
get_sftp_conversation_data(conversation_t *conv, packet_info *pinfo)
{
    struct sftp_analysis *sftpd;

    if(conv == NULL ) {
        conv = find_or_create_conversation(pinfo);
    }

    sftpd = (struct sftp_analysis *)conversation_get_proto_data(conv, proto_sftp);

    if (!sftpd) {
        sftpd = init_sftp_conversation_data();
        conversation_add_proto_data(conv, proto_sftp, sftpd);
    }

    return sftpd;
}


/*AFAC???
static gpointer sftp_temporary_key(const packet_info *pinfo _U_, const guint32 id _U_, const void *data)
{
    return (gpointer)data;
}

static gpointer sftp_persistent_key(const packet_info *pinfo _U_, const guint32 id _U_, const void *data)
{
    return (gpointer)data;
}

static void sftp_free_temporary_key(gpointer ptr _U_) { }

static void sftp_free_persistent_key(gpointer ptr _U_) { }
*/

/*AFAC???
static reassembly_table_functions sftp_reassembly_table_functions =
{
    g_direct_hash,
    g_direct_equal,
    sftp_temporary_key,
    sftp_persistent_key,
    sftp_free_temporary_key,
    sftp_free_persistent_key
};*/

//AFAC??? static dissector_table_t sftp_dissector_table;
static reassembly_table sftp_reassembly_table;

/*
 * Look up an fd_head in the fragment table, optionally returning the key
 * for it.
 */
static fragment_head *
lookup_fd_head(reassembly_table *table, const packet_info *pinfo,
	       const guint32 id, const void *data, gpointer *orig_keyp)
{
	gpointer key;
	gpointer value;

	/* Create key to search hash with */
	key = table->temporary_key_func(pinfo, id, data);

	/*
	 * Look up the reassembly in the fragment table.
	 */
	if (!g_hash_table_lookup_extended(table->fragment_table, key, orig_keyp,
					  &value))
		value = NULL;
	/* Free the key */
	table->free_temporary_key_func(key);

	return (fragment_head *)value;
}

static int dissect_reassembled_sftp(tvbuff_t *packet_tvb, packet_info *pinfo, int offset, proto_item *msg_type_tree);
static int dissect_sftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
        int offset = 0;
        tvbuff_t                  *next_tvb;(void)next_tvb;
        struct sftp_multisegment_pdu *new_msp = NULL;
        struct sftp_multisegment_pdu *previous_msp = NULL;
        struct sftp_analysis *sftpd = NULL;
        conversation_t *conv = NULL;
        gboolean save_fragmented = pinfo->fragmented;
        ssh_channel * chan = (ssh_channel *)data;
        gboolean    direction = (pinfo->destport != pinfo->match_uint)?0:1;

        guint captured_length = tvb_captured_length(tvb);
        gint reported_length = tvb_reported_length(tvb);
        proto_tree_add_debug_text(tree, "SFTP{%4d}captured_length=%u, reported_length=%d, rcpt_chan=%u", pinfo?(int)pinfo->num:-42, captured_length, reported_length, chan->channel_recipient);

        if((conv = find_conversation_pinfo(pinfo, 0)) != NULL) {
        /* Update how far the conversation reaches */
                if (pinfo->num > conv->last_frame) {
                        conv->last_frame = pinfo->num;
                }
        } else {
                conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_TCP, pinfo->srcport, pinfo->destport, 0);
        }

        sftpd = get_sftp_conversation_data(conv, pinfo);

        guint available = tvb_reported_length_remaining(tvb, offset);
        guint consumed = 0;

        previous_msp = (struct sftp_multisegment_pdu *)wmem_tree_lookup32(sftpd->multisegment_pdus[direction], chan->packet_id);
        if(previous_msp){
                new_msp = previous_msp;
                previous_msp = (struct sftp_multisegment_pdu *)wmem_tree_lookup32_le(sftpd->multisegment_pdus[direction], chan->packet_id-1);
                if(previous_msp && previous_msp->finished){
                        previous_msp = NULL;
                }
        } else {
                previous_msp = (struct sftp_multisegment_pdu *)wmem_tree_lookup32_le(sftpd->multisegment_pdus[direction], chan->packet_id);
                ws_debug("previous_msp=%p, sftp_last_pdu=%d, pinfo->num=%d, captured_length=%u", previous_msp, sftp_last_pdu, pinfo->num, captured_length);

                if (previous_msp && !previous_msp->finished) {
                        previous_msp->nxtpdu = pinfo->num;
                        new_msp = pdu_store(chan->packet_id, sftpd->multisegment_pdus[direction], previous_msp->first_frame);
                        new_msp->plen = previous_msp->plen;
                        consumed = (previous_msp->running_size + captured_length < new_msp->plen+4)?captured_length:(new_msp->plen+4-previous_msp->running_size);
                        proto_tree_add_debug_text(tree, "+++consumed = %d", consumed);
                        new_msp->running_size = previous_msp->running_size + consumed;
                } else {
                        previous_msp = NULL;
                        new_msp = pdu_store(chan->packet_id, sftpd->multisegment_pdus[direction], chan->packet_id);
                        new_msp->running_size = captured_length;
                        new_msp->plen = tvb_get_ntohl(tvb, offset);
//                      fragment_add_check(&sftp_reassembly_table, tvb, offset, pinfo, new_msp->first_frame, GUINT_TO_POINTER(new_msp->first_frame), 0, captured_length, TRUE);
//                      sftp_last_pdu = pinfo->num;
                }
        }

//        guint available = new_msp->running_size
        ws_debug("plen = %u available = %u offset = %u", new_msp->plen, available, offset);
        proto_tree_add_debug_text(tree, "SFTP      plen = %u need = %u available = %u / %u offset = %u / running_size = %u", new_msp->plen, new_msp->plen+4, available, new_msp->running_size, offset, new_msp->running_size);
        if( offset + available < new_msp->plen + 4 ) {          // 32 bits length field
            pinfo->fragmented = TRUE;
            tvbuff_t* new_tvb = NULL;
            fragment_head *frag_sftp = NULL;
//            frag_sftp = fragment_add_seq_check(&sftp_reassembly_table, tvb, offset, pinfo, sftp_seqid, NULL, /* ID for fragments belonging together */ sftp_num, /* fragment sequence number */ tvb_captured_length_remaining(tvb, offset), /* fragment length - to the end */ TRUE); /* More fragments? */
//            frag_sftp = fragment_add_check(&sftp_reassembly_table, tvb, offset, pinfo, new_msp->first_frame, GUINT_TO_POINTER(new_msp->first_frame), previous_msp?previous_msp->running_size:0, captured_length, TRUE);
            gboolean more_frags;
            more_frags = new_msp->running_size < new_msp->plen+4;
            proto_tree_add_debug_text(tree, "first_frame = %u.%u, offst = %u, captured_length= %u, more_frags = %u (%u >= %u), previous_msp=%p", new_msp->first_frame >> 4, new_msp->first_frame & 0xF, previous_msp?previous_msp->running_size:0, captured_length, more_frags, new_msp->running_size, new_msp->plen+4, previous_msp);
//            frag_sftp = fragment_add_check(&sftp_reassembly_table, tvb, offset, pinfo, new_msp->first_frame, GUINT_TO_POINTER(new_msp->first_frame), previous_msp?previous_msp->running_size:0, captured_length, more_frags);
            consumed = more_frags?captured_length:new_msp->plen+4-(previous_msp?previous_msp->running_size:0);
            frag_sftp = fragment_add_check(&sftp_reassembly_table, tvb, offset, pinfo, new_msp->first_frame, NULL, previous_msp?previous_msp->running_size:0, consumed, more_frags);
            if(!previous_msp){
//                    fragment_set_tot_len(&sftp_reassembly_table, pinfo, new_msp->first_frame, GUINT_TO_POINTER(new_msp->first_frame), new_msp->plen + 4);
                    fragment_set_tot_len(&sftp_reassembly_table, pinfo, new_msp->first_frame, NULL, new_msp->plen + 4);
            }

            new_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled SFTP", frag_sftp, &sftp_frag_items, NULL, tree);

            proto_tree_add_debug_text(tree, "frag_sftp = %p, new_tvb = %p, tvb_bytes_exist(%u)=%u tot_len = %u", frag_sftp, new_tvb, captured_length, tvb_bytes_exist(tvb, offset, captured_length), fragment_get_tot_len(&sftp_reassembly_table, pinfo, new_msp->first_frame, NULL));

            if(!more_frags){
                proto_item *frag_tree_item;
                gpointer orig_key;
                fragment_head *fd_head = lookup_fd_head(&sftp_reassembly_table, pinfo, new_msp->first_frame, NULL, &orig_key);
                if(fd_head){
                        show_fragment_tree(fd_head, &sftp_frag_items, tree, pinfo, tvb, &frag_tree_item);
                }
            }

            if (frag_sftp && new_tvb) { /* Reassembled */
                col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
            } else { /* Not last packet of reassembled Short Message */
//                col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment %u)", sftp_num);
//                col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment X)");
                col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment %u-%u of %u)", previous_msp?previous_msp->running_size:0, new_msp->running_size, new_msp->plen);
            }

            if (new_tvb) { /* take it all */
                dissect_reassembled_sftp(new_tvb, pinfo, offset, tree);
                sftp_last_pdu = -1;
                new_msp->finished = TRUE;
                next_tvb = new_tvb;
            } else { /* make a new subset */
//                char * flag_string = "XYZ";
//                char * pdu_type_string = "xXx";
                /* Just show this as a segment. */
//                col_add_fstr(pinfo->cinfo, COL_INFO, "[Fragmented %s SFTP %s(off=%u/%u)]", pdu_type_string, flag_string, previous_msp?previous_msp->running_size:0, new_msp->plen);

                next_tvb = tvb_new_subset_remaining(tvb, offset);
            }
            pinfo->fragmented = save_fragmented;

            /* we ran out of data: ask for more */
//            pinfo->desegment_offset = offset;
//            pinfo->desegment_len = plen - available;
        }else{
                consumed = dissect_reassembled_sftp(tvb, pinfo, offset, tree) - offset;
                new_msp->finished = TRUE;
                sftp_last_pdu = -1;
        }
        proto_tree_add_debug_text(tree, "dissect_sftp %d + %d = %d", offset, consumed, offset + consumed);
        return offset + consumed;
}
static int dissect_reassembled_sftp(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_item *tree)
{
        guint slen;
        guint plen = tvb_get_ntohl(tvb, offset);

        wmem_strbuf_t *title = wmem_strbuf_new(wmem_packet_scope(), "SFTP");
        proto_item * sftp_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_sftp, NULL, NULL);
        proto_tree_add_item(sftp_tree, hf_ssh_sftp_len, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        guint8  typ;
        typ = tvb_get_guint8(tvb, offset) ;
        proto_tree_add_item(sftp_tree, hf_ssh_sftp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(typ, ssh2_sftp_vals, "Unknown (%u)"));
        switch(typ){
        case SSH_FXP_INIT:{
                int ver = tvb_get_ntohl(tvb, offset) ;
                wmem_strbuf_append_printf(title, " SSH_FXP_INIT (%d) version %d", typ, ver);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_version, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                break;
                }
        case SSH_FXP_VERSION:{
                int ver = tvb_get_ntohl(tvb, offset) ;
                wmem_strbuf_append_printf(title, " SSH_FXP_VERSION (%d) version %d", typ, ver);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_version, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                offset += plen-4;
                break;
                }
        case SSH_FXP_OPEN:{
                int id = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8 * path = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, slen, ENC_UTF_8);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
//                int pflags = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_pflags, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = dissect_sftp_attrs(tvb, pinfo, offset, sftp_tree);
                offset += slen;
                wmem_strbuf_append_printf(title, " SSH_FXP_OPEN (%d) id=%d [%s]", typ, id, path);
                break;
                }
        case SSH_FXP_CLOSE:{
                int id = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                gchar * handle = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, slen);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle, tvb, offset, slen, ENC_NA);
                offset += slen;
                wmem_strbuf_append_printf(title, " SSH_FXP_CLOSE (%d) id=%d {%s}", typ, id, handle);
                break;
                }
        case SSH_FXP_READ:{
                int id = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                gchar * handle = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, slen);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle, tvb, offset, slen, ENC_NA);
                offset += slen;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += 8;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_length, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                wmem_strbuf_append_printf(title, " SSH_FXP_READ (%d) id=%d {%s}", typ, id, handle);
                break;
                }
        case SSH_FXP_WRITE:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                gchar * handle = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, slen);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle, tvb, offset, slen, ENC_NA);
                offset += slen;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += 8;
                int dlen = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_data_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_data, tvb, offset, dlen, ENC_NA);
                offset += dlen;
                wmem_strbuf_append_printf(title, " SSH_FXP_WRITE (%d) id=%d {%s} len=%d", typ, id, handle, dlen);
                break;
                }
        case SSH_FXP_LSTAT:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8 * path = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, slen, ENC_UTF_8);
                wmem_strbuf_append_printf(title, " SSH_FXP_LSTAT (%d) id=%d [%s]", typ, id, path);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                break;
                }
        case SSH_FXP_FSTAT:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                gchar * handle = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, slen);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle, tvb, offset, slen, ENC_NA);
                offset += slen;
                wmem_strbuf_append_printf(title, " SSH_FXP_FSTAT (%d) id=%d {%s}", typ, id, handle);
                break;
                }
        case SSH_FXP_SETSTAT:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8 * path = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, slen, ENC_UTF_8);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                slen = dissect_sftp_attrs(tvb, pinfo, offset, sftp_tree);
                proto_item_set_len(sftp_tree, slen);
                offset += slen;
                wmem_strbuf_append_printf(title, " SSH_FXP_SETSTAT (%d) id=%d [%s]", typ, id, path);
                break;
                }
//        case SSH_FXP_FSETSTAT):{
//                break;
//                }
        case SSH_FXP_OPENDIR:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8 * path = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, slen, ENC_UTF_8);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                wmem_strbuf_append_printf(title, " SSH_FXP_OPENDIR (%d) id=%d [%s]", typ, id, path);
                break;
                }
        case SSH_FXP_READDIR:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                gchar * handle = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, slen);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle, tvb, offset, slen, ENC_NA);
                offset += slen;
                wmem_strbuf_append_printf(title, " SSH_FXP_READDIR (%d) id=%d {%s}", typ, id, handle);
                break;
                }
        case SSH_FXP_REMOVE:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8 * path = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, slen, ENC_UTF_8);
                wmem_strbuf_append_printf(title, " SSH_FXP_REMOVE (%d) id=%d [%s]", typ, id, path);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                break;
                }
//        case SSH_FXP_MKDIR:{
//                break;
//                }
//        case SSH_FXP_RMDIR:{
//                break;
//                }
        case SSH_FXP_REALPATH:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8 * path = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, slen, ENC_UTF_8);
                wmem_strbuf_append_printf(title, " SSH_FXP_REALPATH (%d) id=%d [%s]", typ, id, path);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                break;
                }
        case SSH_FXP_STAT:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8 * path = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, slen, ENC_UTF_8);
                wmem_strbuf_append_printf(title, " SSH_FXP_STAT (%d) id=%d [%s]", typ, id, path);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                break;
                }
        case SSH_FXP_RENAME:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8 * oldpath = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, slen, ENC_UTF_8);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8 * newpath = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, slen, ENC_UTF_8);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_path, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                wmem_strbuf_append_printf(title, " SSH_FXP_STAT (%d) id=%d [%s] > [%s]", typ, id, oldpath, newpath);
                break;
                }
//        case SSH_FXP_READLINK:{
//                break;
//                }
//        case SSH_FXP_SYMLINK:{
//                break;
//                }
        case SSH_FXP_STATUS:{
                int id = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                int code = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_status, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_error_message_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8 * err_msg = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, slen, ENC_UTF_8);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_error_message, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_lang_tag_length, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(sftp_tree, hf_ssh_lang_tag, tvb, offset, slen, ENC_UTF_8);
                offset += slen;
                wmem_strbuf_append_printf(title, " SSH_FXP_STATUS (%d) id=%d code=%d [%s]", typ, id, code, err_msg);
                break;
                }
        case SSH_FXP_HANDLE:{
                int id = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                gchar * handle = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, slen);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_handle, tvb, offset, slen, ENC_NA);
                offset += slen;
                wmem_strbuf_append_printf(title, " SSH_FXP_HANDLE (%d) id=%d {%s}", typ, id, handle);
                break;
                }
        case SSH_FXP_DATA:{
                int id = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                int dlen = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_data_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_data, tvb, offset, dlen, ENC_NA);
                offset += dlen;
                wmem_strbuf_append_printf(title, " SSH_FXP_DATA (%d) id=%d len=%d", typ, id, dlen);
                break;
                }
        case SSH_FXP_NAME:{
                wmem_strbuf_append_printf(title, " SSH_FXP_NAME (%d)", typ);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint count = tvb_get_ntohl(tvb, offset) ;
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_name_count, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint cnt;
                for(cnt=0;cnt<count;cnt++){
                        slen = tvb_get_ntohl(tvb, offset) ;
                        proto_tree_add_item(sftp_tree, hf_ssh_sftp_name_fn_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(sftp_tree, hf_ssh_sftp_name_fn, tvb, offset, slen, ENC_UTF_8);
                        offset += slen;
                        slen = tvb_get_ntohl(tvb, offset) ;
                        proto_tree_add_item(sftp_tree, hf_ssh_sftp_name_ln_len, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(sftp_tree, hf_ssh_sftp_name_ln, tvb, offset, slen, ENC_UTF_8);
                        offset += slen;
                        slen = dissect_sftp_attrs(tvb, pinfo, offset, sftp_tree);
                        offset += slen;
                }
                break;
                }
        case SSH_FXP_ATTRS:{
                int id = tvb_get_ntohl(tvb, offset);
                wmem_strbuf_append_printf(title, " SSH_FXP_ATTRS (%d) id=%d", typ, id);
                proto_tree_add_item(sftp_tree, hf_ssh_sftp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                slen = dissect_sftp_attrs(tvb, pinfo, offset, sftp_tree);
                proto_item_set_len(sftp_tree, slen);
                offset += slen;
                break;
                }
//        case SSH_FXP_EXTENDED:{
//                break;
//                }
//        case SSH_FXP_EXTENDED_REPLY:{
//                break;
//                }
        default:{
                wmem_strbuf_append_printf(title, " unknown (%d)", typ);
                offset += plen;
                break;
                }
        }
        proto_item_set_text(sftp_tree, "%s", wmem_strbuf_get_str(title));
        proto_item_set_len(sftp_tree, plen+4);
        return offset;
}

static int dissect_sftp_attrs(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree)
{
        wmem_strbuf_t *title = wmem_strbuf_new(wmem_packet_scope(), "SFTP attributes");
        proto_item * sftp_attrs_tree = proto_tree_add_subtree(msg_type_tree, packet_tvb, offset, -1, ett_sftp_attrs, NULL, NULL);

        int offset0 = offset;
        guint flags = tvb_get_ntohl(packet_tvb, offset) ;
        proto_tree_add_item(sftp_attrs_tree, hf_ssh_sftp_attrs_flags, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        if(flags & SSH_FILEXFER_ATTR_SIZE){
                proto_tree_add_item(sftp_attrs_tree, hf_ssh_sftp_attrs_size, packet_tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += 8;
        }
        if(flags & SSH_FILEXFER_ATTR_UIDGID){
                proto_tree_add_item(sftp_attrs_tree, hf_ssh_sftp_attrs_uid, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }
        if(flags & SSH_FILEXFER_ATTR_UIDGID){
            proto_tree_add_item(sftp_attrs_tree, hf_ssh_sftp_attrs_gid, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if(flags & SSH_FILEXFER_ATTR_PERMISSIONS){
            proto_tree_add_item(sftp_attrs_tree, hf_ssh_sftp_attrs_permissions, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if(flags & SSH_FILEXFER_ATTR_ACMODTIME){
            proto_tree_add_item(sftp_attrs_tree, hf_ssh_sftp_attrs_atime, packet_tvb, offset, 4, ENC_TIME_SECS);
            offset += 4;
        }
        if(flags & SSH_FILEXFER_ATTR_ACMODTIME){
            proto_tree_add_item(sftp_attrs_tree, hf_ssh_sftp_attrs_mtime, packet_tvb, offset, 4, ENC_TIME_SECS);
            offset += 4;
        }
        if(flags & SSH_FILEXFER_ATTR_EXTENDED){
            proto_tree_add_item(sftp_attrs_tree, hf_ssh_sftp_attrs_extended_count, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }

        proto_item_set_text(sftp_attrs_tree, "%s", wmem_strbuf_get_str(title));
        proto_item_set_len(sftp_attrs_tree, offset - offset0);

        return offset - offset0;

(void)pinfo;
}

void
proto_register_sftp(void)
{
    static hf_register_info hf[] = {
        { &hf_ssh_sftp_len,
          { "SFTP packet length", "sftp.packet_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_type,
          { "SFTP packet type", "sftp.packet_type",
            FT_UINT8, BASE_DEC, VALS(ssh2_sftp_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_version,
          { "SFTP version", "sftp.version",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_id,
          { "SFTP id", "sftp.id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_path_len,
          { "SFTP path length", "sftp.path_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_path,
          { "SFTP path", "sftp.path",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_pflags,
          { "SFTP pflags", "sftp.pflags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_name_count,
          { "SFTP count", "sftp.name_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_name_fn_len,
          { "SFTP name file name length", "sftp.name_fn_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_name_fn,
          { "SFTP name file name", "sftp.name_fn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_name_ln_len,
          { "SFTP name long name length", "sftp.name_ln_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_name_ln,
          { "SFTP name long name", "sftp.name_ln",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_attrs_flags,
          { "SFTP attributes flags", "sftp.attrs.flags",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_attrs_size,
          { "SFTP attributes file size", "sftp.attrs.size",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_attrs_uid,
          { "SFTP attributes uid", "sftp.attrs.uid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_attrs_gid,
          { "SFTP attributes gid", "sftp.attrs.gid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_attrs_permissions,
          { "SFTP attributes permissions", "sftp.attrs.permissions",
            FT_UINT32, BASE_OCT, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_attrs_atime,
          { "SFTP attributes access time", "sftp.attrs.atime",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_attrs_mtime,
          { "SFTP attributes modification time", "sftp.attrs.mtime",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_attrs_extended_count,
          { "SFTP attributes extended count", "sftp.attrs.extended_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_offset,
          { "SFTP offset", "sftp.offset",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_length,
          { "SFTP length", "sftp.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_handle_len,
          { "SFTP handle length", "sftp.handle_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_handle,
          { "SFTP handle", "sftp.handle",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_status,
          { "SFTP error/status code", "sftp.status",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_error_message_len,
          { "SFTP error message length", "sftp.error_message_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_error_message,
          { "SFTP error message", "sftp.error_message",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_data_len,
          { "SFTP data length", "sftp.data_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_sftp_data,
          { "SFTP data", "sftp.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_lang_tag_length,
          { "Language tag length", "sftp.lang_tag_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_lang_tag,
          { "Language tag", "sftp.lang_tag",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},


    /* Fragment entries */
    { &hf_sftp_data_fragments,
      { "DATA fragments", "sftp.data.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, "Message fragments", HFILL } },

    { &hf_sftp_data_fragment,
      { "DATA fragment", "sftp.data.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, "Message fragment", HFILL } },

    { &hf_sftp_data_fragment_overlap,
      { "DATA fragment overlap", "sftp.data.fragment.overlap", FT_BOOLEAN,
        BASE_NONE, NULL, 0x0, "Message fragment overlap", HFILL } },

    { &hf_sftp_data_fragment_overlap_conflicts,
      { "DATA fragment overlapping with conflicting data",
        "sftp.data.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL,
        0x0, "Message fragment overlapping with conflicting data", HFILL } },

    { &hf_sftp_data_fragment_multiple_tails,
      { "DATA has multiple tail fragments", "sftp.data.fragment.multiple_tails",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Message has multiple tail fragments", HFILL } },

    { &hf_sftp_data_fragment_too_long_fragment,
      { "DATA fragment too long", "sftp.data.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Message fragment too long", HFILL } },

    { &hf_sftp_data_fragment_error,
      { "DATA defragmentation error", "sftp.data.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, "Message defragmentation error", HFILL } },

    { &hf_sftp_data_fragment_count,
      { "DATA fragment count", "sftp.data.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },

    { &hf_sftp_data_reassembled_in,
      { "Reassembled DATA in frame", "sftp.data.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, "This DATA fragment is reassembled in this frame", HFILL } },

    { &hf_sftp_data_reassembled_length,
      { "Reassembled DATA length", "sftp.data.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, "The total length of the reassembled payload", HFILL } },
    };

    static gint *ett[] = {
        &ett_sftp,
        &ett_sftp_attrs,
        &ett_sftp_data_fragment,
        &ett_sftp_data_fragments,
    };

    proto_sftp = proto_register_protocol("SFTP Protocol", "SFTP", "sftp");
    proto_register_field_array(proto_sftp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    reassembly_table_register(&sftp_reassembly_table, &addresses_ports_reassembly_table_functions);

    sftp_handle = register_dissector("sftp", dissect_sftp, proto_sftp);
}
