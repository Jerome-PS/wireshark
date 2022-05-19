/* packet-ssh-shell.c
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
 * Note:  support for SSH Shell.
 *
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_ssh_shell(void);

static int proto_ssh_shell = -1;

static int hf_ssh_shell_data = -1;

static dissector_handle_t ssh_shell_handle;

static int dissect_ssh_shell(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

static int dissect_ssh_shell(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
        int offset = 0;
        guint consumed = tvb_reported_length_remaining(tvb, offset);

(void)pinfo;
(void)data;

        proto_tree_add_item(tree, hf_ssh_shell_data, tvb, offset, consumed, ENC_NA);

        return offset + consumed;
}

void
proto_register_ssh_shell(void)
{
    static hf_register_info hf[] = {

        { &hf_ssh_shell_data,
          { "SSH Shell data", "ssh-shell.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
    };

    proto_ssh_shell = proto_register_protocol("SSH shell Protocol", "SSH-Shell", "ssh-shell");
    proto_register_field_array(proto_ssh_shell, hf, array_length(hf));

    ssh_shell_handle = register_dissector("ssh-shell", dissect_ssh_shell, proto_ssh_shell);
}
