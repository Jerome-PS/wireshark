/* packet-ssh.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SSH_H__
#define __PACKET_SSH_H__

#include "ws_symbol_export.h"
#include <epan/packet.h>

typedef struct {
    guint   channel_recipient;
    guint   channel_sender;
    guint   packet_id;
} ssh_channel;

#endif  /* __PACKET_SSH_H__ */
