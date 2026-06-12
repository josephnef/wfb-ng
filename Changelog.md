fork: multi-stream wfb_tx (feat/multistream-tx)
-----------------------------------------------
 - One `wfb_tx` process can now serve several streams via repeatable `-y` specs
   (`u=<udp_port>|shm=<ring>,p=<radio_port>[,k=][,n=][,T=][,F=][,mcs=][,bw=][,gi=][,stbc=][,ldpc=][,vht=][,nss=]`).
   Each stream gets its own FEC encoder, session key and radiotap header on the shared
   link_id, exactly as N separate processes would - but in one event loop. Without `-y`
   nothing changes.
 - Spec order is strict drain priority (first = highest): under radio saturation the
   socket buffers of later streams overflow first. Intended for layered video (e.g.
   SVC-T from OpenIPC waybeam_venc): the always-decodable base layer is stream 0 with
   strong FEC, droppable enhancement layers ride behind it with light FEC.
 - `shm=<ring_name>` stream input: attach to an OpenIPC waybeam_venc shared-memory
   packet ring (`/dev/shm/<ring_name>`, vendored `src/venc_ring.{h,c}`, MIT) for a
   syscall-free producer path. Survives producer respawn via epoch-based re-attach.
 - Per-stream runtime control: `wfb_tx_cmd <port> {set,get}_{fec,radio}_stream -r <radio_port> ...`
   (new control-port commands CMD_*_STREAM; legacy commands keep addressing the first
   stream). Unknown radio_port answers ENODEV.
 - Per-stream stdout stats: `PKT_S` / `TX_ANT_S` lines tagged with the radio_port, plus
   the legacy aggregate `PKT` / `TX_ANT` lines so existing stats parsers keep working.

23.08 upcoming release
----------------------
 - Mavlink parser speedup. Instead of using standard full-featured (and slow mavlink parser) now use fast packet splitter.
 - Added callbacks for vehicle arm/disarm. You can use it for camera recording activation.
 - Added mavlink tcp proxy. Now it is possible to use backup link via LTE modem or connect onboard computer without external mavlink-router.
   To connect as backup link in QGC use tcp connection to port 5760 and check "high latency link" checkbox.

 - Self-injected frames are ignored now in case when TX and RX use the same radio port.
 - Added cross-build support via qemu + docker.
 - Improved udp socket buffer overflow handling:

    1. Added option for socket buffer size for incoming messages on the tx side.
    2. Check for socket buffer overflow and show warnings.

    You can set socket buffer size system-wide via `net.core.rmem_default` or via `-R` option in `wfb_tx`.

 - Warn if incoming packet > `MAX_PAYLOAD_SIZE` and will be truncated.
 - Added support for RTS frames. Now you can choose between data and rts frames when transmit packages.
 - Added default route option for IP tunnel.
 - Large refactoring of WFB-ng control-plane:

    1. Added support for multiple profiles and profile inheritance (no need to have multiple copies of wifibroadcast.cfg).
    2. No hardcoded streams (video/mavlink/tunnel) anymore. You can define own profiles and any number of data streams can be added/removed to profiles without any code change.
    3. Multiple profiles can be active simultaneously (no need to run multiple instances of wfb-server when using the same wifi adapters for different links). For example: `systemctl enable wifbroadcast@gs1:gs2:gs3:gs4`
    4. Added support for raw udp data streams. They don't use any frame aggregation or mavlink injection.
    5. TX antenna selection is now `link_domain` wide - for example one-way `udp_proxy` TX will use active antenna selected by other RX streams.
    6. Added mirror mode. Use it only if you use different frequency channels for multiple cards. In this mode each packet will be send via all cards (by default only active cards send packets). This allow to add redundancy for multi-frequency link

    Compatibility:
    This commit maintain both radio and config compatibility with previous version.
    So you can use previous version of wfb-ng on the other link side and import most of your customizations from /etc/wifibroadcast.cfg
    The only config incompatible change is that `common.link_id` was moved to profile section and renamed to `link_domain`.

 - Added support for multiple directed antennas on both ends and different frequency channels on different cards:
     1. `common.wifi_channel` can now be not only `int`, but also `dict`. In this case, you can specify different frequency channels for different cards. For example: `{'wlan0': 161, 'wlan1': 165}`
     2. Tunnel keepalive package is now transmitted through all cards, not just through the active

     These allow you to use multiple frequency channels at the same time if you have multiple cards on each end. For example, you can use 2.4 + 5.8 GHz.
     Or you can use multiple directional antennas on both sides of the link, as point (2) solves the chicken and egg problem of allowing directional antennas
     (and/or different frequency channels) to agree on the direction (and/or frequency) of transmission

     In the case of different frequency channels, the solution is not quite ideal, because only RSSI is used to select the active channel, and the number of errors is ignored. Use mirror mode in this case.
