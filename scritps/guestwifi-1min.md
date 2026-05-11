/ip/firewall/filter/add chain=forward src-address-list=GuestBanList action=drop comment="Block Banned Guests" disabled=no

:local targetSSID "GuestWiFi"
:local maxUptime 60
:local banListName "GuestBanList"
:local banDuration 300

:log info "BanGuestClients: Start"

:local clients [/interface wifi registration-table find]

:if ([:len $clients] = 0) do={
    :log info "BanGuestClients: No clients"
    :return
}

:foreach client in=$clients do={

    :local mac [/interface wifi registration-table get $client mac-address]
    :local ssid [/interface wifi registration-table get $client ssid]
    :local uptime [/interface wifi registration-table get $client uptime]

    # continue —  if
    :if ($ssid = $targetSSID) do={

        :if ($uptime >= $maxUptime) do={

            :local ip ""

            :local lease [/ip dhcp-server lease find where mac-address=$mac]
            :if ([:len $lease] > 0) do={
                :set ip [/ip dhcp-server lease get $lease address]
            }

            :if ($ip = "") do={
                :local arp [/ip arp find where mac-address=$mac]
                :if ([:len $arp] > 0) do={
                    :set ip [/ip arp get $arp address]
                }
            }

            :if ($ip != "") do={

                :log info ("BanGuestClients: BAN " . $mac . " IP=" . $ip)

                /ip firewall address-list add \
                    list=$banListName \
                    address=$ip \
                    timeout=$banDuration

                /interface wifi registration-table remove $client
            }
        }
    }
}

:log info "BanGuestClients: End"
