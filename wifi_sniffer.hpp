/*
 * This file is part of VoidCipher (enhanced capibaraZero)
 * (https://github.com/menevia16a/VoidCipher). Copyright (c) 2024 Josiah
 * Watkins.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include "FS.h"
#include "esp_event.h"
#include "esp_wifi.h"

class WifiSniffer {
  private:
    uint8_t mac_address[6];

    void set_random_mac();

  public:
    WifiSniffer(const char* filename, FS SD);
    WifiSniffer(const char* filename, FS SD, int ch);
    WifiSniffer(const char* filename, FS SD, uint8_t* bssid, int ch,
                bool handshake_capture_mode = false);
    ~WifiSniffer();

    int get_sniffed_packets();
    void clean_sniffed_packets();
};

#endif