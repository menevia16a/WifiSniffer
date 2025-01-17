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

#include "wifi_sniffer.hpp"

#include <TimeLib.h>

#include "PCAP.h"
#include "WiFi.h"
#include "driver/gpio.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "lwip/err.h"
#include "nvs_flash.h"

int sniffed_packet_count = 0;
static PCAP pcap = PCAP();
static unsigned long int last_save = millis();
static QueueHandle_t packetQueue = NULL;

static void packet_processing_task(void* pv) {
    wifi_promiscuous_pkt_t* pkt;

    while (true) {
        if (xQueueReceive(packetQueue, &pkt, portMAX_DELAY)) {
            Serial.println("Processing packet...");
            wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;
            uint32_t packetLength = ctrl.sig_len;

            if (packetLength > 2500) {
                Serial.println("Dropping oversized packet");
                free(pkt);

                continue;
            }

            pcap.newPacketSD(ctrl.timestamp, ctrl.timestamp, packetLength,
                             pkt->payload);
            sniffed_packet_count++;

            Serial.printf("Processed packet #%d\n", sniffed_packet_count);
            free(pkt);
        }

        vTaskDelay(pdMS_TO_TICKS(1)); // Yield to other tasks
    }
}

static void cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MISC)
        return;

    if (packetQueue == NULL) {
        Serial.println("Queue is not initialized, dropping packet");

        return;
    }

    wifi_promiscuous_pkt_t* pkt =
        (wifi_promiscuous_pkt_t*)malloc(sizeof(wifi_promiscuous_pkt_t));

    if (!pkt) {
        Serial.println("Failed to allocate memory for packet");

        return;
    }

    memcpy(pkt, buf, sizeof(wifi_promiscuous_pkt_t));

    BaseType_t status = xQueueSendToBackFromISR(packetQueue, &pkt, NULL);

    if (status != pdPASS) {
        Serial.println("Queue full, dropping packet");
        free(pkt);
    } else {
        Serial.println("Packet enqueued");
    }
}

uint8_t _bssid[6];

static void cb_bssid(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MISC)
        return; // Ignore misc packets

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

    // Packet too long
    if (ctrl.sig_len > 2500)
        return;

    // Compare addr1, addr2, and addr3 with the saved BSSID
    if (memcmp(&pkt->payload[4], _bssid, 6) != 0 &&
        memcmp(&pkt->payload[10], _bssid, 6) != 0 &&
        memcmp(&pkt->payload[18], _bssid, 6) != 0)
        return;

    // Allocate memory for the packet and enqueue it
    wifi_promiscuous_pkt_t* pkt_copy =
        (wifi_promiscuous_pkt_t*)malloc(sizeof(wifi_promiscuous_pkt_t));

    if (!pkt_copy) {
        Serial.println("Failed to allocate memory for packet");

        return;
    }

    memcpy(pkt_copy, buf, sizeof(wifi_promiscuous_pkt_t));

    BaseType_t status = xQueueSendToBackFromISR(packetQueue, &pkt_copy, NULL);

    if (status != pdPASS) {
        Serial.println("Failed to enqueue packet");
        free(pkt_copy); // Free memory if the queue is full
    }
}

static void cb_handshake_capture(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = static_cast<wifi_promiscuous_pkt_t*>(buf);
    wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;

    // Ignore non-management or non-data packets
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA)
        return;

    // Ignore packets that are too short or too long
    if (ctrl.sig_len < 26 || ctrl.sig_len > 2500)
        return;

    const char* type_str;

    switch (type) {
    case WIFI_PKT_MGMT:
        type_str = "Management";
        break;
    case WIFI_PKT_DATA:
        type_str = "Data";
        break;
    default:
        type_str = "Unknown";
    }

    Serial.printf("Packet detected: Type: %s, Length: %d\n", type_str,
                  ctrl.sig_len);
    Serial.printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                  pkt->payload[10], pkt->payload[11], pkt->payload[12],
                  pkt->payload[13], pkt->payload[14], pkt->payload[15]);

    // BSSID filtering (addr3 should match target BSSID)
    if (memcmp(&pkt->payload[10], _bssid, 6) != 0) // Check addr3
        return;

    // Check for EAPOL frames (0x888E at payload offset 24+)
    if (ctrl.sig_len >= 26 && pkt->payload[24] == 0x88 &&
        pkt->payload[25] == 0x8E) {
        Serial.println("EAPOL frame detected!");

        // Save EAPOL packet to file or memory
        uint32_t timestamp = now();
        uint32_t microseconds = (unsigned int)(micros() - millis() * 1000);

        pcap.newPacketSD(timestamp, microseconds, ctrl.sig_len, pkt->payload);
        sniffed_packet_count++;

        // Flush PCAP file every 2 seconds
        if (millis() - last_save >= 2000) {
            pcap.flushFile();
            last_save = millis();
        }
    }
}

WifiSniffer::WifiSniffer(const char* filename, FS SD) {
    // Create a queue for packet processing
    packetQueue = xQueueCreate(100, sizeof(wifi_promiscuous_pkt_t*));

    if (!packetQueue) {
        Serial.println("Failed to create packet queue!");

        return;
    }

    WiFi.mode(WIFI_MODE_AP);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(cb);
    esp_wifi_set_promiscuous(true);

    bool promiscuous;
    esp_wifi_get_promiscuous(&promiscuous);
    Serial.printf("Promiscuous mode: %s\n",
                  promiscuous ? "Enabled" : "Disabled");

    // Set custom mac for better stealth
    set_random_mac();
    esp_wifi_set_mac(WIFI_IF_AP, mac_address);

    pcap.filename = filename;
    pcap.openFile(SD);
    xTaskCreate(&packet_processing_task, "packet_processing_task", 4096, this,
                5, NULL);
}

WifiSniffer::WifiSniffer(const char* filename, FS SD, int ch) {
    // Create a queue for packet processing
    packetQueue = xQueueCreate(100, sizeof(wifi_promiscuous_pkt_t*));

    if (!packetQueue) {
        Serial.println("Failed to create packet queue!");

        return;
    }

    WiFi.mode(WIFI_MODE_AP);
    esp_wifi_set_channel(ch, (wifi_second_chan_t)NULL);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(cb);

    bool promiscuous;
    esp_wifi_get_promiscuous(&promiscuous);
    Serial.printf("Promiscuous mode: %s\n",
                  promiscuous ? "Enabled" : "Disabled");

    // Set custom mac for better stealth
    set_random_mac();
    esp_wifi_set_mac(WIFI_IF_AP, mac_address);

    pcap.filename = filename;
    pcap.openFile(SD);
    xTaskCreate(&packet_processing_task, "packet_processing_task", 4096, this,
                5, NULL);
}

WifiSniffer::WifiSniffer(const char* filename, FS SD, uint8_t* bssid, int ch,
                         bool handshake_capture_mode) {
    // Create a queue for packet processing
    packetQueue = xQueueCreate(100, sizeof(wifi_promiscuous_pkt_t*));

    if (!packetQueue) {
        Serial.println("Failed to create packet queue!");

        return;
    }

    WiFi.mode(WIFI_MODE_AP);
    memcpy(_bssid, bssid, sizeof(uint8_t) * 6);
    esp_wifi_set_channel(ch, (wifi_second_chan_t)NULL);
    esp_wifi_set_promiscuous(true);

    if (!handshake_capture_mode)
        esp_wifi_set_promiscuous_rx_cb(cb_bssid);
    else
        esp_wifi_set_promiscuous_rx_cb(cb_handshake_capture);

    bool promiscuous;
    esp_wifi_get_promiscuous(&promiscuous);
    Serial.printf("Promiscuous mode: %s\n",
                  promiscuous ? "Enabled" : "Disabled");

    // Set custom mac for better stealth
    set_random_mac();
    esp_wifi_set_mac(WIFI_IF_AP, mac_address);

    pcap.filename = filename;
    pcap.openFile(SD);
    xTaskCreate(&packet_processing_task, "packet_processing_task", 4096, this,
                5, NULL);
}

WifiSniffer::~WifiSniffer() {
    esp_wifi_set_promiscuous(false);
    WiFi.softAPdisconnect(true);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    pcap.closeFile();
    clean_sniffed_packets();

    // Delete the packet processing task and queue
    if (packetQueue != NULL) {
        vQueueDelete(packetQueue);

        packetQueue = NULL;
    }
}

int WifiSniffer::get_sniffed_packets() { return sniffed_packet_count; };

void WifiSniffer::clean_sniffed_packets() { sniffed_packet_count = 0; };

void WifiSniffer::set_random_mac() {
    // First byte: clear bit 0 (not locally administered) and
    // bit 1 (not multicast)
    mac_address[0] = random(0, 255) & 0xFC;

    // Randomize remaining 5 bytes
    for (int i = 1; i < 6; i++)
        mac_address[i] = random(0, 255);
}
