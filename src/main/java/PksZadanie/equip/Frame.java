/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PksZadanie.equip;

import PksZadanie.AnalyserArpParserPanel;
import PksZadanie.analysers.ArpParser;
import PksZadanie.analysers.IpV4Parser;
import org.krakenapps.pcap.packet.PcapPacket;
import org.krakenapps.pcap.util.Buffer;
import pkszadanie.analysers.Analyser;

/**
 *
 * @author Mathis
 */
public final class Frame {

    private String sourceMAC;
    private final byte[] sourceMACByte = new byte[6];
    private String destinationMAC;
    private final byte[] destinationMACByte = new byte[6];
    private final Integer id;
    private final Integer frameLength;
    private final Integer frameLengthWire;
    private String frameType;
    private final PcapPacket packet;
    public Buffer buffer;
    public byte[] etherType;
    private boolean isIpV4 = false;
    private boolean isARP = false;
    public IpV4Parser ipv4;
    public ArpParser arp;
    public Analyser an;
    public Integer communicationListId;
    public Integer comId;
    public String protocol;
    public String applicationProtocol;

    public Frame(int id, PcapPacket packet, Analyser an) {
        this.id = id;
        this.packet = packet;
        if (packet.getPacketHeader().getOrigLen()+4 <= 64) {
            frameLength = packet.getPacketHeader().getOrigLen();
            frameLengthWire = 64;
        } else {
            frameLength = packet.getPacketHeader().getOrigLen();
            frameLengthWire = packet.getPacketHeader().getOrigLen() + 4;
        }
        buffer = packet.getPacketData();
        this.an = an;
        this.findMacAdress(0);
        this.findMacAdress(1);
        this.findEtherType();
    }

    public void findEtherType() {
        Integer etherTypeInt;
        etherType = new byte[]{buffer.get(), buffer.get()};
        etherTypeInt = DataTypeHelper.toInt(etherType);

        if (etherTypeInt >= 1536) {
            frameType = "Ethernet II";
            if (etherTypeInt == 2048) {
                isIpV4 = true;
                ipv4 = new IpV4Parser(buffer);
                ipv4.analyse();
            }
            else if (etherTypeInt == 2054) {
                isARP = true;
                arp = new ArpParser(buffer);
                arp.analyse();
            }

        }
        if (etherTypeInt <= 1500) {
            byte temp = buffer.get();
            if ((temp & 0xff) == 0xFF) {
                byte temp2 = buffer.get();
                if ((temp2 & 0xff) == 0xFF) {
                    frameType = "Novell raw IEEE 802.3";
                }
            } else if ((temp & 0xff) == 0xAA) {
                    byte temp2 = buffer.get();
                if ((temp2 & 0xff) == 0xAA) {
                    frameType = "IEEE 802.2 SNAP";
                }
            } else {
                frameType = "IEEE 802.2 LLC";
            }
        }
    }

    public void findMacAdress(Integer type) {
        if (type == 1) {
            //zdrojova MAC adresa

            for (int i = 0; i < 6; i++) {
                byte temp = buffer.get();
                // DataTypeHelper macbyte = new DataTypeHelper(temp);
                sourceMACByte[i] = temp;
                if (sourceMAC != null) {
                    sourceMAC = sourceMAC + " " + DataTypeHelper.bToString(temp);
                } else {
                    sourceMAC = DataTypeHelper.bToString(temp);
                }
            }
        }
        if (type == 0) {
            // destination MAC adress
            for (int i = 0; i < 6; i++) {
                byte temp1 = buffer.get();
                //       DataTypeHelper macbyte1 = new DataTypeHelper(temp1);
                destinationMACByte[i] = temp1;
                if (destinationMAC != null) {
                    destinationMAC = destinationMAC + " " + DataTypeHelper.bToString(temp1);
                } else {
                    destinationMAC = DataTypeHelper.bToString(temp1);
                }
            }
        }
    }

    public boolean getIsArp() {
        return isARP;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setApplicationProtocol(String applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public String getApplicationProtocol() {
        return applicationProtocol;
    }
    
        public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public Integer getComId() {
        return comId;
    }

    public void setComId(Integer comId) {
        this.comId = comId;
    }

    public void setCommunicationId(Integer communicationId) {
        this.communicationListId = communicationId;
    }

    public Integer getCommunicationId() {
        return communicationListId;
    }

    public ArpParser getArpParser() {
        return arp;
    }

    public boolean getIsIpv4() {
        return isIpV4;
    }

    public IpV4Parser getIpv4parser() {
        return ipv4;
    }

    public Buffer getBuffer() {
        return buffer;
    }

    public byte[] getDestinationMACByte() {
        return destinationMACByte;
    }

    public byte[] getSourceMACByte() {
        return sourceMACByte;
    }

    public String getDestinationMAC() {
        return destinationMAC;
    }

    public Integer getFrameLength() {
        return frameLength;
    }

    public Integer getFrameLengthWire() {
        return frameLengthWire;
    }

    public String getFrameType() {
        return frameType;
    }

    public int getId() {
        return id;
    }

    public String getSourceMAC() {
        return sourceMAC;
    }

}
