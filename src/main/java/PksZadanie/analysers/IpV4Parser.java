/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PksZadanie.analysers;

import PksZadanie.equip.DataTypeHelper;
import org.krakenapps.pcap.util.Buffer;

/**
 *
 * @author Mathis
 */
public class IpV4Parser extends AbstractAnalyser implements IAnalyser {

    private final byte[] sourceIPbyte = new byte[4];
    private String sourceIP;
    private String destinationIP;
    private final byte[] destinationIPbyte = new byte[4];
    private Integer ipV4length;
    private Integer ipV4theMostSentBytes = 0;
    private Integer ihl;
    private IcmpParser icmpParser;
    private byte ipv4Protocol;
    private boolean isIcmp;
    private boolean isTcp;
    private TcpParser tcpParser = null;

    public IpV4Parser(Buffer buffer) {
        super(buffer);
    }

    @Override
    public void analyse() {
        ihl = DataTypeHelper.getIhl(buffer.get());

        buffer.skip(1);
        byte[] ipv4Length = new byte[2];
        ipv4Length[0] = buffer.get();
        ipv4Length[1] = buffer.get();
        ipV4length = DataTypeHelper.toInt(ipv4Length);

        if (ihl > 5) {
            ipV4length = ihl * 4;
        }
        ipV4theMostSentBytes = ipV4length + 14;
        buffer.skip(5);
        ipv4Protocol = buffer.get();
        //      System.out.println(DataTypeHelper.singleToInt(ipv4Protocol));
        buffer.skip(2);
        for (int i = 0; i < 4; i++) {
            sourceIPbyte[i] = buffer.get();
            // DataTypeHelper newInt = new DataTypeHelper(sourceIPbyte[i]);
            if (i == 0) {
                sourceIP = DataTypeHelper.singleToInt(sourceIPbyte[i]).toString();
            } else {
                sourceIP += DataTypeHelper.singleToInt(sourceIPbyte[i]).toString();

            }
            if (i < 3) {
                sourceIP += ".";
            } else {
                sourceIP += "\n";
            }
        }
        //    System.out.println("sourceee IP " + sourceIP);
        for (int i = 0; i < 4; i++) {
            destinationIPbyte[i] = buffer.get();
            // DataTypeHelper newInt = new DataTypeHelper(destinationIPbyte[i]);
            if (i == 0) {
                destinationIP = DataTypeHelper.singleToInt(destinationIPbyte[i]).toString();
            } else {
                destinationIP += DataTypeHelper.singleToInt(destinationIPbyte[i]).toString();

            }
            if (i < 3) {
                destinationIP += ".";
            } else {
                destinationIP += "\n";
            }
        }

        if (ihl > 5) {
            buffer.skip(ihl - 20);
        }

        if (ipv4Protocol == 0x01) {
            isIcmp = true;
            icmpParser = new IcmpParser(buffer);
        }
        if (ipv4Protocol == 0x06) {
            isTcp = true;
            tcpParser = new TcpParser(buffer);
        }
    }

    public boolean getIsIcmp() {
        return isIcmp;
    }

    public TcpParser getTcpParser() {
        return tcpParser;
    }

    public boolean getIsTcp() {
        return isTcp;
    }

    public Integer getiPv4length() {
        return ipV4length;
    }

    public void setIpV4TheMostSentBytes(Integer ipV4) {
        this.ipV4theMostSentBytes = ipV4;
    }

    public Integer getIpV4theMostSentBytes() {
        return ipV4theMostSentBytes;
    }

    public byte[] getSourceIPbyte() {
        return sourceIPbyte;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public byte[] getDestinationIPbyte() {
        return destinationIPbyte;
    }

    public String getDestinationIP() {
        return destinationIP;
    }

    public IcmpParser getIcmpParser() {
        return icmpParser;
    }

}
