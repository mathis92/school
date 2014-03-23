/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PksZadanie.equip;

import java.util.ArrayList;

public class CommunicationChannel {

    private final byte[] sourceIpAdress;
    private final byte[] DestinationIpAdress;
    private final byte[] sourceMacAdress;
    private final byte[] destinationMacAdress;
    private final ArrayList<Frame> tcpCommList;
    Frame frame;
    private Integer completed = 0;
    private Integer commId;

    public CommunicationChannel(Frame frame) {
        this.frame = frame;
        tcpCommList = new ArrayList<>();
        sourceIpAdress = frame.getIpv4parser().getSourceIPbyte();
        DestinationIpAdress = frame.getIpv4parser().getDestinationIPbyte();
        sourceMacAdress = frame.getSourceMACByte();
        destinationMacAdress = frame.getDestinationMACByte();
        tcpCommList.add(frame);
    }

    public void checkCompleted() {
        Integer fin = 0;
        Integer rst = 0;
        for (Frame temp : tcpCommList) {
            for (String flag : DataTypeHelper.getTcpPortFlags(temp)) {
                if (flag.equalsIgnoreCase("FIN")) {
                    fin++;
                    System.out.println("nasiel som fin");
                } else if (flag.equalsIgnoreCase("RST")) {
                    rst++;
                }
            }
        }
        if (fin > 1 || rst > 0) {
            completed = 1;
        }
    }

    public Integer getCommId() {
        return commId;
    }

    public Frame getFrame() {
        return frame;
    }

    public byte[] getSourceIpAdress() {
        return sourceIpAdress;
    }

    public byte[] getDestinationIpAdress() {
        return DestinationIpAdress;
    }

    public byte[] getSourceMacAdress() {
        return sourceMacAdress;
    }

    public byte[] getDestinationMacAdress() {
        return destinationMacAdress;
    }

    public ArrayList<Frame> getTcpCommList() {
        return tcpCommList;
    }

    public Integer getCompleted() {
        return completed;
    }

}
