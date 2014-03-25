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
    private Integer sourcePort = null;
    private Integer destinationPort = null;
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
        sourcePort = DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getSourcePortByte());
        destinationPort = DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getDestinationPortByte());
        tcpCommList.add(frame);
    }

    public void checkCompleted() {
        Integer fin = 0;
        Integer rst = 0;
        Integer srcPsyn = 0;
        Integer srcPfin = 0;
        Integer open = 0;
        Integer close = 0;
        for (Frame temp : tcpCommList) {
            if (DataTypeHelper.getTcpPortFlags(temp).contains("SYN")) {
                if (srcPsyn == 0) {
                    srcPsyn = temp.getIpv4parser().getTcpParser().getSourcePort();
               //     System.out.println("nasiel som prvy SYN");
                } else {
                    if (DataTypeHelper.getTcpPortFlags(temp).contains("SYN") && srcPsyn.equals(temp.getIpv4parser().getTcpParser().getDestinationPort())) {
                        open = 1;
             //           System.out.println("nasiel som druhy SYN");
                    }
                }
            } else if (DataTypeHelper.getTcpPortFlags(temp).contains("FIN")) {
                if (srcPfin == 0) {
                    srcPfin = temp.getIpv4parser().getTcpParser().getSourcePort();
           //         System.out.println("nasiel som prvy FIN");
                } else {
                    if (DataTypeHelper.getTcpPortFlags(temp).contains("FIN") && srcPfin.equals(temp.getIpv4parser().getTcpParser().getDestinationPort())) {
                        close = 1;
                    //    System.out.println("nasiel som druhy FIN");
                    }
                }
            } else if (DataTypeHelper.getTcpPortFlags(temp).contains("RST")) {
                rst++;
            }
        }
        if((open.equals(1) && close.equals(1)) || rst > 0){
            completed = 1;
        }
            
       
        /*
         for (Frame temp : tcpCommList) {
         if (DataTypeHelper.getTcpPortFlags(temp).contains("FIN")) {
         fin++;
         } else if (DataTypeHelper.getTcpPortFlags(temp).contains("RST")) {
         rst++;
         }
         }
         if (fin > 1 || rst > 0) {
         completed = 1;
         }
         */
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

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public Integer getCompleted() {
        return completed;
    }

}
