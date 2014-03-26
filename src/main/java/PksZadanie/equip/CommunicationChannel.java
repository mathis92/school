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
    private String closingType = null;
    private Integer sourcePort = null;
    private Integer destinationPort = null;
    Frame frame;
    private Integer completed = 0;
    private Integer commId;
    Integer rst = 0;
    Integer srcPsyn = 0;
    Integer srcPfin3 = 0;
    Integer srcPfin4 = 0;
    Integer open = 0;
    Integer synOK = 0;
    Integer finOK3 = 0;
    Integer finOK4 = 0;
    Integer finOKK4 = 0;
    Integer close3 = 0;
    Integer close4 = 0;
    Integer foundSyn = 0;
    Integer foundFin3 = 0;
    Integer foundFin4 = 0;

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

        for (Frame temp : tcpCommList) {
            if (DataTypeHelper.getTcpPortFlags(temp).contains("SYN") && foundSyn.equals(0)) {
                foundSyn = 1;
                if (srcPsyn == 0) {
                    srcPsyn = temp.getIpv4parser().getTcpParser().getSourcePort();
                }
                // System.out.println("nasiel som len SYN");

            } else if (DataTypeHelper.getTcpPortFlags(temp).contains("SYN") && DataTypeHelper.getTcpPortFlags(temp).contains("ACK") && foundSyn.equals(1)) {
                if (DataTypeHelper.getTcpPortFlags(temp).contains("SYN") && srcPsyn.equals(temp.getIpv4parser().getTcpParser().getDestinationPort())) {
                    synOK = 1;
                }
                // System.out.println("nasiel som SYN a ACK");
            } else if (DataTypeHelper.getTcpPortFlags(temp).contains("ACK") && srcPsyn.equals(temp.getIpv4parser().getTcpParser().getSourcePort()) && synOK.equals(1) && !open.equals(1)) {
                open = 1;
                //System.out.println("nasiel som ACK");

            } else if (DataTypeHelper.getTcpPortFlags(temp).contains("RST")) {
                rst++;
            }
            segment3(temp);
            segment4(temp);
            
            
        }
        if ((open.equals(1) && (close3.equals(1) || close4.equals(1))) || (open.equals(1) && rst > 0)) {
            completed = 1;
            if (rst > 0) {
                closingType = "reset close";
            }
            if (close3.equals(1)) {
                closingType = "three segment close";
            }
            if (close4.equals(1)) {
                closingType = "four segment connection close";
            }

        }
        if (closingType == null) {
            closingType = "incomplete connection";
        }

    }

    public void segment4(Frame temp) {
        if (DataTypeHelper.getTcpPortFlags(temp).contains("FIN") && DataTypeHelper.getTcpPortFlags(temp).contains("ACK") && foundFin4.equals(0)) {
            foundFin4 = 1;
            if (srcPfin4 == 0) {
                srcPfin4 = temp.getIpv4parser().getTcpParser().getSourcePort();
            }
            // System.out.println("nasiel som FIN a ACK");
        } else if (!DataTypeHelper.getTcpPortFlags(temp).contains("FIN") && DataTypeHelper.getTcpPortFlags(temp).contains("ACK") && foundFin4.equals(1) && !finOK4.equals(1) && !finOKK4.equals(1)) {
            if (DataTypeHelper.getTcpPortFlags(temp).contains("ACK") && srcPfin4.equals(temp.getIpv4parser().getTcpParser().getDestinationPort())) {
                finOK4 = 1;
            }
            //System.out.println("nasiel som ACK");
        } else if (DataTypeHelper.getTcpPortFlags(temp).contains("FIN") && DataTypeHelper.getTcpPortFlags(temp).contains("ACK") && srcPfin4.equals(temp.getIpv4parser().getTcpParser().getDestinationPort()) && finOK4.equals(1)) {
            finOKK4 = 1;
            // System.out.println("nasiel som FIN a ACK opacne");
        } else if (DataTypeHelper.getTcpPortFlags(temp).contains("ACK") && !close4.equals(1) && finOK4.equals(1) && finOKK4.equals(1) && srcPfin4.equals(temp.getIpv4parser().getTcpParser().getSourcePort())) {
            close4 = 1;
            //   System.out.println("nasiel som ACK naspet");

        }
    }

    public void segment3(Frame temp) {
        if (DataTypeHelper.getTcpPortFlags(temp).contains("FIN") && DataTypeHelper.getTcpPortFlags(temp).contains("ACK") && foundFin3.equals(0)) {
            foundFin3 = 1;
            if (srcPfin3 == 0) {
                srcPfin3 = temp.getIpv4parser().getTcpParser().getSourcePort();
                System.out.println("nasiel som FIN ACK");
            }

        } else if (DataTypeHelper.getTcpPortFlags(temp).contains("FIN") && DataTypeHelper.getTcpPortFlags(temp).contains("ACK") && foundFin3.equals(1)) {
            if (DataTypeHelper.getTcpPortFlags(temp).contains("FIN") && srcPfin3.equals(temp.getIpv4parser().getTcpParser().getDestinationPort())) {
                finOK3 = 1;
                System.out.println("nasiel som FIN ACK opacne");
            }
        } else if (DataTypeHelper.getTcpPortFlags(temp).contains("ACK") && srcPfin3.equals(temp.getIpv4parser().getTcpParser().getSourcePort()) && finOK3.equals(1) && !close3.equals(1)) {
            close3 = 1;
            System.out.println("nasiel som ACK");
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

    public String getClosingType() {
        return closingType;
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
