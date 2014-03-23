/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PksZadanie.equip;

import java.util.ArrayList;

/**
 *
 * @author Mathis
 */
public class Communication {

    private ArrayList<CommunicationChannel> comList = new ArrayList<>();
    private Frame frame;
    public Communication(Frame frame) {
        this.frame = frame;
        createCommunication(frame);
    }

    public void createCommunication(Frame frame) {
        if (comList.isEmpty()) {
            CommunicationChannel communication = new CommunicationChannel(frame);
            frame.setComId(comList.size());
            frame.setCommunicationId(0);
            comList.add(communication);
        } else {
            Integer foundComm = 0;
            Integer iterator = 0;
            for (CommunicationChannel temp : comList) {
                if ((DataTypeHelper.ipAdressConvertor(temp.getSourceIpAdress()).equalsIgnoreCase(DataTypeHelper.ipAdressConvertor(frame.getIpv4parser().getSourceIPbyte())) && DataTypeHelper.ipAdressConvertor(temp.getDestinationIpAdress()).equalsIgnoreCase(DataTypeHelper.ipAdressConvertor(frame.getIpv4parser().getDestinationIPbyte()))) || (DataTypeHelper.ipAdressConvertor(temp.getSourceIpAdress()).equalsIgnoreCase(DataTypeHelper.ipAdressConvertor(frame.getIpv4parser().getDestinationIPbyte())) && DataTypeHelper.ipAdressConvertor(temp.getDestinationIpAdress()).equalsIgnoreCase(DataTypeHelper.ipAdressConvertor(frame.getIpv4parser().getSourceIPbyte())))) {
                    //  if ((DataTypeHelper.macAdressConvertor(temp.getDestinationMacAdress()).equalsIgnoreCase(frame.getDestinationMAC()) && DataTypeHelper.macAdressConvertor(temp.getSourceMacAdress()).equalsIgnoreCase(frame.getSourceMAC())) || (DataTypeHelper.macAdressConvertor(temp.getSourceMacAdress()).equalsIgnoreCase(DataTypeHelper.macAdressConvertor(frame.getDestinationMACByte())) && DataTypeHelper.macAdressConvertor(temp.getDestinationMacAdress()).equalsIgnoreCase(frame.getSourceMAC()))) {
                    if (frame.getProtocol().equalsIgnoreCase(temp.getTcpCommList().get(0).getProtocol())) {
                        frame.setComId(iterator);
                        frame.setCommunicationId(temp.getTcpCommList().size());
                        temp.getTcpCommList().add(frame);
                        foundComm = 1;
                    }
                    // }
                }
                iterator++;
            }
            if (foundComm == 0) {
                CommunicationChannel communication = new CommunicationChannel(frame);
                frame.setComId(comList.size());
                frame.setCommunicationId(0);
                comList.add(communication);
            }
        }
    }

    public ArrayList<CommunicationChannel> getComList() {
        return comList;
    }

}
