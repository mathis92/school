


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PksZadanie.equip;

import PksZadanie.AnalyserTcpParserPanel;
import java.util.ArrayList;
import java.util.Arrays;

/**
 *
 * @author Mathis
 */
public class TcpCommunication {

    private ArrayList<CommunicationChannel> comList = new ArrayList<>();
    //  private Frame frame;
    private Integer found = 0;
    private ArrayList<Frame> list = new ArrayList<>();
    private AnalyserTcpParserPanel panel = null;

    public TcpCommunication(Frame frame) {
        //this.frame = frame;
        found = 1;
        createCommunication(frame);

    }

    public void createCommunication(Frame frame) {
        list.add(frame);
        if (comList.isEmpty()) {
            CommunicationChannel communication = new CommunicationChannel(frame);
            frame.setComId(comList.size());
            frame.setCommunicationId(0);
            comList.add(communication);
        } else {
            Integer foundComm = 0;
            Integer iterator = 0;
            for (CommunicationChannel temp : comList) {
                if ((Arrays.equals(temp.getSourceIpAdress(), frame.getIpv4parser().getSourceIPbyte()) && Arrays.equals(temp.getDestinationIpAdress(), frame.getIpv4parser().getDestinationIPbyte())) || (Arrays.equals(temp.getSourceIpAdress(), frame.getIpv4parser().getDestinationIPbyte()) && Arrays.equals(temp.getDestinationIpAdress(), frame.getIpv4parser().getSourceIPbyte()))) {
                    if (frame.getApplicationProtocol().equalsIgnoreCase(temp.getTcpCommList().get(0).getApplicationProtocol())) {

                        Integer fs = frame.getIpv4parser().getTcpParser().getSourcePort();
                        Integer fd = frame.getIpv4parser().getTcpParser().getDestinationPort();
                        Integer ts = temp.getSourcePort();
                        Integer td = temp.getDestinationPort();
                        if ((fs.equals(td) && fd.equals(ts)) || (fs.equals(ts) && fd.equals(td))) {
                            frame.setComId(iterator);
                            frame.setCommunicationId(temp.getTcpCommList().size());
                            temp.getTcpCommList().add(frame);
                            foundComm = 1;
                        }
                    }
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

    public void setPanel(AnalyserTcpParserPanel panel) {
        this.panel = panel;
    }

    public void setFound(Integer found) {
        this.found = found;
    }

    public AnalyserTcpParserPanel getPanel() {
        return panel;
    }

    public ArrayList<Frame> getList() {
        return list;
    }

    public Integer getFound() {
        return found;
    }

}
