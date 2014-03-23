/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkszadanie.analysers;

import PksZadanie.AnalyserArpParserPanel;
import PksZadanie.AnalyserGUI;
import PksZadanie.AnalyserTcpParserPanel;
import PksZadanie.AnalyserIcmpParserPanel;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import org.krakenapps.pcap.PcapInputStream;
import org.krakenapps.pcap.file.PcapFileInputStream;
import org.krakenapps.pcap.packet.PcapPacket;
import PksZadanie.AnalyserMainCheck;
import PksZadanie.AnalyserMainCheckResult;
import PksZadanie.analysers.ArpStorage;
import PksZadanie.equip.CommunicationChannel;
import PksZadanie.equip.DataTypeHelper;
import PksZadanie.equip.Frame;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import javax.swing.JLabel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

public class Analyser {

    private final AnalyserMainCheck panel;
    private final File pcap;
    private Integer i = 0;
    private ArrayList<Frame> frameList = new ArrayList<>();
    private ArrayList<Frame> arpFrameList;
    private ArrayList<Frame> longestIplist;
    private ArrayList<CommunicationChannel> comList;
    private ArrayList<Frame> httpList;
    private ArrayList<Frame> httpsList;
    private ArrayList<Frame> ftpcList;
    private ArrayList<Frame> ftpdList;
    private ArrayList<Frame> sshList;
    private ArrayList<Frame> telnetList;
    private ArrayList<ArpStorage> arpStorageFrameList;
    private ArrayList<Frame> icmpList;
    public Integer theMostBytes = 0;
    public String theMostFrequentSourceIpAdress;
    private AnalyserMainCheckResult result;
    private AnalyserArpParserPanel arpPanel = null;
    private AnalyserIcmpParserPanel icmpPanel = null;
    private AnalyserTcpParserPanel httpPanel = null;
    private AnalyserTcpParserPanel httpsPanel = null;
    private AnalyserTcpParserPanel ftpcPanel = null;
    private AnalyserTcpParserPanel sshPanel = null;
    private AnalyserTcpParserPanel ftpdPanel = null;
    private AnalyserTcpParserPanel telnetPanel = null;
    private Frame frame;
    private Integer arpFound = 0;
    private Integer icmpFound = 0;
    private Integer httpFound = 0;
    private Integer httpsFound = 0;
    private Integer ftpcFound = 0;
    private Integer ftpdFound = 0;
    private Integer sshFound = 0;
    private Integer telnetFound = 0;

    public Analyser(AnalyserMainCheck aPanel, File pcapFile, AnalyserGUI gui) {
        this.panel = aPanel;
        this.pcap = pcapFile;
        //     this.gui = gui;
    }

    public void analyzeFile() throws FileNotFoundException {
        try {
            PcapInputStream is = new PcapFileInputStream(pcap);
            frameList = new ArrayList<>();
            arpFrameList = new ArrayList<>();
            icmpList = new ArrayList<>();
            result = new AnalyserMainCheckResult();
            arpStorageFrameList = new ArrayList<>();
            httpList = new ArrayList<>();
            comList = new ArrayList<>();
            longestIplist = new ArrayList<>();
            httpsList = new ArrayList<>();
            ftpcList = new ArrayList<>();
            sshList = new ArrayList<>();
            ftpdList = new ArrayList<>();
            telnetList = new ArrayList<>();

            try {
                while (true) {
                    PcapPacket packet = is.getPacket();
                    i++;
                    frame = new Frame(i, packet, this);
                    frameList.add(frame);
                    if (frame.getIsArp()) {
                        arpFrameList.add(frame);
                        arpFound = 1;
                        if (frame.getArpParser().getOperationType().equals("ARP-Request")) {
                            ArpStorage str = new ArpStorage(frame, null);
                            arpStorageFrameList.add(str);
                        } else {
                            this.assignArpFrames(frame);
                        }

                    }
                    if (frame.getIsIpv4()) {
                        if (frame.getIpv4parser().getIsIcmp()) {
                            icmpFound = 1;
                            icmpList.add(frame);

                        }
                        if (frame.getIpv4parser().getTcpParser() != null) {
                            if (frame.getIpv4parser().getTcpParser().getIsTcp()) {
                                frame.setProtocol("TCP");
                                if (DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getDestinationPort()) == 80 || DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getSourcePort()) == 80) {
                                    frame.setApplicationProtocol("HTTP");
                                    httpList.add(frame);
                                    httpFound = 1;
                                    createCommunication(frame);
                                }
                                if (DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getDestinationPort()) == 443 || DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getSourcePort()) == 443) {
                                    frame.setApplicationProtocol("HTTPS");
                                    httpsList.add(frame);
                                    // httpFound = 1;
                                    httpsFound = 1;
                                    createCommunication(frame);
                                }
                                if (DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getDestinationPort()) == 20 || DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getSourcePort()) == 20) {
                                    frame.setApplicationProtocol("FTP-D");
                                    sshList.add(frame);
                                    sshFound = 1;
                                    createCommunication(frame);
                                }
                                if (DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getDestinationPort()) == 21 || DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getSourcePort()) == 21) {
                                    frame.setApplicationProtocol("FTP-C");
                                    ftpcList.add(frame);
                                    ftpcFound = 1;
                                    createCommunication(frame);
                                }

                                if (DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getDestinationPort()) == 22 || DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getSourcePort()) == 22) {
                                    frame.setApplicationProtocol("SSH");
                                    ftpdList.add(frame);
                                    ftpdFound = 1;
                                    createCommunication(frame);
                                }
                                if (DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getDestinationPort()) == 23 || DataTypeHelper.toInt(frame.getIpv4parser().getTcpParser().getSourcePort()) == 23) {
                                    frame.setApplicationProtocol("TELNET");
                                    telnetList.add(frame);
                                    telnetFound = 1;
                                    createCommunication(frame);
                                }
                            }
                        }
                        if (longestIplist.isEmpty()) {
                            longestIplist.add(frame);
                            //    frame.getIpv4parser().setIpV4TheMostSentBytes(frame.getFrameLengthWire());
                        } else {
                            Integer iPfound = 0;

                            for (Frame temp : longestIplist) {
                                if (frame.getIpv4parser().getSourceIP().equalsIgnoreCase(temp.getIpv4parser().getSourceIP())) {
                                    Integer sumar = 0;
                                    sumar = temp.getIpv4parser().getIpV4theMostSentBytes() + frame.getFrameLength();
                                    temp.getIpv4parser().setIpV4TheMostSentBytes(sumar);
                                    iPfound = 1;
                                }
                            }
                            if (iPfound != 1) {
                                longestIplist.add(frame);
                            }
                        }
                    }

                    //   System.out.println(longestIplist.get(0).getIpv4parser().getiPv4length() + "zapisana");
                    DefaultTableModel tableModel = (DefaultTableModel) panel.getjTable1().getModel();
                    Object data[] = new Object[6];
                    data[0] = frame.getId();
                    data[1] = frame.getFrameLength();
                    data[2] = frame.getFrameLengthWire();
                    data[3] = frame.getFrameType();
                    data[4] = frame.getSourceMAC();
                    data[5] = frame.getDestinationMAC();
                    tableModel.addRow(data);
                    this.panel.getjTable1().setModel(tableModel);

                }
            } catch (EOFException ex) {
            }
        } catch (IOException ex) {
        }
        i = 1;
        for (Frame temp : longestIplist) {
            fillResultTable(i, temp.getIpv4parser().getSourceIP());
            i++;
        }

        DefaultTableCellRenderer centerTable = new DefaultTableCellRenderer();
        centerTable.setHorizontalAlignment(JLabel.CENTER);
        panel.getjTable1().setDefaultRenderer(Integer.class, centerTable);
        panel.getjTable1().setDefaultRenderer(String.class, centerTable);
        result.getjTable1().setDefaultRenderer(String.class, centerTable);
        result.getjTable1().setDefaultRenderer(Integer.class, centerTable);

        findTheMostBytesSent();
        result.getjSourceIpAdress().setText(theMostFrequentSourceIpAdress);
        result.getjByteCount().setText(theMostBytes.toString() + " B");

        if (arpFound == 1 && arpPanel == null) {
            arpPanel = new AnalyserArpParserPanel(this);
            Integer i = 1;
            for (ArpStorage temp : arpStorageFrameList) {
                if (temp.getReply() == null) {
                    fillArpTable(temp.getRequest(), i);
                } else {
                    fillArpTable(temp.getRequest(), i);
                    fillArpTable(temp.getReply(), i);
                }
                i++;
            }
        }

        if (icmpFound == 1 && icmpPanel == null) {
            icmpPanel = new AnalyserIcmpParserPanel(this);
            Integer i = 0;
            for (Frame temp : icmpList) {
                i++;
                fillIcmpTable(temp, i);
            }
        }

        if (httpsFound == 1 && httpsPanel == null) {
            for (CommunicationChannel temp : comList) {
                temp.checkCompleted();
            }
            httpsPanel = new AnalyserTcpParserPanel(this, httpsList);
            Integer i = 0;
            for (Frame temp : httpsList) {
                i++;
                fillTcpTable(temp, i, httpsPanel);
            }

        }

        if ((httpFound == 1) && httpPanel == null) {
            for (CommunicationChannel temp : comList) {
                temp.checkCompleted();
            }
            httpPanel = new AnalyserTcpParserPanel(this, httpList);
            Integer i = 0;
            for (Frame temp : httpList) {
                i++;
                fillTcpTable(temp, i, httpPanel);
            }
        }
        if ((ftpcFound == 1) && ftpcPanel == null) {
            for (CommunicationChannel temp : comList) {
                temp.checkCompleted();
            }
            ftpcPanel = new AnalyserTcpParserPanel(this, ftpcList);
            Integer i = 0;
            for (Frame temp : ftpcList) {
                i++;
                fillTcpTable(temp, i, ftpcPanel);
            }
        }
        if ((sshFound == 1) && sshPanel == null) {
            for (CommunicationChannel temp : comList) {
                temp.checkCompleted();
            }
            sshPanel = new AnalyserTcpParserPanel(this, sshList);
            Integer i = 0;
            for (Frame temp : sshList) {
                i++;
                fillTcpTable(temp, i, sshPanel);
            }
        }
        if ((ftpdFound == 1) && ftpdPanel == null) {
            for (CommunicationChannel temp : comList) {
                temp.checkCompleted();
            }
            ftpdPanel = new AnalyserTcpParserPanel(this, ftpdList);
            Integer i = 0;
            for (Frame temp : ftpdList) {
                i++;
                fillTcpTable(temp, i, ftpdPanel);
            }
        }
        if ((telnetFound == 1) && telnetPanel == null) {
            for (CommunicationChannel temp : comList) {
                temp.checkCompleted();
            }
            telnetPanel = new AnalyserTcpParserPanel(this, telnetList);
            Integer i = 0;
            for (Frame temp : telnetList) {
                i++;
                fillTcpTable(temp, i, telnetPanel);
            }
        }
    }

    public void fillIcmpTable(Frame frame, Integer i) throws FileNotFoundException {
        DefaultTableModel icmpTableModel = (DefaultTableModel) icmpPanel.getjTable1().getModel();
        Object[] data = new Object[10];

        data[0] = i;
        data[1] = frame.getId();
        data[2] = frame.getIpv4parser().getSourceIP();
        data[3] = frame.getIpv4parser().getDestinationIP();
        data[4] = frame.getSourceMAC();
        data[5] = frame.getDestinationMAC();
        data[6] = frame.getFrameLength();
        data[7] = frame.getFrameLengthWire();
        data[8] = frame.getIpv4parser().getiPv4length();
        data[9] = "[" + frame.getIpv4parser().getIcmpParser().getType() + "]    " + DataTypeHelper.getIcmpType(DataTypeHelper.singleToInt(frame.getIpv4parser().getIcmpParser().getType()));

        icmpTableModel.addRow(data);
        icmpPanel.getjTable1().setModel(icmpTableModel);
    }

    public void fillArpTable(Frame frame, Integer i) {
        DefaultTableModel arpTableModel = (DefaultTableModel) arpPanel.getjTable1().getModel();
        Object[] data = new Object[12];

        data[0] = i;

        data[1] = frame.getArpParser().getOperationType();
        if (data[1] == "ARP-Request") {
            data[2] = DataTypeHelper.ipAdressConvertor(frame.getArpParser().getDestinationIPbyte());
            data[3] = DataTypeHelper.macAdressConvertor(frame.getArpParser().getDestinationMACbyte());
        } else {
            data[2] = DataTypeHelper.ipAdressConvertor(frame.getArpParser().getSourceIPbyte());
            data[3] = DataTypeHelper.macAdressConvertor(frame.getArpParser().getSourceMACbyte());
        }
        data[4] = DataTypeHelper.ipAdressConvertor(frame.getArpParser().getSourceIPbyte());
        data[5] = DataTypeHelper.ipAdressConvertor(frame.getArpParser().getDestinationIPbyte());
        data[6] = frame.getId();
        data[7] = frame.getFrameLengthWire();
        data[8] = frame.getFrameLength();
        data[9] = frame.getFrameType();
        data[10] = DataTypeHelper.macAdressConvertor(frame.getArpParser().getSourceMACbyte());
        data[11] = DataTypeHelper.macAdressConvertor(frame.getArpParser().getDestinationMACbyte());

        arpTableModel.addRow(data);
        arpPanel.getjTable1().setModel(arpTableModel);
    }

    public void fillResultTable(Integer id, String sourceIp) {
        DefaultTableModel resltTableModel = (DefaultTableModel) result.getjTable1().getModel();
        Object[] data = new Object[4];
        data[0] = id;
        data[1] = sourceIp;

        resltTableModel.addRow(data);
        result.getjTable1().setModel(resltTableModel);
    }

    public void findTheMostBytesSent() {

        for (Frame temp : longestIplist) {
            if (theMostBytes < temp.getIpv4parser().getIpV4theMostSentBytes()) {
                theMostBytes = temp.getIpv4parser().getIpV4theMostSentBytes();
                theMostFrequentSourceIpAdress = temp.getIpv4parser().getSourceIP();
            }
        }
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

    public void assignArpFrames(Frame frame) {
        for (ArpStorage temp : arpStorageFrameList) {
            if (DataTypeHelper.macAdressConvertor(temp.getRequest().getArpParser().getSourceMACbyte()).equalsIgnoreCase(DataTypeHelper.macAdressConvertor(frame.getArpParser().getDestinationMACbyte())) && DataTypeHelper.ipAdressConvertor(temp.getRequest().getArpParser().getSourceIPbyte()).equalsIgnoreCase(DataTypeHelper.ipAdressConvertor(frame.getArpParser().getDestinationIPbyte()))) {
                {
                    temp.setReply(frame);
                }
            }
        }
    }

    private void fillTcpTable(Frame temp, Integer i, AnalyserTcpParserPanel panel) {
        DefaultTableModel tcpTableModel;

        tcpTableModel = (DefaultTableModel) panel.getTcpMainTable().getModel();

        Object[] data = new Object[9];

        data[0] = i;
        data[1] = temp.getComId();
        data[2] = temp.getProtocol();
        data[3] = temp.getIpv4parser().getSourceIP();
        data[4] = DataTypeHelper.toInt(temp.getIpv4parser().getTcpParser().getSourcePort());
        data[5] = temp.getIpv4parser().getDestinationIP();
        data[6] = DataTypeHelper.toInt(temp.getIpv4parser().getTcpParser().getDestinationPort());
        System.out.println(temp.getComId());
        if (comList.get(temp.getComId()).getCompleted() == 0) {
            data[7] = "Incomplete";
        } else {
            data[7] = "Completed";
        }
        data[8] = comList.get(temp.getComId()).getTcpCommList().size();
        tcpTableModel.addRow(data);
        panel.getTcpMainTable().setModel(tcpTableModel);

    }

    public AnalyserMainCheckResult getResult() {
        return result;
    }

    public ArrayList<CommunicationChannel> getComList() {
        return comList;
    }

    public AnalyserTcpParserPanel getFtpcPanel() {
        return ftpcPanel;
    }

    public ArrayList<Frame> getFtpcList() {
        return ftpcList;
    }

    public AnalyserTcpParserPanel getFtpdPanel() {
        return ftpdPanel;
    }

    public ArrayList<Frame> getFtpdList() {
        return ftpdList;
    }

    public Integer getFtpdFound() {
        return ftpdFound;
    }

    public AnalyserTcpParserPanel getTelnetPanel() {
        return telnetPanel;
    }

    public ArrayList<Frame> getTelnetList() {
        return telnetList;
    }

    public Integer getTelnetFound() {
        return telnetFound;
    }

    public Integer getFtpcFound() {
        return ftpcFound;
    }

    public ArrayList<Frame> getHttpList() {
        return httpList;
    }

    public AnalyserTcpParserPanel getSshPanel() {
        return sshPanel;
    }

    public ArrayList<Frame> getSshList() {
        return sshList;
    }

    public Integer getSshFound() {
        return sshFound;
    }

    public Integer getHttpFound() {
        return httpFound;
    }

    public AnalyserIcmpParserPanel getIcmpPanel() {
        return icmpPanel;
    }

    public ArrayList<Frame> getIcmpList() {
        return icmpList;
    }

    public AnalyserTcpParserPanel getHttpsPanel() {
        return httpsPanel;
    }

    public AnalyserArpParserPanel getArpPanel() {
        return arpPanel;
    }

    public ArrayList<Frame> getArpFrameList() {
        return arpFrameList;
    }

    public ArrayList getFrameList() {
        return frameList;
    }

    public AnalyserTcpParserPanel getHttpPanel() {
        return httpPanel;
    }

    public File getPcap() {
        return pcap;
    }

}
