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
import PksZadanie.AnalyserUdpParserPanel;
import PksZadanie.analysers.ArpStorage;
import PksZadanie.equip.TcpCommunication;
import PksZadanie.equip.CommunicationChannel;
import PksZadanie.equip.DataTypeHelper;
import PksZadanie.equip.Frame;
import PksZadanie.equip.UdpCommunication;
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
    private ArrayList<ArpStorage> arpStorageFrameList;
    private ArrayList<Frame> icmpList;
    private ArrayList<UdpCommunication> udpCommunicationList;
    private ArrayList<TcpCommunication> tcpCommunicationList;
    private ArrayList<String> tcpCommunicationHelper;
    private ArrayList<String> udpCommunicationHelper;
    public Integer theMostBytes = 0;
    public String theMostFrequentSourceIpAdress;
    private AnalyserMainCheckResult result;
    private AnalyserArpParserPanel arpPanel = null;
    private AnalyserIcmpParserPanel icmpPanel = null;
    private Frame frame;
    private Integer arpFound = 0;
    private Integer icmpFound = 0;
    private Integer usingTcp2Output = 0;

    public Analyser(AnalyserMainCheck aPanel, File pcapFile, AnalyserGUI gui) throws IOException {
        this.panel = aPanel;
        this.pcap = pcapFile;
        DataTypeHelper.scanFile();
        DataTypeHelper.scanProtocolFile();

    }

    public void analyzeFile() throws FileNotFoundException {
        try {
            PcapInputStream is = new PcapFileInputStream(pcap);
            frameList = new ArrayList<>();
            arpFrameList = new ArrayList<>();
            icmpList = new ArrayList<>();
            result = new AnalyserMainCheckResult();
            arpStorageFrameList = new ArrayList<>();
            longestIplist = new ArrayList<>();
            tcpCommunicationList = new ArrayList<>();
            udpCommunicationList = new ArrayList<>();
            tcpCommunicationHelper = new ArrayList<>();
            udpCommunicationHelper = new ArrayList<>();
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
                                String tcpPort = DataTypeHelper.tcpMap.get(frame.getIpv4parser().getTcpParser().getDestinationPort());
                                if (tcpPort == null) {
                                    tcpPort = DataTypeHelper.tcpMap.get(frame.getIpv4parser().getTcpParser().getSourcePort());

                                }
                                if (tcpPort != null) {
                                    if (tcpPort.equals("www")) {
                                        tcpPort = "http";
                                    }

                                    frame.setApplicationProtocol(tcpPort);
                                    if (tcpCommunicationHelper.contains(tcpPort) == false) {
                                        TcpCommunication newCommunication = new TcpCommunication(frame);
                                        tcpCommunicationList.add(newCommunication);
                                        tcpCommunicationHelper.add(tcpPort);
                                    } else {
                                        tcpCommunicationList.get(tcpCommunicationHelper.indexOf(tcpPort)).createCommunication(frame);
                                    }
                                }
                            }
                        }
                        if (frame.getIpv4parser().getUdpParser() != null) {
                            if (frame.getIpv4parser().getUdpParser().isIsUdp()) {
                                frame.setProtocol("UDP");
                                String udpPort = DataTypeHelper.udpMap.get(DataTypeHelper.toInt(frame.getIpv4parser().getUdpParser().getDestinationPort()));
                                if (udpPort == null) {
                                    udpPort = DataTypeHelper.udpMap.get(DataTypeHelper.toInt(frame.getIpv4parser().getUdpParser().getSourcePort()));
                                }

                                if (udpPort != null) {
                                    if (udpPort.equals("www")) {
                                        udpPort = "http";
                                    }
                                    frame.setApplicationProtocol(udpPort);
                                    if (udpCommunicationHelper.contains(udpPort) == false) {
                                        UdpCommunication newCommunication = new UdpCommunication(frame);
                                        udpCommunicationList.add(newCommunication);
                                        udpCommunicationHelper.add(udpPort);
                                    } else {
                                        udpCommunicationList.get(udpCommunicationHelper.indexOf(udpPort)).storeCommunication(frame);
                                    }
                                }
                            }
                        }
                        if (longestIplist.isEmpty()) {
                            longestIplist.add(frame);
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
        result.getjLabel3().setText(DataTypeHelper.getStringFromArray());

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
            arpPanel.getjTable1().setDefaultRenderer(Integer.class, centerTable);
             arpPanel.getjTable1().setDefaultRenderer(String.class, centerTable);
        }

        if (icmpFound == 1 && icmpPanel == null) {
            icmpPanel = new AnalyserIcmpParserPanel(this);
            Integer i = 0;
            for (Frame temp : icmpList) {
                i++;
                fillIcmpTable(temp, i);
            }
        }
        for (TcpCommunication temp : tcpCommunicationList) {
            // setUpTcpTable(temp);
            setUpTcpTable2(temp);
        }
        for (UdpCommunication temp : udpCommunicationList) {
            setUpUdpTable(temp);
        }
    }

    public void setUpUdpTable(UdpCommunication communication) {
        if ((communication.getFound() == 1) && communication.getPanel() == null) {
            communication.setPanel(new AnalyserUdpParserPanel(this, communication));
            Integer i = 0;
            for (Frame temp : communication.getList()) {
                i++;
                fillUdpTable(temp, i, communication);
            }
            DefaultTableCellRenderer centerTable = new DefaultTableCellRenderer();
            centerTable.setHorizontalAlignment(JLabel.CENTER);
            communication.getPanel().getUdpMainTable().setDefaultRenderer(Integer.class, centerTable);
            communication.getPanel().getUdpMainTable().setDefaultRenderer(String.class, centerTable);
        }
    }

    private void fillUdpTable(Frame temp, Integer i, UdpCommunication comm) {
        DefaultTableModel udpTableModel;

        udpTableModel = (DefaultTableModel) comm.getPanel().getUdpMainTable().getModel();

        Object[] data = new Object[7];

        data[0] = i;
        data[1] = temp.getId();
        data[2] = temp.getProtocol();
        data[3] = temp.getIpv4parser().getSourceIP();
        data[4] = (DataTypeHelper.toInt(temp.getIpv4parser().getUdpParser().getSourcePort()) + " [" + DataTypeHelper.getUdpPortName(DataTypeHelper.toInt(temp.getIpv4parser().getUdpParser().getSourcePort())) + "]");
        data[5] = temp.getIpv4parser().getDestinationIP();
        data[6] = (DataTypeHelper.toInt(temp.getIpv4parser().getUdpParser().getDestinationPort()) + " [" + DataTypeHelper.getUdpPortName(DataTypeHelper.toInt(temp.getIpv4parser().getUdpParser().getDestinationPort())) + "]");
        udpTableModel.addRow(data);
        comm.getPanel().getUdpMainTable().setModel(udpTableModel);
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

    public void assignArpFrames(Frame frame) {
        for (ArpStorage temp : arpStorageFrameList) {
            if (DataTypeHelper.macAdressConvertor(temp.getRequest().getArpParser().getSourceMACbyte()).equalsIgnoreCase(DataTypeHelper.macAdressConvertor(frame.getArpParser().getDestinationMACbyte())) && DataTypeHelper.ipAdressConvertor(temp.getRequest().getArpParser().getSourceIPbyte()).equalsIgnoreCase(DataTypeHelper.ipAdressConvertor(frame.getArpParser().getDestinationIPbyte()))) {
                {
                    temp.setReply(frame);
                }
            }
        }
    }

    public void setUpTcpTable2(TcpCommunication communication) {
        usingTcp2Output = 1;
        if ((communication.getFound() == 1) && communication.getPanel() == null) {
            for (CommunicationChannel temp : communication.getComList()) {
                temp.checkCompleted();
            }
            communication.setPanel(new AnalyserTcpParserPanel(this, communication));
            for (CommunicationChannel temp : communication.getComList()) {
                fillTcpTable(temp.getTcpCommList().get(0), temp.getTcpCommList().get(0).getComId(), communication.getPanel(), communication);
            }
            DefaultTableCellRenderer centerTable = new DefaultTableCellRenderer();
            centerTable.setHorizontalAlignment(JLabel.CENTER);
            communication.getPanel().getTcpMainTable().setDefaultRenderer(Integer.class, centerTable);
            communication.getPanel().getjTable2().setDefaultRenderer(Integer.class, centerTable);
            communication.getPanel().getjTable3().setDefaultRenderer(Integer.class, centerTable);
            communication.getPanel().getTcpMainTable().setDefaultRenderer(String.class, centerTable);
            communication.getPanel().getjTable2().setDefaultRenderer(String.class, centerTable);
            communication.getPanel().getjTable3().setDefaultRenderer(String.class, centerTable);
        }
    }

    public void setUpTcpTable(TcpCommunication communication) {
        usingTcp2Output = 0;
        if ((communication.getFound() == 1) && communication.getPanel() == null) {
            for (CommunicationChannel temp : communication.getComList()) {
                temp.checkCompleted();
            }
            communication.setPanel(new AnalyserTcpParserPanel(this, communication));
            Integer i = 0;
            for (Frame temp : communication.getList()) {
                i++;
                fillTcpTable(temp, i, communication.getPanel(), communication);
            }
            DefaultTableCellRenderer centerTable = new DefaultTableCellRenderer();
            centerTable.setHorizontalAlignment(JLabel.CENTER);
            communication.getPanel().getTcpMainTable().setDefaultRenderer(Integer.class, centerTable);
            communication.getPanel().getjTable2().setDefaultRenderer(Integer.class, centerTable);
            communication.getPanel().getjTable3().setDefaultRenderer(Integer.class, centerTable);
            communication.getPanel().getTcpMainTable().setDefaultRenderer(String.class, centerTable);
            communication.getPanel().getjTable2().setDefaultRenderer(String.class, centerTable);
            communication.getPanel().getjTable3().setDefaultRenderer(String.class, centerTable);
        }
    }

    private void fillTcpTable(Frame temp, Integer i, AnalyserTcpParserPanel panel, TcpCommunication comm) {
        DefaultTableModel tcpTableModel;

        tcpTableModel = (DefaultTableModel) panel.getTcpMainTable().getModel();

        Object[] data = new Object[9];

        data[0] = i +1;
        data[1] = temp.getComId() +1;
        data[2] = temp.getProtocol();
        data[3] = temp.getIpv4parser().getSourceIP();
        Integer sPort = DataTypeHelper.toInt(temp.getIpv4parser().getTcpParser().getSourcePortByte());
        data[4] = sPort + " [" + DataTypeHelper.getTcpPortName(sPort) + "]";
        data[5] = temp.getIpv4parser().getDestinationIP();
        Integer dPort = DataTypeHelper.toInt(temp.getIpv4parser().getTcpParser().getDestinationPortByte());
        data[6] = dPort + " [" + DataTypeHelper.getTcpPortName(dPort) + "]";

        if (comm.getComList().get(temp.getComId()).getCompleted() == 0) {
            data[7] = "Incomplete";
        } else {
            data[7] = "Completed";
        }
        data[8] = comm.getComList().get(temp.getComId()).getTcpCommList().size();
        tcpTableModel.addRow(data);
        panel.getTcpMainTable().setModel(tcpTableModel);
    }

    public AnalyserMainCheckResult getResult() {
        return result;
    }

    public ArrayList<UdpCommunication> getUdpCommunicationList() {
        return udpCommunicationList;
    }

    public ArrayList<TcpCommunication> getTcpCommunicationList() {
        return tcpCommunicationList;
    }

    public AnalyserIcmpParserPanel getIcmpPanel() {
        return icmpPanel;
    }

    public ArrayList<Frame> getIcmpList() {
        return icmpList;
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

    public File getPcap() {
        return pcap;
    }

    public Integer getUsingTcp2Output() {
        return usingTcp2Output;
    }

}
