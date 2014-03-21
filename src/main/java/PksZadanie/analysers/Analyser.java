/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkszadanie.analysers;

import PksZadanie.AnalyserArpParserPanel;
import PksZadanie.AnalyserGUI;
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
    private ArrayList<Frame> longestIplist = new ArrayList<>();
    private ArrayList<CommunicationChannel> comList;
    private ArrayList<Frame> tcpList;
    private ArrayList<ArpStorage> arpStorageFrameList;
    private ArrayList<Frame> icmpList;
    public Integer theMostBytes = 0;
    public String theMostFrequentSourceIpAdress;
    private AnalyserMainCheckResult result;
    private AnalyserArpParserPanel arpPanel = null;
    private AnalyserIcmpParserPanel icmpPanel = null;
    private Frame frame;
    private Integer arpFound = 0;
    private Integer icmpFound = 0;
    private Integer tcpFound = 0;

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
            tcpList = new ArrayList<>();
            comList = new ArrayList<>();
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
                                tcpList.add(frame);
                                tcpFound = 1;
                                System.out.println(frame.getId());
                                for (String temp : DataTypeHelper.getTcpPortFlags(frame)) {
                                    System.out.print(temp + ",");
                                }
                                System.out.println("");
                                
                            }
                            if (longestIplist.isEmpty()) {
                                longestIplist.add(frame);
                            //    frame.getIpv4parser().setIpV4TheMostSentBytes(frame.getFrameLengthWire());
                            } else {
                                Integer found = 0;
                                for (Frame temp : longestIplist) {
                                    if (frame.getIpv4parser().getSourceIP().equalsIgnoreCase(temp.getIpv4parser().getSourceIP())) {
                                        Integer sumar = 0;
                                        sumar = temp.getIpv4parser().getIpV4theMostSentBytes() + frame.getFrameLength();
                                        temp.getIpv4parser().setIpV4TheMostSentBytes(sumar);
                                        found = 1;
                                    }
                                }
                                if (found != 1) {
                                    longestIplist.add(frame);
                                }
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
      //  gui.getjTabbedPane3().addTab("result", result);

        //   panel.panel.getjTabbedPane3()dd.addTab("cosijak",mostBytePanel);
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

    public AnalyserMainCheckResult getResult() {
        return result;
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
}
