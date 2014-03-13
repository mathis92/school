/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkszadanie.analysers;

import PksZadanie.AnalyserGUI;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import org.krakenapps.pcap.PcapInputStream;
import org.krakenapps.pcap.file.PcapFileInputStream;
import org.krakenapps.pcap.packet.PcapPacket;
import PksZadanie.AnalyserMainCheck;
import PksZadanie.AnalyserMainCheckResult;
import PksZadanie.equip.ByteTo;
import PksZadanie.equip.Frame;
import PksZadanie.equip.FrameType;
import java.util.ArrayList;
import javax.swing.JLabel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import org.krakenapps.pcap.util.Buffer;

public class Analyser {

    private final AnalyserMainCheck panel;
    private final File pcap;
    private Integer i = 0;
    private ArrayList<Frame> frameList;
    public final ArrayList<Frame> longestIplist = new ArrayList<>();
    public Integer theMostBytes = 0;
    public String theMostSourceIpAdress;
    //   private final AnalyserGUI gui;
    private AnalyserMainCheckResult result;
    private Frame frame;

    public Analyser(AnalyserMainCheck aPanel, File pcapFile, AnalyserGUI gui) {
        this.panel = aPanel;
        this.pcap = pcapFile;
        //     this.gui = gui;
    }

    public void analyzeFile() {
        try {
            PcapInputStream is = new PcapFileInputStream(pcap);
            frameList = new ArrayList<>();
            result = new AnalyserMainCheckResult();

            try {
                while (true) {
                    PcapPacket packet = is.getPacket();
                    i++;
                    frame = new Frame(i, packet);
                    frameList.add(frame);
                    if (frame.getIsIpv4()) {
                        if (longestIplist.isEmpty()) {
                            //      System.out.println(frame.getFrameType() + "som v ife");
                            longestIplist.add(frame);
                        } else {
                            Integer found = 0;
                            for (Frame temp : longestIplist) {
                                if (frame.getIpv4analyser().getSourceIP().equalsIgnoreCase(temp.getIpv4analyser().getSourceIP())) {
                                    Integer sumar;
                                    sumar = temp.getIpv4analyser().getiPv4length() + frame.getIpv4analyser().getiPv4length();
                                    temp.getIpv4analyser().setIpV4(sumar);
                                    found = 1;
                                }
                            }
                            if (found != 1) {
                                longestIplist.add(frame);
                            }
                        }
                    }
                    //   System.out.println(longestIplist.get(0).getIpv4analyser().getiPv4length() + "zapisana");

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
            fillResultTable(i, temp.getIpv4analyser().getSourceIP());
            i++;
        }

        DefaultTableCellRenderer centerTable = new DefaultTableCellRenderer();
        centerTable.setHorizontalAlignment(JLabel.CENTER);
        panel.getjTable1().setDefaultRenderer(String.class, centerTable);
        result.getjTable1().setDefaultRenderer(String.class, centerTable);

        findTheMostBytesSent();
        result.getjSourceIpAdress().setText(theMostSourceIpAdress);
        result.getjByteCount().setText(theMostBytes.toString() + " B");
      //  gui.getjTabbedPane3().addTab("result", result);

        //   panel.panel.getjTabbedPane3()dd.addTab("cosijak",mostBytePanel);
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
            if (theMostBytes < temp.getIpv4analyser().getiPv4length()) {
                theMostBytes = temp.getIpv4analyser().getiPv4length();
                theMostSourceIpAdress = temp.getIpv4analyser().getSourceIP();
            }
        }
    }

    public AnalyserMainCheckResult getResult() {
        return result;
    }

    public ArrayList getFrameList() {
        return frameList;
    }

    public File getPcap() {
        return pcap;
    }

}
