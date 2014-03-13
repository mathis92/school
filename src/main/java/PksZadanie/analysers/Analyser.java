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
import PksZadanie.equip.Frame;
import PksZadanie.equip.FrameType;
import java.util.ArrayList;
import javax.swing.table.DefaultTableModel;
import org.krakenapps.pcap.util.Buffer;

public class Analyser {

    public AnalyserMainCheck panel;
    public File pcap;
    public Integer i = 0;
    public ArrayList<Frame> frameList;
    public ArrayList<Frame> longestIplist = new ArrayList<>();
    private ArrayList<String> sourceIP = new ArrayList<String>();
    public AnalyserGUI gui;
    private AnalyserMainCheckResult result;
    private Frame frame;

    public Analyser(AnalyserMainCheck aPanel, File pcapFile, AnalyserGUI gui) {
        this.panel = aPanel;
        this.pcap = pcapFile;
        this.gui = gui;
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
                   //           System.out.println(frame.getIpv4analyser().getiPv4length() + "frame Length");
                    //          System.out.println(longestIplist.get(0).getIpv4analyser().getiPv4length() + ": list length");
                            if (frame.getIpv4analyser().getiPv4length() >= longestIplist.get(0).getIpv4analyser().getiPv4length()) {
                                if (frame.getIpv4analyser().getiPv4length() > longestIplist.get(0).getIpv4analyser().getiPv4length()) {
                                    longestIplist.clear();
                                    longestIplist.add(frame);
                                } else {
                                    longestIplist.add(frame);
                                }
                            }
                        }
                    }
                 //   System.out.println(longestIplist.get(0).getIpv4analyser().getiPv4length() + "zapisana");
                    if (frame.getIsIpv4()) {
                        if (sourceIP.contains((String) frame.getIpv4analyser().getSourceIP()) != true) {
                            sourceIP.add(frame.getIpv4analyser().getSourceIP());
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
        for (String temp : sourceIP) {
            fillResultTable(i, temp);
            i++;
        }

        result.getjSourceIpAdress().setText(longestIplist.get(0).getIpv4analyser().getSourceIP());
        result.getjByteCount().setText(longestIplist.get(0).getIpv4analyser().getiPv4length().toString());
      //  gui.getjTabbedPane3().addTab("result", result);

        //   panel.panel.getjTabbedPane3().addTab("cosijak",mostBytePanel);
    }

    public void fillResultTable(Integer id, String sourceIp) {
        DefaultTableModel resltTableModel = (DefaultTableModel) result.getjTable1().getModel();
        Object[] data = new Object[4];
        data[0] = id;
        data[1] = sourceIp;

        resltTableModel.addRow(data);
        result.getjTable1().setModel(resltTableModel);
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
