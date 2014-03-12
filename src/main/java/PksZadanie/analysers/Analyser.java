/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkszadanie.analysers;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import org.krakenapps.pcap.PcapInputStream;
import org.krakenapps.pcap.file.PcapFileInputStream;
import org.krakenapps.pcap.packet.PcapPacket;
import PksZadanie.AnalyserMainCheck;
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
    public ArrayList<Frame> mostBytesList = new ArrayList<Frame>();

    public Analyser(AnalyserMainCheck aPanel, File pcapFile) {
        this.panel = aPanel;
        this.pcap = pcapFile;
    }

    public void analyzeFile() {
        try {
            PcapInputStream is = new PcapFileInputStream(pcap);
            frameList = new ArrayList<>();
            try {
                while (true) {
                    PcapPacket packet = is.getPacket();
                    i++;
                    Frame frame = new Frame(i, packet);
                    frameList.add(frame);
                    if (mostBytesList.isEmpty()) {
                        mostBytesList.add(frame);
                    } else {
                        if (frame.getFrameLengthWire() >= mostBytesList.get(0).getFrameLengthWire()) {
                            if (frame.getFrameLengthWire() > mostBytesList.get(0).getFrameLengthWire()) {
                                mostBytesList.clear();
                            } else {
                                mostBytesList.add(frame);
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
        
     //   panel.gui.getjTabbedPane3().addTab("cosijak",mostBytePanel);
    }

    public ArrayList getFrameList() {
        return frameList;
    }

    public File getPcap() {
        return pcap;
    }

}
