/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PksZadanie.equip;

import PksZadanie.AnalyserTcpParserPanel;
import java.util.ArrayList;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author Mathis
 */
public class TcpCommunicationDataUpdater {

    public Frame frame;
    public AnalyserTcpParserPanel dataFrame;
    public ArrayList<Integer> sizesFrames = new ArrayList<>();
    public ArrayList<String> sizes = new ArrayList<>();

    public TcpCommunicationDataUpdater(Frame frame, AnalyserTcpParserPanel dataPanel) {
        this.frame = frame;
        this.dataFrame = dataPanel;
        update();
        fillSizeTable();
    }

    public void update() {
        Integer x = 0;
        Integer x1 = 20;

        while (2 * x - 1 < 2560) {
            sizes.add(x.toString() + "-" + (x1 - 1));
            x = x1;
            x1 = x * 2;
        }
        
        for(int i=0; i<8;i++){
            sizesFrames.add(0);
        }

        System.out.println(sizes);
        for (Frame temp : dataFrame.getAn().getComList().get(frame.getComId()).getTcpCommList()) {
            Integer i = 0;
            i++;
            DefaultTableModel tableModel = (DefaultTableModel) dataFrame.getjTable2().getModel();
            Object data[] = new Object[9];
            data[0] = i;
            data[1] = temp.getId();
            data[2] = DataTypeHelper.ipAdressConvertor(temp.getIpv4parser().getSourceIPbyte());
            data[3] = DataTypeHelper.ipAdressConvertor(temp.getIpv4parser().getDestinationIPbyte());
            data[4] = DataTypeHelper.toInt(temp.getIpv4parser().getTcpParser().getSourcePort());
            data[5] = DataTypeHelper.toInt(temp.getIpv4parser().getTcpParser().getDestinationPort());
            data[6] = DataTypeHelper.getTcpPortFlags(temp);
            data[7] = DataTypeHelper.macAdressConvertor(temp.getSourceMACByte());
            data[8] = DataTypeHelper.macAdressConvertor(temp.getDestinationMACByte());
            tableModel.addRow(data);
            dataFrame.getjTable2().setModel(tableModel);

            if (temp.getFrameLength() < 19) {
                sizesFrames.set(0, sizesFrames.get(0) + 1);
            } else if (temp.getFrameLength() > 20 && temp.getFrameLength() < 39) {
                sizesFrames.set(1, sizesFrames.get(1) + 1);
            } else if (temp.getFrameLength() > 40 && temp.getFrameLength() < 79) {
                sizesFrames.set(2, sizesFrames.get(2) + 1);
            } else if (temp.getFrameLength() > 80 && temp.getFrameLength() < 159) {
                sizesFrames.set(3, sizesFrames.get(3) + 1);
            } else if (temp.getFrameLength() > 160 && temp.getFrameLength() < 319) {
                sizesFrames.set(4, sizesFrames.get(4) + 1);
            } else if (temp.getFrameLength() > 320 && temp.getFrameLength() < 639) {
                sizesFrames.set(5, sizesFrames.get(5) + 1);
            } else if (temp.getFrameLength() > 640 && temp.getFrameLength() < 1279) {
                sizesFrames.set(6, sizesFrames.get(6) + 1);
            }else if (temp.getFrameLength() > 1280 && temp.getFrameLength() < 2560) {
                sizesFrames.set(7, sizesFrames.get(7) + 1);
            }
        }
    }

    public void fillSizeTable() {
        Integer i = 0;
        for (String temp : sizes) {
            DefaultTableModel tableModel = (DefaultTableModel) dataFrame.getjTable3().getModel();
            Object data[] = new Object[2];
            data[0] = temp;
            data[1] = sizesFrames.get(i);
            tableModel.addRow(data);
            dataFrame.getjTable3().setModel(tableModel);
            i++;
        }
    }
}
