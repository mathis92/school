/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package PksZadanie.equip;

import PksZadanie.AnalyserUdpParserPanel;
import java.util.ArrayList;

public class UdpCommunication {
private ArrayList<Frame> list = new ArrayList<>();
private AnalyserUdpParserPanel panel = null;
private Integer found = 0;
    public UdpCommunication(Frame frame) {
        storeCommunication(frame);
        found = 1;
    }

    public void storeCommunication(Frame frame) {
        list.add(frame);
    }

    public ArrayList<Frame> getList() {
        return list;
    }

    public AnalyserUdpParserPanel getPanel() {
        return panel;
    }

    public Integer getFound() {
        return found;
    }

    public void setPanel(AnalyserUdpParserPanel panel) {
        this.panel = panel;
    }
    
}
