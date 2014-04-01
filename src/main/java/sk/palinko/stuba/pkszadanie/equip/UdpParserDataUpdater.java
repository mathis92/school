/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.palinko.stuba.pkszadanie.equip;

import sk.palinko.stuba.pkszadanie.AnalyserArpParserPanel;
import sk.palinko.stuba.pkszadanie.AnalyserIcmpParserPanel;
import sk.palinko.stuba.pkszadanie.AnalyserMainCheck;
import sk.palinko.stuba.pkszadanie.AnalyserUdpParserPanel;
import java.util.ArrayList;

/**
 *
 * @author Mathis
 */
public class UdpParserDataUpdater {

    public Frame frame;
    public AnalyserUdpParserPanel dataFrameUdp;

    public UdpParserDataUpdater(Frame frame, AnalyserUdpParserPanel dataPanel) {
        this.frame = frame;
        this.dataFrameUdp = dataPanel;

    }

    public String makeString(byte data) {
        StringBuilder dataByte = new StringBuilder();
        dataByte.append(String.format("%02X ", data));
        return dataByte.toString();
    }

    public void update() {
        ArrayList stringList = new ArrayList();
        String data = new String();
        frame.getBuffer().rewind();

        while (frame.getBuffer().isEOB() != true) {
            stringList.add(makeString(frame.getBuffer().get()));

        }
        for (int i = 1; i < stringList.size() + 1; i++) {

            data += stringList.get(i - 1).toString();

            if (i % 8 == 0) {
                data += " ";
            }
            if (i % 16 == 0) {
                data += "\n";
            }
        }
        dataFrameUdp.getjDataText().setText(data);

    }
}
