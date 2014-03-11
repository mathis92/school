/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PksZadanie.analysers;

import PksZadanie.equip.ByteTo;
import org.krakenapps.pcap.util.Buffer;

/**
 *
 * @author Mathis
 */
public class IpV4Analyser extends AbstractAnalyser implements IAnalyser {

    private final byte[] sourceIPbyte = new byte[4];
    private String sourceIP;
    private String destinationIP;
    private final byte[] destinationIPbyte = new byte[4];

    public IpV4Analyser(Buffer buffer) {
        super(buffer);
    }

    @Override
    public void analyse() {
        buffer.skip(12);
        for (int i = 0; i < 4; i++) {
            sourceIPbyte[i] = buffer.get();
            ByteTo newInt = new ByteTo(sourceIPbyte[i]);
            if (i == 0) {
                sourceIP = newInt.singleToInt().toString();
            } else {
                sourceIP += newInt.singleToInt().toString();

            }
            if (i < 3) {
                sourceIP += ".";
            } else {
                sourceIP += "\n";
            }
        }
        System.out.println("source IP " + sourceIP);
        for (int i = 0; i < 4; i++) {
            destinationIPbyte[i] = buffer.get();
            ByteTo newInt = new ByteTo(destinationIPbyte[i]);
            if (i == 0) {
                destinationIP = newInt.singleToInt().toString();
            } else {
                destinationIP += newInt.singleToInt().toString();

            }
            if (i < 3) {
                destinationIP += ".";
            } else {
                destinationIP += "\n";
            }
        }
        System.out.println("destination IP " + destinationIP);

    }

    public String getSourceIP() {
        return sourceIP;
    }

    public String getDestinationIP() {
        return destinationIP;
    }
    
    
}
