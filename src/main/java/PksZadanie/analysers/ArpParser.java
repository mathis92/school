/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PksZadanie.analysers;

import PksZadanie.equip.DataTypeHelper;
import org.krakenapps.pcap.util.Buffer;

/**
 *
 * @author Mathis
 */
public class ArpParser extends AbstractAnalyser implements IAnalyser {

    private String operationType;
    private final byte[] sourceIPbyte = new byte[4];
    private final byte[] destinationIPbyte = new byte[4];
    private final byte[] destinationMACbyte = new byte[6];
    private final byte[] sourceMACbyte = new byte[6];
    public ArpParser(Buffer buffer) {
        super(buffer);
    }

    @Override
    public void analyse() {
        super.analyse(); //To change body of generated methods, choose Tools | Templates.
        buffer.skip(6);
        byte[] opType = new byte[]{buffer.get(), buffer.get()};
        if (DataTypeHelper.toInt(opType) == 1) {
            operationType = "ARP-Request";
        } else if (DataTypeHelper.toInt(opType) == 2) {
            operationType = "ARP-Reply";
        }

        for (int i = 0; i < 6; i++) {
            sourceMACbyte[i] = buffer.get();
        }
        for (int i = 0; i < 4; i++) {
            sourceIPbyte[i] = buffer.get();
        }

        for (int i = 0; i < 6; i++) {
            destinationMACbyte[i] = buffer.get();
        }

        for (int i = 0; i < 4; i++) {
            destinationIPbyte[i] = buffer.get();
        }
    }

    public byte[] getDestinationIPbyte() {
        return destinationIPbyte;
    }

    public byte[] getDestinationMACbyte() {
        return destinationMACbyte;
    }

    public String getOperationType() {
        return operationType;
    }

    public byte[] getSourceIPbyte() {
        return sourceIPbyte;
    }

    public byte[] getSourceMACbyte() {
        return sourceMACbyte;
    }

    
    
    
}
