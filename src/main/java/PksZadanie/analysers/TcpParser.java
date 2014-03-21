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
public class TcpParser extends AbstractAnalyser implements IAnalyser {

    private final byte[] sourcePort;
    private final byte[] destinationPort;
    private Integer DataOffset;
    private byte flags;
    private boolean isTcp = false;

    public TcpParser(Buffer buffer) {
        super(buffer);
        this.destinationPort = new byte[2];
        this.sourcePort = new byte[2];

        analyse();
    }

  //  public TcpParser() {
    //  }
    @Override
    public void analyse() {
        isTcp = true;
        sourcePort[0] = buffer.get();
        sourcePort[1] = buffer.get();
        destinationPort[0] = buffer.get();
        destinationPort[1] = buffer.get();
        buffer.skip(8);
        DataOffset = buffer.get() & 0xF0;
        flags = buffer.get();
    }

    public Integer getDataOffset() {
        return DataOffset;
    }

    public byte[] getDestinationPort() {
        return destinationPort;
    }

    public byte getFlags() {
        return flags;
    }

    public boolean getIsTcp() {
        return isTcp;
    }

    public byte[] getSourcePort() {
        return sourcePort;
    }

}
