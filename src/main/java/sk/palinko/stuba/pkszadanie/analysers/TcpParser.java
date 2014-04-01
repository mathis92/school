/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.palinko.stuba.pkszadanie.analysers;

import sk.palinko.stuba.pkszadanie.equip.DataTypeHelper;
import org.krakenapps.pcap.util.Buffer;

/**
 *
 * @author Mathis
 */
public class TcpParser extends AbstractAnalyser implements IAnalyser {

    private final byte[] sourcePortByte;
    private final byte[] destinationPortByte;
    private Integer sourcePort;
    private Integer destinationPort;
    private Integer DataOffset;
    private byte flags;
    private boolean isTcp = false;

    public TcpParser(Buffer buffer) {
        super(buffer);
        this.destinationPortByte = new byte[2];
        this.sourcePortByte = new byte[2];

        analyse();
    }

  //  public TcpParser() {
    //  }
    @Override
    public void analyse() {
        isTcp = true;
        sourcePortByte[0] = buffer.get();
        sourcePortByte[1] = buffer.get();
        destinationPortByte[0] = buffer.get();
        destinationPortByte[1] = buffer.get();
        sourcePort = DataTypeHelper.toInt(sourcePortByte);
        destinationPort = DataTypeHelper.toInt(destinationPortByte);
        buffer.skip(8);
        DataOffset = buffer.get() & 0xF0;
        flags = buffer.get();
    }

    public Integer getDataOffset() {
        return DataOffset;
    }

    public byte[] getDestinationPortByte() {
        return destinationPortByte;
    }

    public byte getFlags() {
        return flags;
    }

    public boolean getIsTcp() {
        return isTcp;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public byte[] getSourcePortByte() {
        return sourcePortByte;
    }

}
