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
public class UdpParser extends AbstractAnalyser implements IAnalyser {

    private final byte[] sourcePort;
    private final byte[] destinationPort;
    private boolean isUdp = false;

    public UdpParser(Buffer buffer) {
        super(buffer);
        this.destinationPort = new byte[2];
        this.sourcePort = new byte[2];

        analyse();
    }

  //  public TcpParser() {
    //  }
    @Override
    public void analyse() {
        isUdp = true;
        sourcePort[0] = buffer.get();
        sourcePort[1] = buffer.get();
        destinationPort[0] = buffer.get();
        destinationPort[1] = buffer.get();
      
    }

    public byte[] getDestinationPort() {
        return destinationPort;
    }

    public boolean isIsUdp() {
        return isUdp;
    }



    public byte[] getSourcePort() {
        return sourcePort;
    }

}
