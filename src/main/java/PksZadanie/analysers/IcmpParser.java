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
public class IcmpParser extends AbstractAnalyser implements IAnalyser {

    private byte type;
    private byte code; 
    private final byte[] checksum = new byte[2];
    private String typeString;
    
    
    public IcmpParser(Buffer buffer) {
        super(buffer);
        this.analyse();
    }

    @Override
    public void analyse() {

    
       type = buffer.get();
       code = buffer.get();
        System.out.println(DataTypeHelper.bToString(type));
       checksum[0] = buffer.get();
       checksum[1] = buffer.get();
    }

    public byte getType() {
        return type;
    }

    public byte getCode() {
        return code;
    }

    public byte[] getChecksum() {
        return checksum;
    } 
    
    
    
}
