/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package PksZadanie.analysers;

import org.krakenapps.pcap.util.Buffer;

/**
 *
 * @author Mathis
 */
public class HttpParser extends AbstractAnalyser implements IAnalyser{

    public HttpParser(Buffer buffer) {
        super(buffer);
        analyze();
    }
    
    public void analyze(){
        
    }
    
}
