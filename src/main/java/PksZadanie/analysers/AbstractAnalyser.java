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
abstract class AbstractAnalyser implements IAnalyser{
    Buffer buffer;

    public AbstractAnalyser(Buffer buffer) {
        this.buffer = buffer;
    }

    @Override
    public void analyse() {
    }
}
