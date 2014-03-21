/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package PksZadanie.equip;

import java.util.ArrayList;

public class CommunicationChannel {

    
    private byte[] ipAdress;
    private byte[] macAdress;    
    private ArrayList<Frame> tcpCommList;
    Frame frame;
    private boolean completed = false;
    public CommunicationChannel(Frame frame) {
        this.frame = frame;
        tcpCommList = new ArrayList<>();
    }

    public Frame getFrame() {
        return frame;
    }

    public byte[] getIpAdress() {
        return ipAdress;
    }

    public byte[] getMacAdress() {
        return macAdress;
    }

    public ArrayList<Frame> getTcpCommList() {
        return tcpCommList;
    }
    
    private boolean getCompleted(){
        return completed;
    }
    
}
