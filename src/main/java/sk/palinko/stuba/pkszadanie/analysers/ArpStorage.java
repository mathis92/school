/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package sk.palinko.stuba.pkszadanie.analysers;

import sk.palinko.stuba.pkszadanie.equip.Frame;

/**
 *
 * @author Mathis
 */
public class ArpStorage {
    
    private final Frame request;
    private Frame reply;
    
    public ArpStorage(Frame request, Frame reply) {
    this.reply = reply;
    this.request = request;
    }  

    public Frame getReply() {
        return reply;
    }

    public Frame getRequest() {
        return request;
    }

    public void setReply(Frame reply) {
        this.reply = reply;
    }
    
    
}


