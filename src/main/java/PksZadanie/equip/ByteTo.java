/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PksZadanie.equip;

import java.text.DecimalFormat;

/**
 *
 * @author Mathis
 */
public class ByteTo {

    //  public byte[] byteArray;
    //  public byte singleByte;
    /*
     public ByteTo(byte[] byteArray) {
     this.byteArray = byteArray;
  
     }

     public ByteTo(byte singleByte) {
     this.singleByte = singleByte;
     }
     */
    public static String UnitConverter(double size) {

        String output;
        
        DecimalFormat temp1 = new DecimalFormat("#,#0.0");
        double temp = size;
        String[] units = new String[]{"B", "KB", "MB", "GB", "TB"};
        int i = 0;
        while (temp > 1) {
            i++;
            temp = temp / (1024);
            System.out.println(temp);
        }
        temp = temp * 1024;
        double out = new Double(temp1.format(temp)).doubleValue();
        output = out + " " + units[i - 1];// + "( " + out2 + " B )";

        return output;
    }

    public static Integer singleToInt(byte singleByte) {
        Integer result = 0;
        result = (singleByte & 0xff);
        return result;

    }

    public static Integer toInt(byte[] byteArray) {
        Integer result = 0;

        for (int i = 0; i < byteArray.length - 1; i++) {
            result = ((byteArray[i] & 0xff) << 8) | ((byteArray[i + 1] & 0xff));

        }
        return result;

    }

    public static String bToString(byte singleByte) {
        StringBuilder newString = new StringBuilder();
        newString.append(String.format("%02X ", singleByte));
        return newString.toString();
    }
}
