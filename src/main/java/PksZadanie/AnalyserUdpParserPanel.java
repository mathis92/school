/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PksZadanie;

import PksZadanie.equip.UdpCommunication;
import PksZadanie.equip.UdpParserDataUpdater;
import javax.swing.JTable;
import javax.swing.JTextArea;
import pkszadanie.analysers.Analyser;

/**
 *
 * @author Mathis
 */
public class AnalyserUdpParserPanel extends javax.swing.JPanel {

    /**
     * Creates new form AnalyserUdpParserPanel
     */
    Analyser an;
    UdpCommunication comm;

    public AnalyserUdpParserPanel(Analyser an, UdpCommunication communication) {
this.comm = communication;
        this.an = an;
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jDialog1 = new javax.swing.JDialog();
        jScrollPane1 = new javax.swing.JScrollPane();
        jDataText = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        udpMainTable = new javax.swing.JTable();

        jDialog1.setAlwaysOnTop(true);

        jDataText.setEditable(false);
        jDataText.setColumns(20);
        jDataText.setFont(new java.awt.Font("Courier New", 0, 13)); // NOI18N
        jDataText.setRows(5);
        jDataText.setToolTipText("");
        jDataText.setName("Frame Data"); // NOI18N
        jScrollPane1.setViewportView(jDataText);

        javax.swing.GroupLayout jDialog1Layout = new javax.swing.GroupLayout(jDialog1.getContentPane());
        jDialog1.getContentPane().setLayout(jDialog1Layout);
        jDialog1Layout.setHorizontalGroup(
            jDialog1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDialog1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 904, Short.MAX_VALUE)
                .addContainerGap())
        );
        jDialog1Layout.setVerticalGroup(
            jDialog1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDialog1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 561, Short.MAX_VALUE)
                .addContainerGap())
        );

        setMinimumSize(new java.awt.Dimension(940, 530));

        udpMainTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Id", "Frame id", "Protocol ", "SourceIp ", "Source Port", "DestinationIp", "Destination Port"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Integer.class, java.lang.Integer.class, java.lang.Integer.class, java.lang.String.class, java.lang.Integer.class, java.lang.String.class, java.lang.Integer.class
            };
            boolean[] canEdit = new boolean [] {
                false, false, false, false, false, false, false
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        udpMainTable.setColumnSelectionAllowed(true);
        udpMainTable.setName(""); // NOI18N
        udpMainTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                udpMainTableMouseClicked(evt);
            }
        });
        jScrollPane2.setViewportView(udpMainTable);
        udpMainTable.getColumnModel().getSelectionModel().setSelectionMode(javax.swing.ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        if (udpMainTable.getColumnModel().getColumnCount() > 0) {
            udpMainTable.getColumnModel().getColumn(0).setResizable(false);
            udpMainTable.getColumnModel().getColumn(1).setResizable(false);
            udpMainTable.getColumnModel().getColumn(2).setResizable(false);
            udpMainTable.getColumnModel().getColumn(3).setResizable(false);
            udpMainTable.getColumnModel().getColumn(4).setResizable(false);
            udpMainTable.getColumnModel().getColumn(5).setResizable(false);
            udpMainTable.getColumnModel().getColumn(6).setResizable(false);
        }

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 940, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 920, Short.MAX_VALUE)
                    .addContainerGap()))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 530, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(5, 5, 5)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 519, Short.MAX_VALUE)
                    .addGap(6, 6, 6)))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void udpMainTableMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_udpMainTableMouseClicked
        jDialog1.setVisible(true);
        jDialog1.setSize(800, 600);
        jDialog1.setTitle("data from " + an.getPcap().getAbsolutePath() + " frame no. " + (comm.getList().get(udpMainTable.getSelectedRow()).getId()));
        UdpParserDataUpdater communicationSetter = new UdpParserDataUpdater(comm.getList().get(udpMainTable.getSelectedRow()), this);
        communicationSetter.update();
    }//GEN-LAST:event_udpMainTableMouseClicked

    public JTextArea getjDataText() {
        return jDataText;
    }

    public JTable getUdpMainTable() {
        return udpMainTable;
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea jDataText;
    private javax.swing.JDialog jDialog1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTable udpMainTable;
    // End of variables declaration//GEN-END:variables


}
