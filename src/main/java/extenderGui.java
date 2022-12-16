                          
                        
/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JPanel.java to edit this template
 */
package burp;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

/**
 *
 * @author Anany
 */

public class extenderGui extends javax.swing.JPanel {

    /**
     * Creates new form extenderGui
     */
    public boolean jsonIsload;
    public String optionStatus = "Run";
    
    public extenderGui() {
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

        btn1 = new javax.swing.JToggleButton();
        jCheckBox1 = new javax.swing.JCheckBox();
        btnExport = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        tableResult = new javax.swing.JTable();
        btnClear = new javax.swing.JButton();
        inputResRegex = new javax.swing.JTextField();

        setToolTipText("");

        btn1.setText("Run");
        btn1.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
        btn1.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                btn1StateChanged(evt);
            }
        });
        btn1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn1ActionPerformed(evt);
            }
        });

        jCheckBox1.setText("Active check");
        jCheckBox1.setToolTipText("Check if the account/page can be takeover or not");
        jCheckBox1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBox1ActionPerformed(evt);
            }
        });

        btnExport.setText("Export");
        btnExport.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                btnExportMouseClicked(evt);
            }
        });
        btnExport.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnExportActionPerformed(evt);
            }
        });

        tableResult.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "#", "Status", "Social Url", "From"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Integer.class, java.lang.String.class, java.lang.String.class, java.lang.String.class
            };
            boolean[] canEdit = new boolean [] {
                false, true, true, true
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        TableColumnModel TCM = tableResult.getColumnModel();
        TCM.getColumn(1).setPreferredWidth(300);
        TCM.getColumn(2).setPreferredWidth(1800);
        TCM.getColumn(3).setPreferredWidth(1800);
        tableResult.setAutoCreateRowSorter(true);
        // alignment # value to left
        DefaultTableCellRenderer NoColu = new DefaultTableCellRenderer();
        NoColu.setHorizontalAlignment(JLabel.LEFT);
        tableResult.getColumnModel().getColumn(0).setCellRenderer(NoColu);
        // aligment stauts to center
        DefaultTableCellRenderer statusColu = new DefaultTableCellRenderer();
        statusColu.setHorizontalAlignment(JLabel.CENTER);
        tableResult.getColumnModel().getColumn(1).setCellRenderer(statusColu);
        tableResult.setToolTipText("");
        tableResult.setAlignmentX(1.0F);
        tableResult.setAlignmentY(1.0F);
        tableResult.setAutoscrolls(false);
        tableResult.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        tableResult.setRowHeight(25);
        tableResult.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        tableResult.setShowGrid(true);
        tableResult.setSurrendersFocusOnKeystroke(true);
        tableResult.getTableHeader().setResizingAllowed(false);
        tableResult.getTableHeader().setReorderingAllowed(false);
        tableResult.setVerifyInputWhenFocusTarget(false);
        jScrollPane1.setViewportView(tableResult);

        btnClear.setText("Clear");
        btnClear.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                btnClearMouseClicked(evt);
            }
        });

        inputResRegex.setText("https://github.com/alanEG/Sock/blob/main/resource/regex.json");
        inputResRegex.setToolTipText("Enter Regex path or url for math social media links by regex in path/url for more information README.txt");
        inputResRegex.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                inputResRegexActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(btn1, javax.swing.GroupLayout.PREFERRED_SIZE, 129, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jCheckBox1, javax.swing.GroupLayout.PREFERRED_SIZE, 124, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(btnExport, javax.swing.GroupLayout.PREFERRED_SIZE, 129, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 1087, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(inputResRegex, javax.swing.GroupLayout.PREFERRED_SIZE, 381, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(btnClear, javax.swing.GroupLayout.PREFERRED_SIZE, 129, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(2, 2, 2)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btn1, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnExport)
                    .addComponent(jCheckBox1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnClear)
                    .addComponent(inputResRegex, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 870, Short.MAX_VALUE))
        );

        inputResRegex.getAccessibleContext().setAccessibleName("");
    }// </editor-fold>//GEN-END:initComponents
    
    private void jCheckBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBox1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jCheckBox1ActionPerformed

    private void btn1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn1ActionPerformed
        // turn on and off
        if (btn1.getText() == "Run") {
            btn1.setText("Stop");
        } else{
            btn1.setText("Run");
            jsonIsload = false;
        }
        optionStatus = btn1.getText();
    }//GEN-LAST:event_btn1ActionPerformed

    private void btn1StateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_btn1StateChanged
        // TODO add your handling code here:
    }//GEN-LAST:event_btn1StateChanged

    private void btnClearMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnClearMouseClicked
        // TODO add your handling code here:
        int Confim = JOptionPane.showConfirmDialog(null, "Are you sure you want clear history?", "Select an Option...",JOptionPane.YES_NO_OPTION,     JOptionPane.ERROR_MESSAGE);
        if (Confim == 0){
            DefaultTableModel model = (DefaultTableModel) tableResult.getModel();
            model.setRowCount(0);
        }
    }//GEN-LAST:event_btnClearMouseClicked
    private void btnExportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnExportActionPerformed
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
            File file;
            file = fileChooser.getSelectedFile();
            try {
                // save to file
                TableModel model = tableResult.getModel();
                FileWriter csv;
                csv = new FileWriter(new File(file.getAbsolutePath()));
                for (int i=0; i < model.getColumnCount(); i++){
                    csv.write(model.getColumnName(i)+ ",");
                }
                csv.write("\n");

                for (int i=0; i < model.getRowCount(); i++){
                    for (int j = 0; j < model.getColumnCount(); j++){
                        csv.write(model.getValueAt(i,j).toString() + ",");
                    }
                    csv.write("\n");
                }
                csv.close();
            } catch (IOException e) {
            }
        }

    }//GEN-LAST:event_btnExportActionPerformed
    
    private void btnExportMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnExportMouseClicked
        // parent component of the dialog
        JFileChooser fileChooser = new JFileChooser();
    }//GEN-LAST:event_btnExportMouseClicked

    private void inputResRegexActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_inputResRegexActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_inputResRegexActionPerformed
    
    public void addToTable(String status, String socialUrl,String From){
        DefaultTableModel model = (DefaultTableModel) tableResult.getModel();
        model.addRow(new Object[]{model.getRowCount() + 1,status,socialUrl, From});
    }
    
    public boolean getOptionActiveCheck(){
        return jCheckBox1.isSelected();
    }
    
    //return path from input 
    public String getRegexLocation(){
        return inputResRegex.getText();
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    public javax.swing.JToggleButton btn1;
    javax.swing.JButton btnClear;
    javax.swing.JButton btnExport;
    javax.swing.JTextField inputResRegex;
    javax.swing.JCheckBox jCheckBox1;
    javax.swing.JScrollPane jScrollPane1;
    javax.swing.JTable tableResult;
    // End of variables declaration//GEN-END:variables
}
