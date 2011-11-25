
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Paulo Cezar P. Costa
 */
public class SegInfTable extends AbstractTableModel {
    private String[] columnNames;
    private ArrayList< ArrayList<Object> > data;
    private RuleEntry rule_view;

    public SegInfTable(){
        columnNames = new String[6];
        columnNames[0] = "Ação";
        columnNames[1] = "IP Origem";
        columnNames[2] = "Porta Origem";
        columnNames[3] = "IP Destino ";
        columnNames[4] = "Porta Destino";
        columnNames[5] = "Protocolo";

        data = new ArrayList< ArrayList<Object> >();
        rule_view = new RuleEntry(this);
    }

    public void send_command( String command ){
        try{
            PrintWriter writer = new PrintWriter( new FileWriter("/proc/seginf") );
            writer.print(command);
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void save_data(PrintWriter writer){

        for( ArrayList<Object> rule : data ){
            String command = "";
            for( Object wut : rule ){
                command += (((String)wut) + " ");
            }
            writer.println(command);
        }

    }

    public void addRow( ArrayList<Object> values ){
        data.add( values );

        String command = "";
        if( ((String)values.get(0)).equals("Aceitar") ) command += "allow ";
        else command += "block ";

        if( !((String)values.get(1)).equals("*") )
            command += ( "-i " + ((String)values.get(1)) + " " );

        if( !((String)values.get(2)).equals("*") )
            command += ( "-s " + ((String)values.get(2)) + " " );

        if( !((String)values.get(3)).equals("*") )
            command += ( "-o " + ((String)values.get(3)) + " " );

        if( !((String)values.get(4)).equals("*") )
            command += ( "-d " + ((String)values.get(4)) + " " );


        if( !((String)values.get(5)).equals("*") )
            command += ( "-p IPPROTO_" + ((String)values.get(5)) + " " );

        send_command(command);

        fireTableRowsInserted(getRowCount(), getRowCount());
    }

    public void showInputWindow(){
        rule_view.cleanup();
        rule_view.setVisible(true);
    }

    public void deleteRow( int row ){
        data.remove(row);
        send_command( "remove " + (row+1) + " " );
        fireTableRowsDeleted(row, row);
    }

    public int getColumnCount() {
        return columnNames.length;
    }

    public int getRowCount() {
        return data.size();
    }

    @Override
    public String getColumnName(int col) {
        return columnNames[col];
    }

    public Object getValueAt(int row, int col) {
        return data.get(row).get(col);
    }

    @Override
    public Class getColumnClass(int c) {
        return getValueAt(0, c).getClass();
    }

    public void setValueAt(Object value, int row, int col) {
        data.get(row).set(col, value);
    }
}