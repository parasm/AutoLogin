import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.MediaTracker;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

import javax.net.ssl.HttpsURLConnection;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class AutoLogin extends JFrame{
    private static final long serialVersionUID = 1L;
    public final JTextField username;
    public final JTextField password;
    private final JButton signin;
    public AutoLogin(boolean saved){
    	super("AutoLogin");
    	this.username = new JTextField(10);
    	this.password = new JPasswordField(10);
    	this.signin = new JButton("Sign in");
    	if(saved){
    		final Container mainPanel = getContentPane();
    		mainPanel.setLayout(new BorderLayout());
    		JPanel buttonPanel = new JPanel();
    		mainPanel.add(buttonPanel);
    		buttonPanel.add(signin);
    		signin.addActionListener(new ActionListener() {
		        @Override  
		        public void actionPerformed(final ActionEvent ae){
		        	try{
		        		String[]userPass = readFile("creds.txt");
		        		signIn(userPass[0],userPass[1]);
		        		JOptionPane.showMessageDialog(null, "Sucessfully logged in", "Sucess", JOptionPane.INFORMATION_MESSAGE);
		        	}catch(Exception e){
		        		JOptionPane.showMessageDialog(null,e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
		        		//System.out.println("Failed");
		        	}
		                  
		        }
		    });
    	}else{
			JLabel user = new JLabel("Enter username: ");
			JLabel pass = new JLabel("Enter password: ");
			user.setLabelFor(username);
			pass.setLabelFor(password);
		    signin.addActionListener(new ActionListener() {
		        @Override  
		        public void actionPerformed(final ActionEvent ae){
		        	try{
		        		signInHelper();
		        		JOptionPane.showMessageDialog(null, "Sucessfully logged in", "Sucess", JOptionPane.INFORMATION_MESSAGE);
		        	}catch(Exception e){
		        		JOptionPane.showMessageDialog(null,e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
		        		System.out.println("Failed");
		        	}
		                  
		        }
		    });
		    final Container mainPanel = getContentPane();
		    mainPanel.setLayout(new BorderLayout());
		    final JPanel spacePanel = new JPanel();
		    final JPanel enterPanel = new JPanel();
		    enterPanel.setLayout(new BorderLayout());
		    final JPanel usernamePanel = new JPanel();
		    usernamePanel.setLayout(new BorderLayout());
		    final JPanel passwordPanel = new JPanel();
		    usernamePanel.setLayout(new BorderLayout());
		    final JPanel button = new JPanel();
		    button.setLayout(new BorderLayout());
		    usernamePanel.add(user,BorderLayout.LINE_START);
		    usernamePanel.add(username,BorderLayout.LINE_END);
		    passwordPanel.add(pass, BorderLayout.LINE_START);
		    passwordPanel.add(password, BorderLayout.LINE_END);
		    button.add(signin);
		    enterPanel.add(usernamePanel,BorderLayout.PAGE_START);
		    enterPanel.add(passwordPanel, BorderLayout.PAGE_END);
		    mainPanel.add(spacePanel, BorderLayout.CENTER);
		    mainPanel.add(enterPanel,BorderLayout.NORTH);
		    mainPanel.add(button,BorderLayout.SOUTH);
    		}
		    setResizable(true);
		    setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		    pack();
		    setLocationRelativeTo(null);
		    setVisible(true);
    
    }
    /*base 64 stuff to encode file with username credentials  */
    public static String decodeString (String s) {
        return new String(decode(s)); }

     public static byte[] decodeLines (String s) {
        char[] buf = new char[s.length()];
        int p = 0;
        for (int ip = 0; ip < s.length(); ip++) {
           char c = s.charAt(ip);
           if (c != ' ' && c != '\r' && c != '\n' && c != '\t')
              buf[p++] = c; }
        return decode(buf, 0, p); }

     public static byte[] decode (String s) {
        return decode(s.toCharArray()); }

     public static byte[] decode (char[] in) {
        return decode(in, 0, in.length); }
     private static final char[] map1 = new char[64];
     static {
        int i=0;
        for (char c='A'; c<='Z'; c++) map1[i++] = c;
        for (char c='a'; c<='z'; c++) map1[i++] = c;
        for (char c='0'; c<='9'; c++) map1[i++] = c;
        map1[i++] = '+'; map1[i++] = '/'; }

  // Mapping table from Base64 characters to 6-bit nibbles.
  private static final byte[] map2 = new byte[128];
     static {
        for (int i=0; i<map2.length; i++) map2[i] = -1;
        for (int i=0; i<64; i++) map2[map1[i]] = (byte)i; }

     public static byte[] decode (char[] in, int iOff, int iLen) {
        if (iLen%4 != 0) throw new IllegalArgumentException ("Length of Base64 encoded input string is not a multiple of 4.");
        while (iLen > 0 && in[iOff+iLen-1] == '=') iLen--;
        int oLen = (iLen*3) / 4;
        byte[] out = new byte[oLen];
        int ip = iOff;
        int iEnd = iOff + iLen;
        int op = 0;
        while (ip < iEnd) {
           int i0 = in[ip++];
           int i1 = in[ip++];
           int i2 = ip < iEnd ? in[ip++] : 'A';
           int i3 = ip < iEnd ? in[ip++] : 'A';
           if (i0 > 127 || i1 > 127 || i2 > 127 || i3 > 127)
              throw new IllegalArgumentException ("Illegal character in Base64 encoded data.");
           int b0 = map2[i0];
           int b1 = map2[i1];
           int b2 = map2[i2];
           int b3 = map2[i3];
           if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0)
              throw new IllegalArgumentException ("Illegal character in Base64 encoded data.");
           int o0 = ( b0       <<2) | (b1>>>4);
           int o1 = ((b1 & 0xf)<<4) | (b2>>>2);
           int o2 = ((b2 &   3)<<6) |  b3;
           out[op++] = (byte)o0;
           if (op<oLen) out[op++] = (byte)o1;
           if (op<oLen) out[op++] = (byte)o2; }
        return out; }

    public String getIP() throws Exception{
    	int net = 1;
    	Enumeration e=NetworkInterface.getNetworkInterfaces();
        while(e.hasMoreElements()){
            NetworkInterface n=(NetworkInterface) e.nextElement();
            Enumeration ee = n.getInetAddresses();
            while(ee.hasMoreElements()){
                InetAddress i= (InetAddress) ee.nextElement();
                if(net == 3){
                	return i.getHostAddress();
                }
                
                net++;
            }
        }
        return "Error";
    }
    private static final String base64code = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "abcdefghijklmnopqrstuvwxyz" + "0123456789" + "+/";
 
    private static final int splitLinesAt = 76;
 
    public static byte[] zeroPad(int length, byte[] bytes) {
        byte[] padded = new byte[length]; // initialized to zero by JVM
        System.arraycopy(bytes, 0, padded, 0, bytes.length);
        return padded;
    }
 
    public static String encode(String string) {
        String encoded = "";
        byte[] stringArray;
        try {
            stringArray = string.getBytes("UTF-8");
        } catch (Exception ignored) {
            stringArray = string.getBytes();
        }
        int paddingCount = (3 - (stringArray.length % 3)) % 3;
        stringArray = zeroPad(stringArray.length + paddingCount, stringArray);
        for (int i = 0; i < stringArray.length; i += 3) {
            int j = ((stringArray[i] & 0xff) << 16) +
                ((stringArray[i + 1] & 0xff) << 8) + 
                (stringArray[i + 2] & 0xff);
            encoded = encoded + base64code.charAt((j >> 18) & 0x3f) +
                base64code.charAt((j >> 12) & 0x3f) +
                base64code.charAt((j >> 6) & 0x3f) +
                base64code.charAt(j & 0x3f);
        }
        return splitLines(encoded.substring(0, encoded.length() -
            paddingCount) + "==".substring(0, paddingCount));
 
    }
    public static String splitLines(String string) {
 
        String lines = "";
        for (int i = 0; i < string.length(); i += splitLinesAt) {
            lines += string.substring(i, Math.min(string.length(), i + splitLinesAt));
            lines += "\r\n";
        }
        return lines;
 
    }
    public String base64(String s) {
        return encode(s);
    }
    public void createFile(String username, String password) throws Exception{
    	File statText = new File("creds.txt");
        FileOutputStream is = new FileOutputStream(statText);
        OutputStreamWriter osw = new OutputStreamWriter(is);    
        Writer w = new BufferedWriter(osw);
        w.write(username + "-" +password);
        w.close();
    }
    public static String[] readFile(String filename) throws Exception{
    	 Scanner input = new Scanner(new File(filename));
    	 StringBuilder sb = new StringBuilder();
    	 while(input.hasNext()){
    		 sb.append(input.next());
    	 }
    	 String unparsed =  sb.toString();
    	 String[] userPass = new String[2];
    	 userPass = unparsed.split("-");
    	 userPass[0] = decodeString(userPass[0]);
    	 userPass[1] = decodeString(userPass[1]);
    	 return userPass;
    }
    public void signInHelper() throws Exception{
    	String username = this.username.getText();
    	String password = this.password.getText();
    	if(username.isEmpty() && password.isEmpty()){
    		throw new IllegalArgumentException("Cannot leave username and password blank");
    	}else if(username.isEmpty()){
    		throw new IllegalArgumentException("Cannot leave username blank");
    	}else if(password.isEmpty()){
    		throw new IllegalArgumentException("Cannot leave password blank");
    	}else{
    		signIn(username,password);
    		createFile(base64(username),base64(password));
    	}
    }
    public void signIn(String username, String password) throws Exception{
    	//System.setProperty("http.agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.29 Safari/537.36");
    	String httpsURL = "https://ccahack.bergen.org/auth/perfigo_validate.jsp";
    	String ip = getIP();
    	StringBuilder q = new StringBuilder();
    	q.append("reqFrom="+URLEncoder.encode("perfigo_simple_login.jsp","UTF-8")); 
    	q.append("&uri="+ URLEncoder.encode("https://ccahack.bergen.org/","UTF-8"));
    	q.append("&cm=" + URLEncoder.encode("ws32vklm", "UTF-8"));
    	q.append("&userip="+URLEncoder.encode(ip,"UTF-8"));
    	q.append("&os=" +URLEncoder.encode("MAC_OSX","UTF-8"));
    	q.append("&index="+URLEncoder.encode("4","UTF-8"));
    	q.append("&username="+URLEncoder.encode(username,"UTF-8"));
    	q.append("&password="+URLEncoder.encode(password,"UTF-8"));
    	q.append("&provider="+URLEncoder.encode("BCA","UTF-8"));
    	q.append("&login_submt="+URLEncoder.encode("Continue","UTF8"));
    	String query = q.toString();
    	URL myurl = new URL(httpsURL);
    	HttpsURLConnection con = (HttpsURLConnection)myurl.openConnection();
    	con.setRequestMethod("POST");
    	con.setRequestProperty("Content-length", String.valueOf(query.length())); 
    	con.setRequestProperty("Content-Type","application/x-www-form-urlencoded");  
    	con.setRequestProperty("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0;Windows98;DigExt)"); 
    	con.setDoOutput(true); 
    	con.setDoInput(true); 

    	DataOutputStream output = new DataOutputStream(con.getOutputStream());  


    	output.writeBytes(query);

    	output.close();

    	DataInputStream input = new DataInputStream( con.getInputStream() ); 



    	for( int c = input.read(); c != -1; c = input.read() ) 
    	System.out.print( (char)c ); 
    	input.close(); 

    	System.out.println("Resp Code:"+con.getResponseCode()); 
    	System.out.println("Resp Message:"+ con.getResponseMessage()); 
    	
    }

	public static void main(String[] args) {
		boolean saved = false;
		try{
			readFile("creds.txt");
			saved = true;
		}catch(Exception e){
			saved = false;
		}
		AutoLogin al = new AutoLogin(saved);

	}

}