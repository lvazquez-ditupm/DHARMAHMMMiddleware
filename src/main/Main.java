package main;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Main {

	private static Scanner reader;
	public static InetAddress maquina;
	public static String alert = "";

	public final static String[] CVE = { "ET WEB_CLIENT Possible BeEF Module in use:2017-0001/medium/1.5",
			"ET INFO JAVA - ClassID:2012-0507/high/3",
			"ET INFO Java .jar request to dotted-quad domain:2012-0507/high/3",
			"ET INFO JAVA - Java Archive Download:2012-0507/high/3",
			"ET INFO Java .jar request to dotted-quad domain:2012-0507/high/3",
			"Possible Information Leak:2017-0002/high/5", "ET SCAN NMAP OS Detection Probe:1999-0977/low/0.75",
			"GPL POP3 POP3 PASS overflow attempt:2003-0264/high/3.5",
			"GPL SHELLCODE x86 inc ebx NOOP:2003-0264/high/3.5", "Admin User doing Suspicious Actions:2017-0005/high/4",
			"HTTP Reverse Shell:2017-0004/high/3", "Successful sudo to ROOT executed:2017-0006/high/3.5",
			"External Access to System:2017-0009/high/5.2", "New User Created:2017-0010/high/5.5",
			"ET DOS Inbound Low Orbit Ion Cannon LOIC DDOS Tool desu string:2013-5211/high/3.8" };

	public static HashMap<String, String> CVEMAP = new HashMap<>();
	public static String IPlocal;
	public static String IPDharma;
	public static Double risk;
	public static int socketInPort;
	public static int socketOutPort;
	public static String IPMySQL;
	public static String MySQLUser;
	public static String MySQLPass;
	public static int idHMM = 1;
	public static HashMap<String, HashMap<Integer, Integer>> HMMtable = new HashMap<>();
	public static HashMap<Integer, Process> processPool = new HashMap<>();
	public static String ipSrc = "";
	public static String ipDst = "";
	public static int portSrc = 0;
	public static int portDst = 0;
	public static String timestamp = "";

	public static void main(String[] args) throws Exception {

		IPlocal = args[0];
		IPDharma = args[1];
		socketInPort = Integer.parseInt(args[2]);
		socketOutPort = Integer.parseInt(args[3]);
		IPMySQL = args[4];
		MySQLUser = args[5];
		if (args.length == 7) {
			MySQLPass = args[6];
		} else {
			MySQLPass = "";
		}

		File root = new File("./");
		File[] files = root.listFiles();
		for (File file : files) {
			if (file.getName().contains(".hmm")) {
				file.delete();
			}
		}

		for (String item : CVE) {
			CVEMAP.put(item.split(":")[0], item.split(":")[1]);
		}

		maquina = InetAddress.getByName(IPlocal);

		Logstash logstash = new Logstash(socketInPort, maquina.getHostAddress());

		new Thread(logstash).start();

		while (true) {
			reader = new Scanner(System.in);
			System.out.print("Introduzca un evento: \n");
			String event = reader.nextLine();
			System.out.println("");
			processEvent(event);

		}

	}

	public static void processEvent(String log) {
		String event;
		
		if (log.contains("signature")) {
			if (log.contains("src_ip")) {
				ipSrc = log.substring(log.indexOf("src_ip") + 11);
				ipSrc = ipSrc.substring(0, ipSrc.indexOf(",") - 2);
			}

			if (log.contains("dest_ip")) {
				ipDst = log.substring(log.indexOf("dest_ip") + 12);
				ipDst = ipDst.substring(0, ipDst.indexOf(",") - 2);
			}
			if (log.contains("timestamp")) {
				timestamp = log.substring(log.indexOf("timestamp") + 14);
				timestamp = timestamp.substring(0, timestamp.indexOf(",") - 2);
			}
			if (log.contains("src_port")) {
				String src_port = log.substring(log.indexOf("src_port") + 11);
				src_port = src_port.substring(0, src_port.indexOf(","));
				portSrc = Integer.parseInt(src_port);
			}
			if (log.contains("dest_port")) {
				String dst_port = log.substring(log.indexOf("dest_port") + 12);
				dst_port = dst_port.substring(0, dst_port.indexOf(","));
				portDst = Integer.parseInt(dst_port);
			}
			log = log.substring(log.indexOf("signature") + 13);
			event = log.substring(log.indexOf("signature") + 14);
			event = event.substring(0, event.indexOf(",") - 2);

		} else if (log.contains("RC:")) {
			if (log.contains("SRCIP")) {
				ipSrc = log.substring(log.indexOf("SRCIP") + 9);
				ipSrc = ipSrc.substring(0, ipSrc.indexOf(";") - 2);
				if (ipSrc == "None") {
					ipSrc = "";
				}
			}
			if (log.contains("DSTIP")) {
				ipDst = log.substring(log.indexOf("DSTIP") + 9);
				ipDst = ipDst.substring(0, ipDst.indexOf(";") - 2);
				if (ipDst == "None") {
					ipDst = "";
				}
			}
			log = log.substring(log.indexOf("RC: "));
			event = log.substring(log.indexOf("RC: ") + 6);
			event = event.substring(0, event.indexOf(";") - 2);

			

		} else if (log.contains("DELETE")) {
			delete(Integer.parseInt(log.substring(7)));
			return;
		} else {

			event = log;
		}

		System.out.print(event);

		if (CVEMAP.get(event) != null) {
			risk = Double.parseDouble(CVEMAP.get(event).split("/")[2]);
		}

		if (event.contains("ET WEB_CLIENT Possible BeEF Module in use")) {
			sendToHMM(1, event, ipDst, portDst);
			sendToHMM(3, event, ipDst, portDst);
		} else if (event.contains("ET INFO JAVA - ClassID")
				|| event.contains("ET INFO Java .jar request to dotted-quad domain")
				|| event.contains("ET INFO JAVA - Java Archive Download")
				|| event.contains("ET INFO Java .jar request to dotted-quad domain")) {
			sendToHMM(1, event, ipSrc, portSrc);
		} else if (event.contains("Possible Information Leak")) {
			sendToHMM(1, event, ipSrc, portSrc);
			sendToHMM(3, event, ipSrc, portSrc);
		} else if (event.contains("ET SCAN NMAP OS Detection Probe")) {
			sendToHMM(2, event, ipDst, portDst);
			sendToHMM(4, event, ipDst, portDst);
		} else if (event.contains("GPL POP3 POP3 PASS overflow attempt")
				|| event.contains("GPL SHELLCODE x86 inc ebx NOOP")) {
			sendToHMM(2, event, ipDst, portDst);
			sendToHMM(4, event, ipDst, portDst);
		} else if (event.contains("Admin User doing Suspicious Actions")) {
			sendToHMM(2, event, ipSrc, portSrc);
		} else if (event.contains("Successful sudo to ROOT executed")) {
			sendToHMM(2, event, ipDst, portDst);
			sendToHMM(3, event, ipDst, portDst);
			/*
			 * } else if (event.contains("External Access to System")) {
			 * sendToHMM(3, event, ip);
			 */
		} else if (event.contains("User account enabled or created")) {
			sendToHMM(3, event, ipSrc, portSrc);
		} else if (event.contains("ET DOS Inbound Low Orbit Ion Cannon LOIC DDOS Tool desu string")) {
			sendToHMM(4, event, ipSrc, portSrc);
		}
	}

	private static void delete(int id) {
		Process p = processPool.get(id);
		p.destroy();
		for (Map.Entry<String, HashMap<Integer, Integer>> ipsItem : HMMtable.entrySet()){
			for (Map.Entry<Integer, Integer> attItem : ipsItem.getValue().entrySet()){
				if (attItem.getValue() == id){
					HMMtable.get(ipsItem.getKey()).remove(attItem.getKey());
					System.out.println("Eliminado ataque "+id);
					if (HMMtable.get(ipsItem.getKey()).isEmpty()){
						System.out.println ("Eliminada IP "+ipsItem.getKey());
						HMMtable.remove(ipsItem);
					}
					break;
				}
			}
		}
	}

	public static void sendToHMM(int idAtt, String typeAtt, String ip, int port) {
		if (!HMMtable.containsKey(ip) || !HMMtable.get(ip).containsKey(idAtt)) {
			HashMap<Integer, Integer> attToChain = new HashMap<>();
			attToChain.put(idAtt, idHMM);
			if (HMMtable.containsKey(ip)) {
				HMMtable.get(ip).putAll(attToChain);
			} else {
				HMMtable.put(ip, attToChain);
			}
			
			System.out.print(" enviado a nueva cadena\n");
			
			String cmd = "java -jar HMMprediction.jar attack" + idAtt + ".conf input" + idHMM + ".hmm " + IPMySQL + " " + socketOutPort + " " + MySQLUser + " " + MySQLPass;
			
			try {
				//System.out.println(ip);
				//System.out.println(cmd);
				Process p = Runtime.getRuntime().exec(cmd);
				processPool.put(idHMM++, p);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		System.out.print(" enviado a cadena existente\n");
		
		PrintWriter writer;
		try {
			writer = new PrintWriter(
					new BufferedWriter(new FileWriter("input" + HMMtable.get(ip).get(idAtt) + ".hmm", true)));
			String[] cve = CVEMAP.get(typeAtt).split("/");
			String output = "CVE=" + cve[0] + ";Severity=" + cve[1] + ";Risk=" + cve[2] + ";ID=" + HMMtable.get(ip).get(idAtt);
			if (ipSrc!=""){
				output+=";IPsrc="+ipSrc;
			}
			if (ipDst!=""){
				output+=";IPdst="+ipDst;
			}
			if (port != 0){
				output += ";Port="+port;
			}
			if (timestamp != ""){
				output+=";Timestamp="+timestamp;
			}
			writer.println(output);
			writer.close();
		} catch (Exception ex) {
			System.err.println(ex);
		}
	}
}
