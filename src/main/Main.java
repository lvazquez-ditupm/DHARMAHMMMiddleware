package main;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
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
				BufferedWriter bw = new BufferedWriter(new FileWriter(file.getAbsolutePath()));
				bw.write("");
				bw.close();
			}
		}

		for (String item : CVE) {
			CVEMAP.put(item.split(":")[0], item.split(":")[1]);
		}

		maquina = InetAddress.getByName(IPlocal);

		Logstash logstash = new Logstash(socketInPort, maquina.getHostAddress());

		String cmd = "java -jar HMMprediction.jar ddos.conf " + "input4.hmm" + " " + IPMySQL + " " + socketOutPort + " "+ MySQLUser + " " + MySQLPass;

		HMM hmm = new HMM(cmd);

		new Thread(hmm).start();

		new Thread(logstash).start();

		while (true) {
			reader = new Scanner(System.in);
			System.out.print("Introduzca un evento: ");
			String event = reader.nextLine();
			System.out.println("");
			// processEvent(event);

		}

	}

	public static void processEvent(String log) {
		String event;
		if (log.contains("signature")) {
			log = log.substring(log.indexOf("signature") + 13);
			event = log.substring(log.indexOf("signature") + 14);
			event = event.substring(0, event.indexOf(",") - 2);
		} else if (log.contains("RC:")) {
			log = log.substring(log.indexOf("RC: "));
			event = log.substring(log.indexOf("RC: ") + 6);
			event = event.substring(0, event.indexOf(";") - 2);
		} else {
			event = log;
		}

		if (CVEMAP.get(event) != null) {
			risk = Double.parseDouble(CVEMAP.get(event).split("/")[2]);
		}

		if (event.contains("ET WEB_CLIENT Possible BeEF Module in use")) {
			sendToHMM(1, event);
			sendToHMM(3, event);
		} else if (event.contains("ET INFO JAVA - ClassID")
				|| event.contains("ET INFO Java .jar request to dotted-quad domain")
				|| event.contains("ET INFO JAVA - Java Archive Download")
				|| event.contains("ET INFO Java .jar request to dotted-quad domain")) {
			sendToHMM(1, event);
		} else if (event.contains("Possible Information Leak")) {
			sendToHMM(1, event);
			sendToHMM(3, event);
		} else if (event.contains("ET SCAN NMAP OS Detection Probe")) {
			sendToHMM(2, event);
			sendToHMM(4, event);
		} else if (event.contains("GPL POP3 POP3 PASS overflow attempt")
				|| event.contains("GPL SHELLCODE x86 inc ebx NOOP")) {
			sendToHMM(2, event);
			sendToHMM(4, event);
		} else if (event.contains("Admin User doing Suspicious Actions")) {
			sendToHMM(2, event);
		} else if (event.contains("Successful sudo to ROOT executed")) {
			sendToHMM(2, event);
			sendToHMM(3, event);
		} else if (event.contains("External Access to System")) {
			sendToHMM(3, event);
		} else if (event.contains("New User Created")) {
			sendToHMM(3, event);
		} else if (event.contains("ET DOS Inbound Low Orbit Ion Cannon LOIC DDOS Tool desu string")) {
			sendToHMM(4, event);
		}
	}

	public static void sendToHMM(int idAtt, String typeAtt) {
		PrintWriter writer;
		try {
			writer = new PrintWriter(new BufferedWriter(new FileWriter("./input" + idAtt + ".hmm", true)));
			String[] cve = CVEMAP.get(typeAtt).split("/");
			writer.println("CVE=" + cve[0] + ";Severity=" + cve[1] + ";Risk=" + cve[2]);
			writer.close();
		} catch (Exception ex) {
			System.err.println(ex);
		}

	}

}
