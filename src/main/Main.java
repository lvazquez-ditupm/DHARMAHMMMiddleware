package main;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;

public class Main {

	private static Scanner reader;
	public static InetAddress maquina;
	public static String alert = "";
	public final static String[] HMMTRAINED = { "Nmap scan", "GPL POP3 POP3 PASS overflow attempt",
			"GPL SHELLCODE x86 inc ebx NOOP", "ET DOS Inbound Low Orbit Ion Cannon LOIC DDOS Tool desu String" };
	public final static ArrayList<String> HMMTRAINEDLIST = new ArrayList<String>(Arrays.asList(HMMTRAINED));
	public final static String[] CVE = { "ET WEB_CLIENT Possible BeEF Module in use:2017-0001/medium/1.5",
			"ET INFO JAVA - ClassID:2012-0507/high/3",
			"ET INFO Java .jar request to dotted-quad domain:2012-0507/high/3",
			"ET INFO JAVA - Java Archive Download:2012-0507/high/3",
			"ET INFO Java .jar request to dotted-quad domain:2012-0507/high/3", "Information Leak:2017-0002/high/5",
			"Nmap scan:1999-0977/low/0.75", "GPL POP3 POP3 PASS overflow attempt:2003-0264/high/3.5",
			"GPL SHELLCODE x86 inc ebx NOOP:2003-0264/high/3.5", "SYSTEM Actions:2017-0005/high/4",
			"HTTP Reverse Shell:2017-0004/high/3", "Successful sudo to ROOT executed:2017-0006/high/3.5",
			"Access Admin node:2017-0009/high/5.2", "Persistence:2017-0010/high/5.5",
			"ET DOS Inbound Low Orbit Ion Cannon LOIC DDOS Tool desu String:2013-5211/high/3.8" };

	public static HashMap<String, String> CVEMAP = new HashMap<>();
	public static String IPlocal;
	public static String IPDharma;
	public static int socketInPort;
	public static int socketOutPort;
	public static String HMMinputroute;
	public static String IPMySQL;
	public static String MySQLUser;
	public static String MySQLPass;

	public static void main(String[] args) throws Exception {

		IPlocal = args[0];
		IPDharma = args[1];
		socketInPort = Integer.parseInt(args[2]);
		socketOutPort = Integer.parseInt(args[3]);
		HMMinputroute = args[4];
		IPMySQL = args[5];
		MySQLUser = args[6];
		if (args.length == 8) {
			MySQLPass = args[7];
		} else {
			MySQLPass = "";
		}

		for (String item : CVE) {
			CVEMAP.put(item.split(":")[0], item.split(":")[1]);
		}

		maquina = InetAddress.getByName(IPlocal);

		Logstash logstash = new Logstash(socketInPort, maquina.getHostAddress());
		HMM hmm = new HMM("java -jar HMMprediction.jar ddos.conf " + HMMinputroute + " " + IPMySQL + " " + socketOutPort
				+ " " + MySQLUser + " " + MySQLPass);

		new Thread(hmm).start();
		new Thread(logstash).start();

		while (true) {
			reader = new Scanner(System.in);
			System.out.print("Introduzca un evento: ");
			String event = reader.nextLine();
			System.out.println("");
			processEvent(event);
		}
	}

	public static void processEvent(String log) {
		String event;
		if (log.contains("signature")) {
			log = log.substring(log.indexOf("signature") + 13);
			event = log.substring(log.indexOf("signature") + 14);
			event = event.substring(0, event.indexOf(",") - 2);
		} else {
			event = log;
		}
		if (HMMTRAINEDLIST.contains(event)) {
			sendToHMM(event);
		}
		
		Double risk = Double.parseDouble(CVEMAP.get(event).split("/")[2]);
		
		if (event.contains("ET WEB_CLIENT Possible BeEF Module in use")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Filtracion" };
			sendToDharma(99, "BeEF", nodes, nodes[0], rand(0.35, 0.55), 0.33, risk);
			String[] nodes2 = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes2, nodes2[0], rand(0.15, 0.40), 0.14, risk);

		} else if (event.contains("ET INFO JAVA - ClassID")
				|| event.contains("ET INFO Java .jar request to dotted-quad domain")
				|| event.contains("ET INFO JAVA - Java Archive Download")
				|| event.contains("ET INFO Java .jar request to dotted-quad domain")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Filtracion" };
			sendToDharma(99, "BeEF", nodes, nodes[1], rand(0.5, 0.65), 0.67, risk);

		} else if (event.contains("Information Leak")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Filtracion" };
			sendToDharma(99, "BeEF", nodes, nodes[2], rand(0.7, 0.95), 1, risk);
			String[] nodes2 = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes2, nodes2[3], rand(0.5, 0.7), 0.57, risk);

		} else if (event.contains("Nmap scan")) {
			String[] nodes = { "Intento de intrusion", "Buffer Overflow", "Sudo", "Acciones SYSTEM" };
			sendToDharma(98, "Control de sistema mediante Buffer Overflow", nodes, nodes[0], rand(0.1, 0.4), 0.25, risk);

		} else if (event.contains("GPL POP3 POP3 PASS overflow attempt")
				|| event.contains("GPL SHELLCODE x86 inc ebx NOOP")) {
			String[] nodes = { "Intento de intrusion", "Buffer Overflow", "Sudo", "Acciones SYSTEM" };
			sendToDharma(98, "Control de sistema mediante Buffer Overflow", nodes, nodes[2], rand(0.6, 0.9), 0.75, risk);

		} else if (event.contains("SYSTEM Actions")) {
			String[] nodes = { "Intento de intrusion", "Buffer Overflow", "Sudo", "Acciones SYSTEM" };
			sendToDharma(98, "Control de sistema mediante Buffer Overflow", nodes, nodes[3], rand(0.75, 1.0), 1.0, risk);

		} else if (event.contains("HTTP Reverse Shell")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes, nodes[1], rand(0.25, 0.45), 0.28, risk);

		} else if (event.contains("Successful sudo to ROOT executed")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes, nodes[2], rand(0.4, 0.6), 0.42, risk);

		} else if (event.contains("Access Admin node")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes, nodes[4], rand(0.7, 0.9), 0.85, risk);

		} else if (event.contains("Persistence")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes, nodes[5], rand(0.8, 1.0), 1.0, risk);

		} else if (event.contains("LOIC")) {
		} else {
			System.err.println("Evento desconocido");
		}
	}

	public static void sendToDharma(int idAtt, String typeAtt, String[] nodes, String state, double pState,
			double pFinal, double risk) {

		String nodes_ = "";
		for (String node : nodes) {
			nodes_ += node + (",");
		}
		nodes_ = nodes_.substring(0, nodes_.length() - 1);

		String chain = "IDAtaque=" + idAtt + ";TipoAtaque=" + typeAtt + ";Nodos=" + nodes_ + ";Estado=" + state
				+ ";PEstado=" + pState + ";PFFinal=" + pFinal + ";Risk=" + risk;

		System.out.println(chain);
		try {

			DatagramSocket elSocket = new DatagramSocket();

			byte[] cadena = chain.getBytes();
			DatagramPacket mensaje = new DatagramPacket(cadena, chain.length(), InetAddress.getByName(IPDharma),
					socketOutPort);

			mensaje.setData(cadena);
			mensaje.setLength(chain.length());

			elSocket.send(mensaje);

			elSocket.close();

		} catch (SocketException e) {
			System.err.println("Socket: " + e.getMessage());
		} catch (IOException e) {
			System.err.println("E/S: " + e.getMessage());
		}
	}

	public static void sendToHMM(String typeAtt) {
		PrintWriter writer;
		try {
			writer = new PrintWriter(new BufferedWriter(new FileWriter(HMMinputroute, true)));
			String[] cve = CVEMAP.get(typeAtt).split("/");
			writer.println("CVE=" + cve[0] + ";Severity=" + cve[1] + ";Risk=" + cve[2]);
			writer.close();
		} catch (Exception ex) {
			System.err.println(ex);
		}

	}

	private static double rand(double min, double max) {
		double i = -1.0;
		while (min > i || i > max) {
			i = Math.random();
		}
		return Math.round(i * 100.0) / 100.0;
	}

}
