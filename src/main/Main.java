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
	public final static String[] HMMTRAINED = { "GPL POP3 POP3 PASS overflow attempt", "GPL SHELLCODE x86 incebx NOOP",
			"ET DOS Inbound Low Orbit Ion Cannon LOIC DDOS Tool desu String" };
	public final static ArrayList<String> HMMTRAINEDLIST = new ArrayList<String>(Arrays.asList(HMMTRAINED));
	public final static String[] CVE = { "ET WEB_CLIENT Possible BeEF Module in use:2017-0001/medium",
			"ET INFO JAVA - ClassID:2012-0507/high", "ET INFO Java .jar request to dotted-quad domain:2012-0507/high",
			"ET INFO JAVA - Java Archive Download:2012-0507/high",
			"ET INFO Java .jar request to dotted-quad domain:2012-0507/high", "Information Leak:2017-0002/high",
			"Nmap scan:2017-0003/low", "GPL POP3 POP3 PASS overflow attempt:2013-0264/high",
			"GPL SHELLCODE x86 incebx NOOP:2013-0264/high", "SYSTEM Actions:2017-0005/high",
			"HTTP Reverse Shell:2017-0004/high", "BypassUAC:2017-0006/high", "Access Admin node:2017-0009/high",
			"Persistence:2017-0010/high",
			// "GPL POP3 POP3 PASS overflow attempt:2015-0235/high",
			"ET DOS Inbound Low Orbit Ion Cannon LOIC DDOS Tool desu String:2013-5211/high" };

	public static HashMap<String, String> CVEMAP = new HashMap<>();

	public static void main(String[] args) throws Exception {

		for (String item : CVE) {
			CVEMAP.put(item.split(":")[0], item.split(":")[1]);
		}

		maquina = InetAddress.getByName("127.0.0.1");

		Logstash logstash = new Logstash(5000, Main.maquina.getHostAddress());

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
		if (event.contains("ET WEB_CLIENT Possible BeEF Module in use")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Filtracion" };
			sendToDharma(99, "BeEF", nodes, nodes[0], rand(0.35, 0.55), 0.33);
			String[] nodes2 = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes2, nodes2[0], rand(0.15, 0.40), 0.14);

		} else if (event.contains("ET INFO JAVA - ClassID")
				|| event.contains("ET INFO Java .jar request to dotted-quad domain")
				|| event.contains("ET INFO JAVA - Java Archive Download")
				|| event.contains("ET INFO Java .jar request to dotted-quad domain")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Filtracion" };
			sendToDharma(99, "BeEF", nodes, nodes[1], rand(0.5, 0.65), 0.67);

		} else if (event.contains("Information Leak")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Filtracion" };
			sendToDharma(99, "BeEF", nodes, nodes[2], rand(0.7, 0.95), 1);
			String[] nodes2 = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes2, nodes2[3], rand(0.5, 0.7), 0.57);

		} else if (event.contains("Nmap scan")) {
			String[] nodes = { "Intento de intrusion", "Buffer Overflow", "Sudo", "Acciones SYSTEM" };
			sendToDharma(98, "Control de sistema mediante Buffer Overflow", nodes, nodes[0], rand(0.1, 0.4), 0.25);

		} else if (event.contains("GPL POP3 POP3 PASS overflow attempt")
				|| event.contains("GPL SHELLCODE x86 incebx NOOP")) {
			String[] nodes = { "Intento de intrusion", "Buffer Overflow", "Sudo", "Acciones SYSTEM" };
			sendToDharma(98, "Control de sistema mediante Buffer Overflow", nodes, nodes[2], rand(0.6, 0.9), 0.75);

		} else if (event.contains("SYSTEM Actions")) {
			String[] nodes = { "Intento de intrusion", "Buffer Overflow", "Sudo", "Acciones SYSTEM" };
			sendToDharma(98, "Control de sistema mediante Buffer Overflow", nodes, nodes[3], rand(0.75, 1.0), 1.0);

		} else if (event.contains("HTTP Reverse Shell")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes, nodes[1], rand(0.25, 0.45), 0.28);

		} else if (event.contains("BypassUAC")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes, nodes[2], rand(0.4, 0.6), 0.42);

		} else if (event.contains("Access Admin node")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes, nodes[4], rand(0.7, 0.9), 0.85);

		} else if (event.contains("Persistence")) {
			String[] nodes = { "BeEF", "Reverse Shell", "Sudo", "Filtracion", "Acceso Servidor", "Persistencia" };
			sendToDharma(97, "APT", nodes, nodes[5], rand(0.8, 1.0), 1.0);

		} else if (event.contains("LOIC")) {
		} else {
			System.err.println("Evento desconocido");
		}
	}

	public static void sendToDharma(int idAtt, String typeAtt, String[] nodes, String state, double pState,
			double pFinal) {

		String nodes_ = "(";
		for (String node : nodes) {
			nodes_ += node + (",");
		}
		nodes_ = nodes_.substring(0, nodes_.length() - 1);
		nodes_ += ")";

		String chain = "HMM: IDAtaque=" + idAtt + ";TipoAtaque=" + typeAtt + ";Nodos=" + nodes_ + ";Estado=" + state
				+ ";PEstado=" + pState + ";PFFinal=" + pFinal;

		try {

			DatagramSocket elSocket = new DatagramSocket();

			int puerto = 6000;

			byte[] cadena = chain.getBytes();
			DatagramPacket mensaje = new DatagramPacket(cadena, chain.length(), maquina, puerto);

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
			writer = new PrintWriter(new BufferedWriter(new FileWriter("./events.hmm", true)));
							
			String[] cve = CVEMAP.get(typeAtt).split("/");
			writer.println("CVE=" + cve[0] + ";Severity=" + cve[1]);
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
