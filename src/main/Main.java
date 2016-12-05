package main;

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
	public final static String[] HMMTRAINED = { "a", "b" };
	public final static ArrayList<String> HMMTRAINEDLIST = new ArrayList<String>(Arrays.asList(HMMTRAINED));
	public final static String[] CVE = { ":2017-0001/medium", ":2012-0507/high", ":2017-0002/high", ":2017-0003/low",
			":2013-0264/high", ":2017-0005/high", ":2017-0001/medium", ":2017-0004/high", ":2017-0006/high",
			":2017-0007/high", ":2017-0008high", ":2017-0009/high", ":2017-0010/high", ":2017-0003/low",
			":2015-0235/high", ":2013-5211/high" };
	public static HashMap<String, String> CVEMAP = new HashMap<>();

	public static void main(String[] args) throws Exception {

		for (String item : CVE) {
			CVEMAP.put(item.split(":")[0], item.split(":")[1]);
		}

		maquina = InetAddress.getByName(args[0]);

		Logstash logstash = new Logstash(512, Main.maquina.getHostAddress());

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
		String event = log.substring(log.indexOf("\"signature\"") + 13);
		event = event.substring(0, event.indexOf(",") - 1);

		if (!HMMTRAINEDLIST.contains(event)) {
			sendToHMM(event);
		} else {

			switch (event) {
			case ("aaa"):
				String[] nodes1 = { "A1", "A2", "A3" };
				sendToDharma(99, "DDoS", nodes1, nodes1[0], 0.8, 0.34);
				break;
			case ("bbb"):
				String[] nodes2 = { "A1", "A2", "A3" };
				sendToDharma(99, "DDoS", nodes2, nodes2[0], 0.8, 0.34);
				break;

			default:
				System.err.println("Evento desconocido");
			}
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

			int puerto = 512;

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
			writer = new PrintWriter("./events.hmm", "UTF-8");
			String[] cve = CVEMAP.get(typeAtt).split("/");
			writer.println("CVE=" + cve[0] + ";Severity=" + cve[1]);
			writer.close();
			System.out.println("****  Generado fichero global.dharma  ****");
		} catch (Exception ex) {
			System.err.println(ex);
		}

	}

}
