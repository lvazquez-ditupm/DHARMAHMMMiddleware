package main;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.Scanner;

public class Main {

	private static Scanner reader;
	public static InetAddress maquina;

	public static void main(String[] args) throws Exception {

		maquina = InetAddress.getByName(args[0]);

		InfLoop infloop = new InfLoop();
		new Thread(infloop).start();

		while (true) {
			reader = new Scanner(System.in);
			System.out.print("Introduzca un evento: ");
			String event = reader.nextLine();
			System.out.println("");
			processEvent(event);
		}
	}

	private static void processEvent(String event) {
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

	public static synchronized void sendToDharma(int idAtt, String typeAtt, String[] nodes, String state, double pState,
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

}
