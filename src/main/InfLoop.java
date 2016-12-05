package main;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class InfLoop implements Runnable {

	private static String alert = "";
	private final static String[] HMMTRAINED = { "a", "b" };
	private final static ArrayList<String> HMMTRAINEDLIST = new ArrayList<String>(Arrays.asList(HMMTRAINED));
	private final static String[] CVE = { "a-cvea", "b-cveb" };
	private static HashMap<String, String> CVEMAP = new HashMap<>();

	@Override
	public void run() {
		
		for (String item : CVE) {
			CVEMAP.put(item.split("-")[0], item.split("-")[1]);
		}
		
		while (true) {
									
			alert = Hadoop.readNewAlert(alert);
			
			if (isTrained(alert)) {
				sendToHMM(alert);
			} else if (alert!=null) {
				sendToDHARMA(alert);
			}
		}
	}

	private static boolean isTrained(String alert) {

		if (HMMTRAINEDLIST.contains(alert)) {
			return true;
		} else {
			return false;
		}
	}

	private static void sendToDHARMA(String chain) {
		try {

			DatagramSocket elSocket = new DatagramSocket();

			int puerto = 512;

			byte[] cadena = chain.getBytes();
			DatagramPacket mensaje = new DatagramPacket(cadena, chain.length(), Main.maquina, puerto);

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

	private static void sendToHMM(String alert) {
		String cve = CVEMAP.get(alert);

	}

}
