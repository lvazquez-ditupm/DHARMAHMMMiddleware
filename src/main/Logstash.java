package main;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

public class Logstash implements Runnable {

	private DatagramSocket socketUDP;
	public static String fname;
	public static Object lck = new Object();
	boolean received_alert = false;
	String log_received;

	public Logstash(int UDPport, String ip) {
		try {
			socketUDP = new DatagramSocket(UDPport, InetAddress.getByName(ip));
		} catch (UnknownHostException | SocketException e) {
			System.err.println("Imposible obtener acceso al socket UDP. Terminando sistema...");
			System.exit(0);
		}
	}

	public void run() {

		String log;

		while (true) {

			log = "";

			try {
				byte[] buf = new byte[4096];
				while (true) {
					DatagramPacket packet = new DatagramPacket(buf, buf.length);
					socketUDP.receive(packet);
					log = new String(packet.getData(), packet.getOffset(), packet.getLength());

					if (!log.equals("")) {
						break;
					}
				}
			} catch (Exception e) {
			}
			
			Main.processEvent(log);

		}
	}
}
