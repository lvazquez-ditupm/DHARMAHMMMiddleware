package main;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class Main {
	private static String alert;
	private final static String[] HMMTRAINED = { "a", "b" };
	private final static ArrayList<String> HMMTRAINEDLIST = new ArrayList<String>(Arrays.asList(HMMTRAINED));
	private final static String[] CVE = { "a-cvea", "b-cveb" };
	private static HashMap<String, String> CVEMAP = new HashMap<>();

	public static void main(String[] args) {

		alert = "";
		for (String item : CVE) {
			CVEMAP.put(item.split("-")[0], item.split("-")[1]);
		}

		while (true) {
			alert = Hadoop.readNewAlert(alert);

			if (isTrained(alert)) {
				sendToHMM(alert);
			} else {
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

	private static void sendToDHARMA(String alert) {
		// TODO Auto-generated method stub

	}

	private static void sendToHMM(String alert) {
		String cve = CVEMAP.get(alert);
		
	}

}
