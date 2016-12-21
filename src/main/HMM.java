package main;

import java.io.IOException;

public class HMM implements Runnable {

	private String cmd;

	public HMM(String cmd) {
		this.cmd = cmd;
	}

	@Override
	public void run() {

		try {
			Runtime.getRuntime().exec(cmd);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
