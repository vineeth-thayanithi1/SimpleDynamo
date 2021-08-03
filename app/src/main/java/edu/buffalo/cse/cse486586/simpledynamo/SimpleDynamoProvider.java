package edu.buffalo.cse.cse486586.simpledynamo;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.lang.reflect.Array;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Environment;
import android.provider.ContactsContract;
import android.telephony.TelephonyManager;
import android.util.Log;

import static android.content.ContentValues.TAG;

public class SimpleDynamoProvider extends ContentProvider {

	public static final int SERVER_PORT = 10000;
	static final int REMOTE_PORT0 = 11108;
	static final int REMOTE_PORT2 = 11116;
	static final int REMOTE_PORT1 = 11112;
	static final int REMOTE_PORT3 = 11120;
	static final int REMOTE_PORT4 = 11124;
	static int pred1;
	static int pred2;
	public static int connected=0;
	public static boolean done=false;
	public static TreeMap<String,int[]> port_map= new TreeMap<String, int[]>();
	public static String portStr;

	public static String[] columns = new String[]{"key","value"};
	public static  MatrixCursor result = new MatrixCursor(columns,1);

	@Override
	public int delete(Uri uri, String selection, String[] selectionArgs) {
		// TODO Auto-generated method stub
		int nodes=0;
		try {
			if (selection.compareTo("@") == 0) {
				String[] files = getContext().fileList();
				for (String k : files) {
					getContext().deleteFile(k);
				}

			}else{
				for (Map.Entry<String, int[]> e : port_map.entrySet()) {
					if (e.getKey().compareTo(genHash(selection))>0){
						for(int i: e.getValue()) {
							try {
								Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), i);
								socket0.setSoTimeout(500);

								DataOutputStream insertsend = new DataOutputStream(socket0.getOutputStream());
								insertsend.writeUTF("Delete:" + e.getValue()[0] + "," + selection);

								DataInputStream read = new DataInputStream(new BufferedInputStream(socket0.getInputStream()));
								String ack = read.readUTF();

								if (ack.compareTo("ACK") == 0) {
									insertsend.flush();
									insertsend.close();
									read.close();
									socket0.close();
								}
							}catch (Exception e1){
								continue;
							}
						}
						break;
					}else
						nodes++;
					if(nodes==5){
						for(int i: port_map.firstEntry().getValue()){
							try {
								Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), i);
								socket0.setSoTimeout(500);

								DataOutputStream insertsend = new DataOutputStream(socket0.getOutputStream());
								insertsend.writeUTF("Delete:" + port_map.firstEntry().getValue()[0] + "," + selection);

								DataInputStream read = new DataInputStream(new BufferedInputStream(socket0.getInputStream()));
								String ack = read.readUTF();

								if (ack.compareTo("ACK") == 0) {
									insertsend.flush();
									insertsend.close();
									read.close();
									socket0.close();
								}
							}catch (Exception e1){
								continue;
							}
						}
						break;
					}
				}

			}
		}catch (Exception e){
			Log.e("Delete Exception",e.toString());
		}
		return 0;
	}

	@Override
	public String getType(Uri uri) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Uri insert(Uri uri, ContentValues values) {
		// TODO Auto-generated method stub
		int nodes=0;
		try {
			for (Map.Entry<String, int[]> e : port_map.entrySet()) {
				if (e.getKey().compareTo(genHash(values.getAsString("key")))>0){
					for(int i: e.getValue()) {
						try {
							Log.e("TO BE INSERTED", genHash(values.getAsString("key"))+"*************"+i+"********"+ genHash(Integer.toString(i/2)));
							Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), i);
							socket0.setSoTimeout(500);


							DataOutputStream insertsend = new DataOutputStream(socket0.getOutputStream());
							insertsend.writeUTF("Insert:"+ e.getValue()[0]+"_"+ values.getAsString("key") + "," + values.getAsString("value"));

							DataInputStream read = new DataInputStream(new BufferedInputStream(socket0.getInputStream()));
							String ack = read.readUTF();

							if (ack.compareTo("ACK") == 0) {
								insertsend.flush();
								insertsend.close();
								read.close();
								socket0.close();
							}
						}
						catch (Exception e1){
							Log.e("INside Insert","Timeout"+values.getAsString("value"));
							continue;
						}
					}
					break;
				}else
					nodes++;
				if(nodes==5){
					for(int i: port_map.firstEntry().getValue()){
						try {
							Log.e("TO BE INSERTED", genHash(values.getAsString("key"))+"*************"+i+"********"+ genHash(Integer.toString(i/2)));
							Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), i);
							socket0.setSoTimeout(500);


							DataOutputStream insertsend = new DataOutputStream(socket0.getOutputStream());
							insertsend.writeUTF("Insert:"+ port_map.firstEntry().getValue()[0]+"_"+ values.getAsString("key") + "," + values.getAsString("value"));

							DataInputStream read = new DataInputStream(new BufferedInputStream(socket0.getInputStream()));
							String ack = read.readUTF();

							if (ack.compareTo("ACK") == 0) {
								insertsend.flush();
								insertsend.close();
								read.close();
								socket0.close();
							}
						}catch (Exception e1){
							Log.e("INside Insert","Timeout"+values.getAsString("value"));
							continue;
					}
					}
					break;
				}
			}
		}catch (Exception e){

			Log.e(TAG,e.toString());

		}

		return null;
	}

	@Override
	public boolean onCreate() {
		// TODO Auto-generated method stub
		try{

			TelephonyManager tel =
					(TelephonyManager)getContext().getSystemService (Context.TELEPHONY_SERVICE);
			portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);

			port_map.put(genHash(Integer.toString(REMOTE_PORT0/2)), new int[] {REMOTE_PORT0,REMOTE_PORT2,REMOTE_PORT3});
			port_map.put(genHash(Integer.toString(REMOTE_PORT1/2)), new int[] {REMOTE_PORT1,REMOTE_PORT0,REMOTE_PORT2});
			port_map.put(genHash(Integer.toString(REMOTE_PORT2/2)), new int[] {REMOTE_PORT2,REMOTE_PORT3,REMOTE_PORT4});
			port_map.put(genHash(Integer.toString(REMOTE_PORT3/2)), new int[] {REMOTE_PORT3,REMOTE_PORT4,REMOTE_PORT1});
			port_map.put(genHash(Integer.toString(REMOTE_PORT4/2)), new int[] {REMOTE_PORT4,REMOTE_PORT1,REMOTE_PORT0});

			switch (Integer.parseInt(portStr)){

				case 5554:
					pred1=REMOTE_PORT1;
					pred2=REMOTE_PORT4;
					break;

				case 5556:
					pred1=REMOTE_PORT4;
					pred2=REMOTE_PORT3;
					break;

				case 5558:
					pred1= REMOTE_PORT0;
					pred2 = REMOTE_PORT1;
					break;

				case 5560:
					pred1=REMOTE_PORT2;
					pred2=REMOTE_PORT0;
					break;

				case 5562:
					pred1=REMOTE_PORT3;
					pred2=REMOTE_PORT2;
					break;

			}

			ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
			new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);

			new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, portStr);



		}catch (Exception e)
		{
			Log.e(TAG,e.toString());
		}
		return false;
	}

	private class ClientTask extends AsyncTask<String, Void, Void> {

		public void recover_mine(){
			StringBuilder read= new StringBuilder();
			try {

				for (Map.Entry<String, int[]> e : port_map.entrySet()) {
					if (e.getKey().compareTo(genHash(portStr)) == 0) {
						for (int i : e.getValue()) {
							if (i != Integer.parseInt(portStr) * 2) {
								Log.e(TAG,"RECOVER SEND TO******"+ Integer.toString(i));
								Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), i);
								socket0.setSoTimeout(500);

								DataOutputStream querysend = new DataOutputStream(socket0.getOutputStream());
								querysend.writeUTF("Recover:" + Integer.parseInt(portStr)*2);

								DataInputStream readall = new DataInputStream(new BufferedInputStream(socket0.getInputStream()));
								read.append(readall.readUTF());

								if (read.toString().split(":")[1].compareTo("empty") == 0) {
									querysend.close();
									readall.close();
									socket0.close();
								} else {

									File root = new File(getContext().getFilesDir(),Integer.toString(Integer.parseInt(portStr)*2));
									if (!root.exists()) {
										root.mkdirs();
									}

									read.deleteCharAt(read.length() - 1);
									String kv = read.toString().split(":")[1];
									read.setLength(0);
									String[] key_val = kv.split(",");
									for (String dum : key_val) {
										String key = dum.split("_")[0];
										String value = dum.split("_")[1];
										File file = new File(root, key);
										FileWriter writer = new FileWriter(file);
										writer.write(value);
										writer.flush();
										writer.close();
										Log.e("Recovered", key + "*****" + value);
									}
								}
							}
						}
					}
				}
			}catch (Exception e){
				Log.e(TAG,"EXCEPTION RECEIVE"+e);

			}
		}

		public void recover_peers(int port ){

			StringBuilder read= new StringBuilder();
			try {

				Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), port);
				socket0.setSoTimeout(500);

				DataOutputStream querysend = new DataOutputStream(socket0.getOutputStream());
				querysend.writeUTF("Recover:" + port);

				DataInputStream readall = new DataInputStream(new BufferedInputStream(socket0.getInputStream()));
				read.append(readall.readUTF());

				if (read.toString().split(":")[1].compareTo("empty") == 0) {
					querysend.close();
					readall.close();
					socket0.close();
				} else {

					File root = new File(getContext().getFilesDir(), Integer.toString(port));
					if (!root.exists()) {
						root.mkdirs();
					}

					read.deleteCharAt(read.length() - 1);
					String kv = read.toString().split(":")[1];
					read.setLength(0);
					String[] key_val = kv.split(",");
					for (String dum : key_val) {
						String key = dum.split("_")[0];
						String value = dum.split("_")[1];
						File file = new File(root, key);
						FileWriter writer = new FileWriter(file);
						writer.write(value);
						writer.flush();
						writer.close();
						Log.e("Recovered", key + "*****" + value);
					}
				}

			}catch (Exception e){


			}

			return ;


		}

		@Override
		protected Void doInBackground(String... msgs) {

			try {
				recover_mine();
				recover_peers(pred1);
				recover_peers(pred2);
			}
			catch (Exception e)
			{
				Log.e(TAG,"Error in client Task"+e);
			}

			return null;
		}

	}


	@Override
	public Cursor query(Uri uri, String[] projection, String selection,
			String[] selectionArgs, String sortOrder) {
		// TODO Auto-generated method stub
		synchronized (this) {
			int i = 0;
			int nodes = 0;
			result = new MatrixCursor(columns, 1);
			char msg;
			StringBuilder sb = new StringBuilder();
			Object[] res = new Object[2];
			String inp;
			try {
				if (selection.compareTo("@") == 0) {
					String[] files = getContext().fileList();
					for (String k : files) {
						File directory = new File(getContext().getFilesDir().toString() + "/" + k);
						for (File f : directory.listFiles()) {
							FileInputStream inputStream = new FileInputStream(f);
							while ((i = inputStream.read()) != -1) {
								msg = ((char) i);
								sb.append(msg);
							}
							res[0] = f.getName();
							res[1] = sb.toString();
							sb.setLength(0);
							result.addRow(res);
						}
					}
				} else if (selection.compareTo("*") == 0) {
					StringBuilder allavd = new StringBuilder();
					for (Map.Entry<String, int[]> e : port_map.entrySet()) {
						for(int i1:e.getValue()) {
							try {
								Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), i1);
								socket0.setSoTimeout(500);

								DataOutputStream querysend = new DataOutputStream(socket0.getOutputStream());
								querysend.writeUTF("QueryAll:" + portStr + ",@");

								DataInputStream recieve_all = new DataInputStream(new BufferedInputStream(socket0.getInputStream()));
								String curr_avd = recieve_all.readUTF();

								if (curr_avd.matches("RETURNALL:.*")) {
									allavd.append(curr_avd.split(":")[1]);
									querysend.flush();
									querysend.close();
									recieve_all.close();
									socket0.close();
								}
							}catch (Exception e1){
								continue;
							}
						}

					}
					allavd.deleteCharAt(allavd.length() - 1);
					String[] key_val = allavd.toString().split(",");
					for (String dum : key_val) {
						res[0] = dum.split("_")[0];
						res[1] = dum.split("_")[1];
						result.addRow(res);
					}
					Log.e("Query All", allavd.toString());

				} else {
					for (Map.Entry<String, int[]> e : port_map.entrySet()) {
						if (e.getKey().compareTo(genHash(selection)) > 0) {
							for (int port : e.getValue()) {
								try {
									Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), port);
									socket0.setSoTimeout(500);

									DataOutputStream querysend = new DataOutputStream(socket0.getOutputStream());
									querysend.writeUTF("Query:" + e.getValue()[0] + "," + selection);

									DataInputStream read = new DataInputStream(new BufferedInputStream(socket0.getInputStream()));
									inp = read.readUTF();

									Log.e("QUERY RESULT", inp);

									res[0] = inp.split(":")[0];
									res[1] = inp.split(":")[1];
									result.addRow(res);

									if (inp.matches(selection + ":.*")) {
										querysend.flush();
										querysend.close();
										read.close();
										socket0.close();
									}
								}catch (Exception e1){
									continue;
								}
							}
							break;
						} else
							nodes++;
						if (nodes == 5) {
							for (int port : port_map.firstEntry().getValue()) {
								try {
									Socket socket0 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), port);
									socket0.setSoTimeout(500);

									DataOutputStream querysend = new DataOutputStream(socket0.getOutputStream());
									querysend.writeUTF("Query:" + port_map.firstEntry().getValue()[0] + "," + selection);

									DataInputStream read = new DataInputStream(new BufferedInputStream(socket0.getInputStream()));
									inp = read.readUTF();

									Log.e("QUERY RESULT", inp);

									res[0] = inp.split(":")[0];
									res[1] = inp.split(":")[1];
									result.addRow(res);

									if (inp.matches(selection + ":")) {
										querysend.flush();
										querysend.close();
										read.close();
										socket0.close();
									}
								}catch (Exception e1 ){
									continue;
								}
							}
							break;
						}
					}
				}

			} catch (Exception e) {
				Log.e("QUERY", e.toString());
			}

			return result;
		}
	}

	@Override
	public int update(Uri uri, ContentValues values, String selection,
			String[] selectionArgs) {
		// TODO Auto-generated method stub
		return 0;
	}

	private class ServerTask extends AsyncTask<ServerSocket, String, Void>{

		public void decideinsert(String msg){

			String directory = msg.split("_")[0];
			String key_val= msg.split("_")[1];

			try {
				File root = new File(getContext().getFilesDir(), directory);
				if (!root.exists()) {
					root.mkdirs();
				}

				String key= key_val.split(",")[0];
				String value= key_val.split(",")[1];
				String keyhash = genHash(key);

				File file = new File(root, key);
				FileWriter writer = new FileWriter(file);

				writer.write(value);
				writer.flush();
				writer.close();

				Log.d("OutputFILe", key);
				Log.e(TAG, "Inserted******"+ keyhash);
				Log.d("Hey", "File Written");

			}
			catch (Exception e)
			{
				Log.d("exception",e.toString());
			}
		}

		public String queryall(String msg){
			int i;
			StringBuilder temp =new StringBuilder();
			StringBuilder sb = new StringBuilder();
			char c;
			try {
				String[] files = getContext().fileList();
				for (String k : files) {
					File directory = new File(getContext().getFilesDir().toString() + "/" + k);
					for (File f : directory.listFiles()) {
						FileInputStream inputStream = new FileInputStream(f);
						while ((i = inputStream.read()) != -1) {
							c = ((char) i);
							sb.append(c);
						}
						temp.append(f.getName() + "_" + sb.toString() + ",");
						sb.setLength(0);
					}
				}
			}catch (Exception e ){

				Log.e(TAG, e.toString());

			}
			return temp.toString();

		}

		public String recover(int port){
			int i;
			StringBuilder temp =new StringBuilder();
			StringBuilder sb = new StringBuilder();
			char c;
			try {
				String[] folders = getContext().fileList();
				if(folders.length>0) {
					File path = new File(getContext().getFilesDir().toString() + "/" + port);
					if(path.exists()){
						if(path.listFiles().length>0){
							File[] files= path.listFiles();
							for(File f: files){
								FileInputStream inputStream = new FileInputStream(f);
								while ((i = inputStream.read()) != -1) {
									c = ((char) i);
									sb.append(c);
								}
								temp.append(f.getName() + "_" + sb.toString() + ",");
								sb.setLength(0);
							}

						}else
							return "empty";
					}else{
						return "empty";
					}


				}else{
					return "empty";
				}
			}catch (Exception e ){

				Log.e(TAG, e.toString());

			}
			return temp.toString();

		}


		public String findquery(String msg){

			String directory = msg.split(",")[0];
			int i=0;
			char dum;
			String key=msg.split(",")[1];
			StringBuilder sb = new StringBuilder();


			File path = new File(getContext().getFilesDir().toString() + "/" + directory);


			try {
				//FileInputStream inputStream = getContext().openFileInput(key);
				File file = new File(path,key);

				BufferedReader br = new BufferedReader(new FileReader(file));
				while ((i = br.read()) != -1) {
					dum = ((char) i);
					sb.append(dum);
				}
			}
			catch (Exception e)
			{
				Log.d("exception",e.toString());
			}
			return key+":"+sb.toString();
		}


		@Override
		protected Void doInBackground(ServerSocket... sockets) {
			ServerSocket serverSocket = sockets[0];
			Socket socket;
			Log.e(TAG,"Server started");

			synchronized (this) {
				while (true) {
					try
					{
						socket = serverSocket.accept();// Connection Accepted
						socket.setSoTimeout(500);

						DataInputStream inputStream = new DataInputStream(new BufferedInputStream(socket.getInputStream()));

						String clientMsg=inputStream.readUTF();
						Log.e(TAG, clientMsg);

						//Insert Msg
						if(clientMsg.matches("Insert:.*")){
							DataOutputStream sendack = new DataOutputStream(socket.getOutputStream());
							sendack.writeUTF("ACK");
							sendack.close();
							socket.close();
							decideinsert(clientMsg.split(":")[1]);
						}

						//* Query Request
						if(clientMsg.matches("QueryAll:.*")){
							DataOutputStream sendack = new DataOutputStream(socket.getOutputStream());
							String value= queryall(clientMsg.split(":")[1]);
							Log.e("Query Res",value);
							sendack.writeUTF("RETURNALL:"+value);
							sendack.close();
							socket.close();
						}

						//Query Request
						if(clientMsg.matches("Query:.*")){
							DataOutputStream sendack = new DataOutputStream(socket.getOutputStream());
							String value= findquery(clientMsg.split(":")[1]);
							Log.e("Query Res",value);
							sendack.writeUTF(value);
							sendack.close();
							socket.close();
						}

						//Delete Request
						if(clientMsg.matches("Delete:.*")){
							DataOutputStream sendack = new DataOutputStream(socket.getOutputStream());
							File path = new File(getContext().getFilesDir().toString() + "/" + clientMsg.split(":")[1].split(",")[0]);
							File file = new File(path,clientMsg.split(":")[1].split(",")[1]);
							file.delete();
							//getContext().deleteFile(clientMsg.split(":")[1]);
							sendack.writeUTF("ACK");
							sendack.close();
							socket.close();
						}

						//Recover Message
						if(clientMsg.matches("Recover:.*")){
							DataOutputStream sendfiles = new DataOutputStream((socket.getOutputStream()));
							String value= recover(Integer.parseInt(clientMsg.split(":")[1]));
							sendfiles.writeUTF("Recover:"+value);
							sendfiles.flush();
							sendfiles.close();
							socket.close();

						}


					}catch (Exception e){
						Log.e(TAG,"Exception in server task"+e );
						continue;
					}
				}
			}
		}


		protected void onProgressUpdate(String...strings) {

			return;
		}
	}




    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }
}
