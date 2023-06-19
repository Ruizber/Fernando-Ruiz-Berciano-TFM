import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.json.JSONObject;

/**
 * This class is used to do some operations with the files in this TFM.
 * 
 * @author Fernando Ruiz Berciano
 *
 */
public class FileManager {

	/**
	 * This method is used to read all the files with the different regular
	 * expressions used. After that it stores them in a list.
	 * 
	 * @return List<String> with the regular expressions.
	 */
	public List<String> fileReaderArchive() {
		File carpeta = new File("C:\\Files-TFM\\Strings\\Regex");
		List<String> regexList = new ArrayList<>();
		for (File ficheroEntrada : carpeta.listFiles()) {
			int idRegExp = getNumberRegex(ficheroEntrada.getName());
			try {
				try (BufferedReader br = new BufferedReader(new FileReader(ficheroEntrada))) {
					String line;
					while ((line = br.readLine()) != null) {
						regexList.add(line + String.valueOf(idRegExp));
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return regexList;
	}

	/**
	 * This Method is used to read the Magic Numbers Archive
	 * 
	 * @return
	 */
	public HashMap<String, String> fileReaderArchiveMagicNumbers() {
		File file = new File("C:\\Files-TFM\\MagicNumbers\\MagicNumbers.txt");
		HashMap<String, String> magicNumbers = new HashMap<>();
		try {
			try (BufferedReader br = new BufferedReader(new FileReader(file))) {
				String line;
				while ((line = br.readLine()) != null) {
					String[] stringParts = line.split("-");
					magicNumbers.put(stringParts[0], stringParts[1]);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return magicNumbers;
	}

	/**
	 * This method is used to get the id of the regular expression.
	 * 
	 * @param String nameFile
	 * @return an id to know the type of the regular expression.
	 */
	private int getNumberRegex(String nameFile) {
		switch (nameFile) {
		case "email.txt":
			return 1;
		case "error.txt":
			return 2;
		case "ip.txt":
			return 3;
		case "url.txt":
			return 4;
		case "kernel32.txt":
			return 5;
		case "dns.txt":
			return 6;
		case "date.txt":
			return 7;
		case "image.txt":
			return 8;
		case "directories.txt":
			return 9;
		case "exe.txt":
			return 0;
		}
		return 10;
	}

	/**
	 * This method is used to write a file in Json format with the different string
	 * values of the data obtained in the program.
	 * 
	 * @param stringsValues
	 */
	public void fileWriterArchive(HashMap<String, String> stringsValues, String programName) {
		FileWriter fichero = null;
		try {
			Date date = new Date();
			String dateString = new SimpleDateFormat("dd-MM-yyyy").format(date);
			fichero = new FileWriter("C:\\Files-TFM\\Strings\\Output\\" + programName + "_StringsOutput_" + dateString + ".json");
			fichero.write("[\n");
			int counter = 0;
			for (String clave : stringsValues.keySet()) {
				String stringValue = stringsValues.get(clave);
				String id = stringValue.substring(stringValue.length() - 1);
				String lineaSimple = stringValue.substring(0, stringValue.length() - 1);
				JSONObject myJsonString = new JSONObject();
				JSONObject myJsonAddress = new JSONObject();
				myJsonString.put(getJsonLabel(id), lineaSimple.replace("\"", ""));
				myJsonAddress.put("hex-address", clave);
				counter++;
				if (counter != stringsValues.size()) {
					fichero.write("\t" + myJsonString.toString() + ",\n");
					fichero.write("\t\t" + myJsonAddress.toString() + ",\n");
				} else {
					fichero.write("\t" + myJsonString.toString() + ",\n");
					fichero.write("\t\t" + myJsonAddress.toString() + "\n");
				}
			}
			fichero.write("]");
			fichero.close();
		} catch (Exception ex) {
			System.out.println("Mensaje de la excepción: " + ex.getMessage());
		}
	}

	/**
	 * This method is used to get the type of data using the id.
	 * 
	 * @param String id
	 * @return String with the type of regular expression.
	 */
	private String getJsonLabel(String id) {
		switch (id) {
		case "1":
			return "email";
		case "2":
			return "error";
		case "3":
			return "ip";
		case "4":
			return "url";
		case "5":
			return "kernel32";
		case "6":
			return "dns";
		case "7":
			return "date";
		case "8":
			return "image";
		case "9":
			return "directory";
		case "0":
			return "exe";
		}
		return "10";
	}

	/**
	 * This function is used to write the type of the archive obtained by the magic
	 * numbers.
	 * 
	 * @param String type of archive
	 */
	public void getTypeArchive(String typeArchive, String programName) {
		FileWriter fichero = null;
		try {
			Date date = new Date();
			String dateString = new SimpleDateFormat("dd-MM-yyyy").format(date);
			fichero = new FileWriter(
					"C:\\Files-TFM\\MagicNumbers\\Output\\" + programName + "_TypeArchive_" + dateString + ".txt");
			fichero.write(typeArchive);
			fichero.close();
		} catch (Exception ex) {
			System.out.println("Mensaje de la excepción: " + ex.getMessage());
		}
	}
	
	/**
	 * This method is used to read the language options from the archive.
	 * 
	 * @return HashMap with the languages.
	 */
	public HashMap<String, String> fileReadLanguage() {
		File file = new File("C:\\Files-TFM\\Strings\\Language\\Language.txt");
		HashMap<String, String> language = new HashMap<>();
		try {
			try (BufferedReader br = new BufferedReader(new FileReader(file))) {
				String line;
				while ((line = br.readLine()) != null) {
					String[] stringParts = line.split("-");
					language.put(stringParts[0], stringParts[1]);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return language;
	}
}
