//
//@author Fernando Ruiz
//@category APT Analyzer
//@keybinding
//@menupath
//@toolbar

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * This is the main class of the program. In this class all the method related
 * with Ghidra are created.
 * 
 * @author Fernando Ruiz Berciano
 *
 */
public class AnalyzeAPT extends GhidraScript {

	/**
	 * This attribute is used to have an instance of the FileManager class.
	 */
	private FileManager fileManager = new FileManager();

	/**
	 * This attribute is used to have an instance of the MainSearcher class.
	 */
	private MainSearcher mainSearcher = new MainSearcher();

	/**
	 * This attribute is used to store a HashMap with the string values obtained
	 * with the regular expressions.
	 */
	private HashMap<String, String> stringsValues = new HashMap<>();

	/**
	 * This is the main method and it gets all the values and magic numbers using
	 * Ghidra.
	 */
	@Override
	public void run() throws Exception {
		String programName = currentProgram.getName();
		println("Running program in file: " + programName);
		askInterface();
	}

	/**
	 * This method is used to ask the user if he wants to use the interface or the
	 * command line. And if the user wants to check virus total.
	 * 
	 * @param allData
	 * 
	 * @return String response
	 * @throws Exception
	 */
	public void askInterface() throws Exception {
		int counter = 0;
		String useCommand = "repeat";
		while (useCommand.equals("repeat")) {
			String response = askString("Opciones a buscar ",
					"Type 'S' to get the values of tge Strings, 'M' for the magic number, 'F' for the MainFunction, 'A' to get all the values or type 'exit' to finish the program: ");
			if (counter != 0) {
				println("Enter a valid value ");
			}
			counter = 0;
			if (response.equals("S") || response.equals("s")) {
				getStringValues();
				getLanguageOfArchive();
				useCommand = "Complete";
			} else if (response.equals("M") || response.equals("m")) {
				getMagicNumbers();
				getLanguageOfArchive();
				useCommand = "Complete";
			} else if (response.equals("F") || response.equals("f")) {
				getMainFunction();
				getLanguageOfArchive();
				useCommand = "Complete";
			} else if (response.equals("A") || response.equals("a")) {
				getStringValues();
				getMagicNumbers();
				getMainFunction();
				getLanguageOfArchive();
				useCommand = "Complete";
			} else if (response.equals("Exit") || response.equals("EXIT") || response.equals("exit")) {
				useCommand = "finish";
			} else {
				useCommand = "repeat";
				counter++;
			}
		}
		if (useCommand.equals("finish")) {
			popup("Execution has been finished");
		}
		if (!useCommand.equals("finish")) {
			String virusTotal = askString("Virus Total", "Type 'Y' to scan the file in VirusTotal, 'N' not to scan: ");
			while (!virusTotal.equals("Y") && !virusTotal.equals("y") && !virusTotal.equals("N")
					&& !virusTotal.equals("n")) {
				println("Enter a valid value ");
				virusTotal = askString("Virus Total", "Type 'Y' to scan the file in VirusTotal, 'N' not to scan: ");
			}
			if (virusTotal.equals("n") || virusTotal.equals("N")) {
				popup("Execution has been completed correctly");
			} else if (virusTotal.equals("Y") || virusTotal.equals("y")) {
				getHashArchive();
			}
		}
	}

	/**
	 * This method is used to get the String values of the archive.
	 * 
	 */
	private void getStringValues() {
		List<String> regex = new ArrayList<>();
		regex = fileManager.fileReaderArchive();
		Listing listing = currentProgram.getListing();

		DataIterator dataIt;
		if (currentSelection != null) {
			dataIt = listing.getDefinedData(currentSelection, true);
		} else {
			dataIt = listing.getDefinedData(true);
		}

		Data data;
		String type;
		int counter = 0;
		String programName = currentProgram.getName();
		String[] stringParts = programName.split("\\.");
		while (dataIt.hasNext() && !monitor.isCancelled()) {
			data = dataIt.next();
			type = data.getDataType().getName().toLowerCase();
			if (type.contains("unicode") || type.contains("string")) {
				String s = data.getDefaultValueRepresentation().toLowerCase();
				for (String stringRegex : regex) {
					String idRegExp = stringRegex.substring(stringRegex.length() - 1);
					String stringRegexSimple = stringRegex.substring(0, stringRegex.length() - 1);
					if (s.matches(stringRegexSimple)) {
						if (s.contains("update") && idRegExp.equals("7")) {
							idRegExp = "2";
						}
						String address = data.getAddress().toString();
						stringsValues.put(address, s + idRegExp);
						counter++;
					}
				}
			}

		}
		println("A total of " + counter + " Strings have been found.");
		fileManager.fileWriterArchive(stringsValues, stringParts[0]);
	}

	/**
	 * This method is used to get the main function in the program.
	 */
	private void getMainFunction() {
		String mainString = "";
		boolean mainIsFind = false;
		String programName = currentProgram.getName();
		String[] stringParts = programName.split("\\.");
		List<Function> main = currentProgram.getListing().getGlobalFunctions("");
		if (currentProgram.getListing().getGlobalFunctions("ServiceMain") != null
				|| currentProgram.getListing().getGlobalFunctions("Main") != null
				|| currentProgram.getListing().getGlobalFunctions("serviceMain") != null
				|| currentProgram.getListing().getGlobalFunctions("main") != null) {
			if (currentProgram.getListing().getGlobalFunctions("ServiceMain") != null) {
				main = currentProgram.getListing().getGlobalFunctions("ServiceMain");
			} else if (currentProgram.getListing().getGlobalFunctions("Main") != null) {
				main = currentProgram.getListing().getGlobalFunctions("Main");
			}
			for (Function f : main) {
				String signature = f.getSignature().toString();
				String name = f.getName();
				String addr = f.getBody().getMinAddress().toString();
				String end = f.getBody().getMaxAddress().toString();
				StackFrame frame = f.getStackFrame();
				int locals = frame.getLocalSize();
				String type = f.getReturnType().toString();
				mainString = "Signature: " + signature + "\n" + "Name: " + name + "\n" + "Start Address: " + addr + "\n"
						+ "End Address: " + end + "\n" + "Local Size: " + locals + "\n" + "Return Type: " + type;
				println("Signature: " + signature + "\n" + "\t\t Name: " + name + "\n" + "\t\t Start Address: " + addr
						+ "\n" + "\t\t End Address: " + end + "\n" + "\t\t Local Size: " + locals + "\n"
						+ "\t\t Return Type: " + type);
				mainIsFind = true;
			}
		}
		if (mainIsFind == false && currentProgram.getListing().getGlobalFunctions("entry") != null) {
			List<Function> mainEntry = currentProgram.getListing().getGlobalFunctions("entry");
			for (Function f : mainEntry) {
				String signature = f.getSignature().toString();
				String name = f.getName();
				String addr = f.getBody().getMinAddress().toString();
				String end = f.getBody().getMaxAddress().toString();
				StackFrame frame = f.getStackFrame();
				int locals = frame.getLocalSize();
				String type = f.getReturnType().toString();
				mainString = "Signature: " + signature + "\n" + "Name: " + name + "\n" + "Start Address: " + addr + "\n"
						+ "End Address: " + end + "\n" + "Local Size: " + locals + "\n" + "Return Type: " + type;
				println("Signature: " + signature + "\n" + "\t\t Name: " + name + "\n" + "\t\t Start Address: " + addr
						+ "\n" + "\t\t End Address: " + end + "\n" + "\t\t Local Size: " + locals + "\n"
						+ "\t\t Return Type: " + type);
			}
		}
		mainSearcher.getMainFunction(mainString, stringParts[0]);
	}

	/**
	 * This function is used to get the type of archive based on the magic numbers.
	 * 
	 * @throws IOException
	 * @throws MemoryAccessException
	 * 
	 */
	private void getMagicNumbers() throws IOException, MemoryAccessException {
		boolean existsMagic = false;
		Data base = getDataContaining(currentProgram.getImageBase());
		if (base != null) {
			String magicNumber = base.getComponent(0).toString();
			HashMap<String, String> magicNumbers = new HashMap<>();
			magicNumbers = fileManager.fileReaderArchiveMagicNumbers();
			String programName = currentProgram.getName();
			String[] stringParts = programName.split("\\.");
			String extension = stringParts[1];
			for (String key : magicNumbers.keySet()) {
				String value = magicNumbers.get(key);
				if (value.equals(magicNumber)) {
					println("Type of file by Magic Number: " + key + "(" + extension + ")" + ", value: " + value);
					String magicNumberToFile = "Type of the file by Magic Number: " + key + "(" + extension + ")"
							+ ", value: " + value;
					existsMagic = true;
					fileManager.getTypeArchive(magicNumberToFile, stringParts[0]);
				}
			}
		}
		if (!existsMagic) {
			String programName = currentProgram.getName();
			String[] stringParts = programName.split("\\.");
			String extension = stringParts[1];
			println("Type of th file by Magic Number: " + extension);
			fileManager.getTypeArchive("Type of the file by Magic Number: " + extension, stringParts[0]);
		}
	}

	/**
	 * This method is used to get the Hash of the Archive and open VirusTotal
	 * 
	 */
	private void getHashArchive() {
		String md5 = currentProgram.getExecutableMD5();
		if (java.awt.Desktop.isDesktopSupported()) {
			java.awt.Desktop desktop = java.awt.Desktop.getDesktop();

			if (desktop.isSupported(java.awt.Desktop.Action.BROWSE)) {
				try {
					java.net.URI uri = new java.net.URI("https://www.virustotal.com/gui/search/" + md5);
					desktop.browse(uri);
				} catch (URISyntaxException | IOException ex) {
					println("There was an error with the URL access");
				}
			}
		}
	}

	/**
	 * This method is used to get the language of the archive that is been analyzed.
	 */
	private void getLanguageOfArchive() {
		HashMap<String, String> laguanges = new HashMap<>();
		laguanges = fileManager.fileReadLanguage();
		Listing listing = currentProgram.getListing();
		List<String> languagesList = new ArrayList<>(); 
		DataIterator dataIt;
		if (currentSelection != null) {
			dataIt = listing.getDefinedData(currentSelection, true);
		} else {
			dataIt = listing.getDefinedData(true);
		}
		Data data;
		String type;
		while (dataIt.hasNext() && !monitor.isCancelled()) {
			data = dataIt.next();
			type = data.getDataType().getName().toLowerCase();
			if (type.contains("unicode") || type.contains("string")) {
				String s = data.getDefaultValueRepresentation().toLowerCase();
				for (String key : laguanges.keySet()) {
					String value = laguanges.get(key);
					if(s.contains(value) && !languagesList.contains(key)) {
						languagesList.add(key);
					}
				}
			}
		}
		println("The languages present in the archive are the following: ");
		for(String language: languagesList) {
			println("\t- " + language);
		}
	}
}
