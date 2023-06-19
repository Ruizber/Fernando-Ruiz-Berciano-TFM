import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * This class is used to manage the files in the searching main function
 * operation.
 * 
 * @author Fernando Ruiz Berciano
 *
 */
public class MainSearcher {

	/**
	 * This method is used to store in a file the information of the main function
	 * of the program.
	 * 
	 * @param String mainFunction
	 */
	public void getMainFunction(String mainFunction, String programName) {
		FileWriter fichero = null;
		try {
			Date date = new Date();
			String dateString = new SimpleDateFormat("dd-MM-yyyy").format(date);
			fichero = new FileWriter(
					"C:\\Files-TFM\\MainFunction\\Output\\" + programName + "_MainFunction_" + dateString + ".txt");
			fichero.write(mainFunction);
			fichero.close();
		} catch (Exception ex) {
			System.out.println("Mensaje de la excepción: " + ex.getMessage());
		}
	}

}
