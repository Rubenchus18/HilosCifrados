
public class Envio implements java.io.Serializable {
	
	private byte[] cadena = null;
	
	public Envio(byte[] cadena) {
		this.cadena = cadena;
	}
	
	public byte[] getCadena() {
		return cadena;
	}
	public void setCadena(byte[] cadena) {
		this.cadena = cadena;
	}

}
