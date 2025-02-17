
public class Principal {
	
	public static void main(String []args) throws Exception {
		ClienteBurger c1 = new ClienteBurger("Ruben", 23, 10);
		ClienteBurger c2 = new ClienteBurger("Gonzalo", 21, 30.50);
		ClienteBurger c3 = new ClienteBurger("Ismael", 15, 25);
		ClienteBurger c4 = new ClienteBurger("Pedro", 22, 20);

        c1.comprar();
        c2.comprar();
        c3.comprar();
        c4.comprar();

    }

}

