import javax.swing.JApplet;
import java.awt.Graphics;

public class helloworld extends JApplet {
    public void Paint(Graphics g){
        g.drawRect(0, 0,
                   getSize().width -1,
                   getSize().height -1);
        g.drawString("Hello world!", 5, 15);
    }
}
